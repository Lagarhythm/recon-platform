"""Reporting: collection, redaction, rendering, and the LLM Analyst."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.engagement import Engagement
from recon.models.enums import AssetType, FindingPolarity, InterestLevel, ModulePhase, ModuleRunStatus, ScopeStatus
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.orchestrator.analyst import (
    AnalystError,
    AnalystService,
    _compact,
    _drop_exploitation,
    _parse,
    _payload_evidence_refs,
)
from recon.reporting.collect import build_report_data
from recon.reporting.redaction import RedactionMode, redact_report
from recon.reporting.render import render_csv, render_html, render_json


async def _seed(engagement_id):
    async with session_scope() as s:
        s.add(Asset(engagement_id=engagement_id, type=AssetType.SUBDOMAIN,
                    value="api.example.com", in_scope_status=ScopeStatus.IN_SCOPE,
                    confidence_score=0.75, interest_level=InterestLevel.NOTABLE))
        s.add(Asset(engagement_id=engagement_id, type=AssetType.FINDING,
                    value="secret:aws_access_key:https://example.com/app.js",
                    in_scope_status=ScopeStatus.NOT_APPLICABLE, confidence_score=0.5,
                    interest_level=InterestLevel.HIGH_VALUE))
    async with session_scope() as s:
        a = (await s.execute(
            select(Asset).where(Asset.value == "api.example.com")
        )).scalar_one()
        s.add(Evidence(
            engagement_id=engagement_id, asset_id=a.id, source_module="http_analyzer",
            subject_type="http_header", subject_value="api.example.com:Server",
            raw_data={"url": "https://api.example.com/", "name": "Server",
                      "value": "nginx", "body": "<html>SECRET INTERNAL PAGE</html>",
                      "context": "aws_secret_key = AKIAXXXXXXXXXXXXXXXX"},
            summary="Server header on /home/analyst/notes.txt reference",
            polarity=FindingPolarity.PRESENT,
        ))
        s.add(Evidence(
            engagement_id=engagement_id, source_module="dns",
            subject_type="dnssec", subject_value="example.com",
            summary="DNSSEC not configured for example.com",
            polarity=FindingPolarity.ABSENT,
        ))


async def _data(engagement_id, mode=RedactionMode.INTERNAL):
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        d = await build_report_data(s, eng)
    return redact_report(d, mode)


@pytest.mark.asyncio
async def test_report_collection_shape(engagement_id):
    await _seed(engagement_id)
    d = await _data(engagement_id)
    assert d["summary"]["asset_count"] == 2
    assert d["summary"]["high_value_count"] == 1
    assert any(f["interest"] == "high_value" for f in d["findings"])
    assert any("DNSSEC" in n["summary"] for n in d["negative_findings"])


@pytest.mark.asyncio
async def test_client_redaction_strips_sensitive(engagement_id):
    await _seed(engagement_id)
    internal = await _data(engagement_id, RedactionMode.INTERNAL)
    client = await _data(engagement_id, RedactionMode.CLIENT)

    internal_blob = json.dumps(internal)
    client_blob = json.dumps(client)

    assert "SECRET INTERNAL PAGE" in internal_blob
    assert "SECRET INTERNAL PAGE" not in client_blob        # body dropped
    assert "AKIAXXXXXXXXXXXXXXXX" not in client_blob         # context dropped
    assert "/home/analyst/notes.txt" not in client_blob      # path scrubbed
    assert "roe_yaml" not in client["engagement"]            # RoE removed
    assert client["meta"]["redaction"] == "client"
    # non-sensitive data survives
    assert "api.example.com" in client_blob
    assert client["summary"]["asset_count"] == 2


@pytest.mark.asyncio
async def test_html_and_json_render(engagement_id):
    await _seed(engagement_id)
    d = await _data(engagement_id)
    html = render_html(d)
    assert "<html" in html.lower()
    assert "api.example.com" in html
    assert "Reconnaissance Report" in html
    parsed = json.loads(render_json(d))
    assert parsed["summary"]["asset_count"] == 2


@pytest.mark.asyncio
async def test_csv_render_escapes_formula_injection(engagement_id):
    """Attacker-influenced recon values (a subdomain label, an evidence summary)
    must not execute as a spreadsheet formula in the client CSV deliverable."""
    async with session_scope() as s:
        s.add(Asset(
            engagement_id=engagement_id, type=AssetType.SUBDOMAIN,
            value="=cmd|'/c calc'!A1.example.com",
            in_scope_status=ScopeStatus.FLAGGED, confidence_score=0.5,
            interest_level=InterestLevel.NOTABLE,
        ))
    async with session_scope() as s:
        a = (await s.execute(
            select(Asset).where(Asset.value.like("=cmd%"))
        )).scalar_one()
        s.add(Evidence(
            engagement_id=engagement_id, asset_id=a.id, source_module="dns",
            subject_type="subdomain", subject_value=a.value,
            summary="@SUM(1+1)*cmd", raw_data={},
        ))

    import csv as _csv
    import io as _io

    csv_text = render_csv(await _data(engagement_id))
    rows = list(_csv.reader(_io.StringIO(csv_text)))
    for row in rows[1:]:
        for cell in row:
            assert cell[:1] not in ("=", "+", "-", "@", "\t", "\r"), cell
    assert "'=cmd|" in csv_text and "'@SUM(1+1)" in csv_text


@pytest.mark.asyncio
async def test_analyst_blocked_when_disabled(engagement_id):
    await _seed(engagement_id)
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        assert eng.llm_analysis_enabled is False
        with pytest.raises(AnalystError):
            await AnalystService().run(s, eng)


@pytest.mark.asyncio
async def test_analyst_runs_with_mocked_llm(engagement_id, monkeypatch):
    await _seed(engagement_id)

    captured = {}

    async def fake_chat(self, system, user, **kw):
        captured["user"] = user
        evidence_id = next(
            ref["id"] for finding in json.loads(user)["findings"]
            for ref in finding["evidence_references"]
        )
        from recon.llm.client import LLMResult
        return LLMResult(
            content=json.dumps({
                "summary": "Small external surface; one leaked AWS key is the priority.",
                "priorities": [f"Review the reported finding [evidence:{evidence_id}]", "Ungrounded priority"],
                "next_steps": ["Enumerate api.example.com endpoints"],
            }),
            model="test-model",
            usage={"total_tokens": 123},
        )

    monkeypatch.setattr("recon.llm.client.LLMClient.chat", fake_chat)

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        eng.llm_analysis_enabled = True
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        analysis = await AnalystService().run(s, eng)
        aid = analysis.id

    # the payload sent to the LLM must be client-redacted
    assert "SECRET INTERNAL PAGE" not in captured["user"]
    assert "AKIAXXXXXXXXXXXXXXXX" not in captured["user"]

    async with session_scope() as s:
        from recon.models.analysis import Analysis
        a = await s.get(Analysis, aid)
        assert a.priorities and a.priorities[0].startswith("Review the reported finding [evidence:")
        assert a.model == "test-model"


@pytest.mark.asyncio
async def test_compact_payload_is_lean_and_keeps_signal(engagement_id):
    await _seed(engagement_id)
    red = await _data(engagement_id, RedactionMode.CLIENT)
    p = _compact(red)

    # far smaller than dumping the full redacted report
    assert len(json.dumps(p, default=str)) < 40_000
    # structure the analyst prompt expects
    assert set(p) >= {"services", "hosts", "findings", "notable_urls", "missing_controls"}
    # the high-value finding survives
    vals = [f["value"] for f in p["findings"]]
    assert any(v.startswith("secret:aws_access_key") for v in vals)
    # each finding carries its evidence lines, not full raw_data blobs
    assert all(isinstance(f.get("evidence"), list) for f in p["findings"])
    assert any(f.get("evidence_references") for f in p["findings"])
    # the missing-DNSSEC negative finding is surfaced as a missing control
    assert any("DNSSEC" in m for m in p["missing_controls"])


def test_compact_preserves_upstream_and_reference_and_never_infers_ownership():
    asset = {
        "value": "candidate.example.com", "type": "finding", "interest": "notable",
        "confidence": .95, "scope": "in_scope", "evidence": [{
            "id": "evidence-one", "module": "ct_subdomains", "summary": "observed",
            "raw_data": {"source": "crt.sh"},
        }],
    }
    payload = _compact({"assets": [asset], "findings": [asset], "summary": {},
                        "engagement": {"name": "test"}, "negative_findings": [],
                        "relationships": [], "scan_runs": []})
    finding = payload["findings"][0]
    assert finding["attribution"] == "uncertain"
    assert "crt.sh" in finding["sources"]
    assert finding["evidence_references"][0]["id"] == "evidence-one"
    assert _parse('{"priorities":["bad [evidence:nope]", "good [evidence:evidence-one]", "mixed [evidence:evidence-one] [evidence:nope]"]}', valid_evidence_refs={"evidence-one"})["priorities"] == ["good [evidence:evidence-one]"]
    assert _payload_evidence_refs({"osint": {"repositories": [finding]}}) == {"evidence-one"}


@pytest.mark.asyncio
async def test_analyst_accepts_a_valid_osint_evidence_reference(engagement_id, monkeypatch):
    async with session_scope() as session:
        eng = await session.get(Engagement, engagement_id)
        eng.llm_analysis_enabled = True
        asset = Asset(engagement_id=engagement_id, type=AssetType.REPOSITORY,
                      value="https://github.com/example/demo", confidence_score=.5,
                      interest_level=InterestLevel.INFORMATIONAL,
                      in_scope_status=ScopeStatus.NOT_APPLICABLE)
        session.add(asset)
        await session.flush()
        session.add(Evidence(engagement_id=engagement_id, asset_id=asset.id,
                              source_module="github_org", subject_type="repository",
                              subject_value=asset.value, summary="Public repository candidate",
                              raw_data={"source": "github"}))

    async def fake_chat(self, system, user, **kwargs):
        ref = json.loads(user)["osint"]["repositories"][0]["evidence_references"][0]["id"]
        from recon.llm.client import LLMResult
        return LLMResult(content=json.dumps({"summary": "Candidate repository.",
                         "priorities": [f"Verify repository association [evidence:{ref}]"],
                         "next_steps": []}), model="synthetic-review", usage={})

    monkeypatch.setattr("recon.llm.client.LLMClient.chat", fake_chat)
    async with session_scope() as session:
        eng = await session.get(Engagement, engagement_id)
        result = await AnalystService().run(session, eng)
        assert len(result.priorities) == 1


@pytest.mark.asyncio
async def test_skipped_coverage_and_exclusions_are_reported(engagement_id):
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        run = ScanRun(engagement_id=engagement_id, roe_config_snapshot={}, roe_config_hash=eng.roe_config_hash,
                      status="completed", modules_requested=["passive_subdomains", "git_secrets"])
        s.add(run)
        await s.flush()
        s.add_all([
            ScanModuleRun(scan_run_id=run.id, engagement_id=engagement_id, module_name="passive_subdomains",
                          phase=ModulePhase.OSINT, status=ModuleRunStatus.SKIPPED,
                          error="all passive sources disabled by configuration"),
            ScanModuleRun(scan_run_id=run.id, engagement_id=engagement_id, module_name="git_secrets",
                          phase=ModulePhase.OSINT, status=ModuleRunStatus.COMPLETED,
                          coverage_metadata={"excluded_repositories": ["lagarhythm/recon-platform"],
                                             "excluded_path_policies": ["tests/**"]}),
        ])
    report = await _data(engagement_id)
    outcomes = {row["name"]: row for row in report["scan_runs"][0]["module_outcomes"]}
    assert report["summary"]["incomplete_coverage"] is True
    assert outcomes["passive_subdomains"]["status"] == "skipped"
    assert outcomes["passive_subdomains"]["reason"] == "all passive sources disabled by configuration"
    assert outcomes["git_secrets"]["coverage_metadata"]["excluded_path_policies"] == ["tests/**"]
    html = render_html(report)
    assert "Excluded repositories" in html and "tests/**" in html


@pytest.mark.asyncio
async def test_skip_reason_distinguishes_benign_resume_from_no_input(engagement_id):
    """A module carried over from an earlier run is NOT a coverage gap; a module
    that skipped because it had no eligible targets IS, and carries an
    operator-facing label (RECON_P0_P01_REVISED_TARGET_CONTRACT §7)."""
    from recon.models.enums import SkipReason

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        run = ScanRun(engagement_id=engagement_id, roe_config_snapshot={},
                      roe_config_hash=eng.roe_config_hash, status="completed",
                      modules_requested=["dns", "port_scan"])
        s.add(run)
        await s.flush()
        s.add_all([
            ScanModuleRun(scan_run_id=run.id, engagement_id=engagement_id,
                          module_name="dns", phase=ModulePhase.PASSIVE,
                          status=ModuleRunStatus.SKIPPED,
                          skip_reason=SkipReason.RESUMED_PRIOR_RUN),
            ScanModuleRun(scan_run_id=run.id, engagement_id=engagement_id,
                          module_name="port_scan", phase=ModulePhase.ACTIVE,
                          status=ModuleRunStatus.SKIPPED,
                          skip_reason=SkipReason.ZERO_ELIGIBLE_TARGETS,
                          error="no input: zero_eligible_targets"),
        ])
    report = await _data(engagement_id)
    outcomes = {row["name"]: row for row in report["scan_runs"][0]["module_outcomes"]}

    assert outcomes["dns"]["coverage_gap"] is False
    assert outcomes["dns"]["skip_reason"] == "resumed_prior_run"
    assert outcomes["port_scan"]["coverage_gap"] is True
    assert outcomes["port_scan"]["skip_reason"] == "zero_eligible_targets"
    assert "no eligible targets" in outcomes["port_scan"]["reason"]
    assert report["summary"]["incomplete_coverage"] is True
    assert "zero findings" in (report["scan_runs"][0]["coverage_note"] or "")


@pytest.mark.asyncio
async def test_compact_surfaces_osint_block(engagement_id):
    async with session_scope() as s:
        s.add(Asset(engagement_id=engagement_id, type=AssetType.ORGANIZATION,
                    value="acme holdings llc", in_scope_status=ScopeStatus.NOT_APPLICABLE,
                    confidence_score=0.6, interest_level=InterestLevel.INFORMATIONAL))
        s.add(Asset(engagement_id=engagement_id, type=AssetType.NETBLOCK,
                    value="93.184.216.0/24", in_scope_status=ScopeStatus.NOT_APPLICABLE,
                    confidence_score=0.5, interest_level=InterestLevel.NOTABLE))
    red = await _data(engagement_id, RedactionMode.CLIENT)
    p = _compact(red)
    assert "osint" in p
    assert any("acme" in o["value"] for o in p["osint"]["organizations"])
    assert "93.184.216.0/24" in [n["value"] for n in p["osint"]["netblocks"]]


def test_drop_exploitation_filters_credential_and_exploit_steps():
    steps = [
        "Enumerate directories on immich.lan",
        "Attempt to access pihole.lan/admin with default credentials admin/admin",
        "Fingerprint the service on :8080",
        "Try brute-forcing the Jellyfin login",
    ]
    kept = _drop_exploitation(steps)
    assert "Enumerate directories on immich.lan" in kept
    assert "Fingerprint the service on :8080" in kept
    assert not any("default credential" in s.lower() for s in kept)
    assert not any("brute" in s.lower() for s in kept)
    assert any("recon only" in s for s in kept)  # the dropped-steps note
