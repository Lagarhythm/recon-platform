"""Reporting: collection, redaction, rendering, and the LLM Analyst."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.engagement import Engagement
from recon.models.enums import AssetType, FindingPolarity, InterestLevel, ScopeStatus
from recon.models.evidence import Evidence
from recon.orchestrator.analyst import (
    AnalystError,
    AnalystService,
    _compact,
    _drop_exploitation,
)
from recon.reporting.collect import build_report_data
from recon.reporting.redaction import RedactionMode, redact_report
from recon.reporting.render import render_html, render_json


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
        from recon.llm.client import LLMResult
        return LLMResult(
            content=json.dumps({
                "summary": "Small external surface; one leaked AWS key is the priority.",
                "priorities": ["Rotate the exposed AWS key", "Review api.example.com"],
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
        assert a.priorities[0].startswith("Rotate")
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
    # the missing-DNSSEC negative finding is surfaced as a missing control
    assert any("DNSSEC" in m for m in p["missing_controls"])


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
