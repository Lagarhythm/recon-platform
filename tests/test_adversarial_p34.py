"""Adversarial review - Phase 3 (active recon + evasion) and Phase 4 (reporting + LLM).

Each test documents one issue. Tests marked ``# BUG:`` fail against the current
code and demonstrate the defect; the rest are regression locks confirming a
behaviour that is actually safe.

Run: ``uv run pytest tests/test_adversarial_p34.py -q``

No real network / subprocess / LLM calls: DNS probe methods are monkeypatched at
the module-method seam, subprocess via ``run_command``, the LLM via
``LLMClient.chat``.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.engagement import Engagement
from recon.models.enums import (
    AssetType,
    FindingPolarity,
    InterestLevel,
    ScopeStatus,
)
from recon.models.evidence import Evidence
from recon.modules.active.dns_axfr import DNSZoneTransferModule
from recon.modules.active.port_scan import PortScanModule
from recon.modules.active.subdomain_brute import SubdomainBruteModule
from recon.net.backoff import BackoffController
from recon.net.external import CommandResult
from recon.reporting.redaction import RedactionMode, _scrub_paths, redact_report
from tests.conftest import EXAMPLE_ROE
from tests.harness import evidence_for, module_harness


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
async def _seed_asset(engagement_id, atype, value, scope=ScopeStatus.IN_SCOPE):
    async with session_scope() as s:
        s.add(
            Asset(
                engagement_id=engagement_id,
                type=atype,
                value=value,
                in_scope_status=scope,
                confidence_score=1.0,
                interest_level=InterestLevel.INFORMATIONAL,
            )
        )


async def _make_engagement(roe_yaml: str) -> str:
    from recon.orchestrator.engagements import EngagementService

    async with session_scope() as s:
        eng, _ = await EngagementService().create(s, roe_yaml)
        return eng.id


# an RoE where an in_scope apex domain is *also* explicitly excluded
_ROE_EXCLUDED_APEX = """
engagement:
  name: "Excluded Apex"
  client: "Test Client"
  authorized_window:
    start: "2026-01-01T00:00:00Z"
    end: "2030-01-01T00:00:00Z"
scope:
  in_scope:
    domains: ["acme-test.com", "*.acme-test.com", "payments.acme-test.com"]
  excluded:
    hosts: ["payments.acme-test.com"]
rate_limits:
  max_requests_per_second: 10
  max_concurrent_connections: 20
evasion:
  jitter: {enabled: false, min_ms: 0, max_ms: 0}
  user_agents: ["UA-1"]
llm:
  analysis_enabled: false
"""


# ===========================================================================
# 1. ACTIVE MODULE SCOPE ESCAPE
# ===========================================================================
@pytest.mark.asyncio
async def test_dns_axfr_skips_excluded_apex(monkeypatch):
    """# BUG: dns_axfr pulls apex domains straight from ``roe.scope.in_scope.domains``
    and never re-checks them against the exclusion list. An apex that is listed
    in_scope AND in ``excluded.hosts`` gets an AXFR attempt with NO override -
    a scope escape. port_scan / dir_fuzz both filter EXCLUDED here; this module
    does not.
    """
    engagement_id = await _make_engagement(_ROE_EXCLUDED_APEX)

    probed: list[str] = []

    async def fake_probe(self, ctx, resolver, domain):  # noqa: ANN001
        probed.append(domain)

    monkeypatch.setattr(DNSZoneTransferModule, "_probe_domain", fake_probe)

    async with module_harness(engagement_id, "dns_axfr") as ctx:
        assert ctx.allow_out_of_scope is False
        assert ctx.scope.classify("payments.acme-test.com").status is ScopeStatus.EXCLUDED
        await DNSZoneTransferModule().run(ctx)

    assert "payments.acme-test.com" not in probed, (
        f"EXCLUDED apex was AXFR-probed without an override: {probed}"
    )


@pytest.mark.asyncio
async def test_subdomain_brute_skips_excluded_apex(monkeypatch):
    """# BUG: same defect in subdomain_brute - the in_scope.domains apexes are
    brute-forced without filtering out an apex that is also excluded.
    """
    engagement_id = await _make_engagement(_ROE_EXCLUDED_APEX)

    bruted: list[str] = []

    async def fake_brute(self, ctx, resolver, apex, labels, sem, concurrency, rps):  # noqa: ANN001, PLR0913
        bruted.append(apex)

    monkeypatch.setattr(SubdomainBruteModule, "_brute_apex", fake_brute)
    monkeypatch.setattr(
        "recon.modules.active.subdomain_brute._load_labels", lambda *a, **k: ["www"]
    )

    async with module_harness(engagement_id, "subdomain_brute") as ctx:
        await SubdomainBruteModule().run(ctx)

    assert "payments.acme-test.com" not in bruted, (
        f"EXCLUDED apex was brute-forced without an override: {bruted}"
    )


@pytest.mark.asyncio
async def test_dns_axfr_skips_excluded_asset_even_with_override(monkeypatch):
    """# BUG: with ``allow_out_of_scope`` the module asks
    ``known_assets("domain", in_scope_only=False)`` which returns EXCLUDED
    domains, and then probes them. The override is meant to unlock FLAGGED
    targets, not EXCLUDED ones (port_scan's docstring: "never scan an explicitly
    EXCLUDED target").
    """
    engagement_id = await _make_engagement(EXAMPLE_ROE)
    # mail.example.com is in EXAMPLE_ROE excluded.hosts
    await _seed_asset(engagement_id, AssetType.DOMAIN, "mail.example.com", ScopeStatus.EXCLUDED)

    probed: list[str] = []

    async def fake_probe(self, ctx, resolver, domain):  # noqa: ANN001
        probed.append(domain)

    monkeypatch.setattr(DNSZoneTransferModule, "_probe_domain", fake_probe)

    async with module_harness(engagement_id, "dns_axfr") as ctx:
        ctx.allow_out_of_scope = True
        await DNSZoneTransferModule().run(ctx)

    assert "mail.example.com" not in probed, (
        f"EXCLUDED domain asset AXFR-probed even though EXCLUDED is never in scope: {probed}"
    )


@pytest.mark.asyncio
async def test_port_scan_still_excludes_excluded_asset_with_override(monkeypatch):
    """Regression lock: port_scan DOES filter EXCLUDED even under an override.
    This is the correct behaviour that dns_axfr / subdomain_brute are missing.
    """
    engagement_id = await _make_engagement(EXAMPLE_ROE)
    await _seed_asset(engagement_id, AssetType.SUBDOMAIN, "mail.example.com", ScopeStatus.EXCLUDED)
    await _seed_asset(engagement_id, AssetType.IP, "203.0.113.10", ScopeStatus.IN_SCOPE)

    monkeypatch.setattr("recon.modules.active.port_scan.find_binary", lambda n: "/usr/bin/nmap")
    seen: dict = {}

    async def fake_run(argv, **kw):  # noqa: ANN001, ANN003
        seen["argv"] = argv
        return CommandResult(argv=argv, returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

    monkeypatch.setattr("recon.modules.active.port_scan.run_command", fake_run)

    async with module_harness(engagement_id, "port_scan") as ctx:
        ctx.allow_out_of_scope = True
        await PortScanModule().run(ctx)

    assert "mail.example.com" not in seen.get("argv", [])
    assert "203.0.113.10" in seen.get("argv", [])


@pytest.mark.asyncio
async def test_port_scan_rejects_internet_wide_cidr():
    """# BUG (low): ``_is_safe_target`` accepts any ``ip_network`` string, so an
    Asset value of ``0.0.0.0/0`` (or ``10.0.0.0/8``) passes the guard and would
    be handed to nmap as a target list - the guard is meant to only let through
    a single host/CIDR the engagement authorised.
    """
    from recon.modules.active.port_scan import _is_safe_target

    assert _is_safe_target("0.0.0.0/0") is False
    assert _is_safe_target("10.0.0.0/8") is False


# ===========================================================================
# 3. RATE-LIMIT / RoE VIOLATION
# ===========================================================================
@pytest.mark.asyncio
async def test_subdomain_brute_rate_limits_every_dns_query(engagement_id, monkeypatch):
    """FIXED: every DNS query (one per record type per label, plus the wildcard
    probe) is gated through a shared RateLimiter built from the RoE rate."""
    labels = ["a", "b", "c", "d", "e", "f"]
    monkeypatch.setattr(
        "recon.modules.active.subdomain_brute._load_labels", lambda *a, **k: list(labels)
    )

    resolve_calls = {"n": 0}
    acquire_calls = {"n": 0}

    class _Ans:
        rrset = None

    class _ZoneAns:
        rrset = ["soa"]  # non-empty -> example.com looks like a real zone

    async def fake_resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
        resolve_calls["n"] += 1
        return _ZoneAns() if rtype in ("SOA", "NS") else _Ans()

    from recon.net.rate_limit import RateLimiter

    real_acquire = RateLimiter.acquire

    async def counting_acquire(self):  # noqa: ANN001
        acquire_calls["n"] += 1

    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", fake_resolve)
    monkeypatch.setattr(RateLimiter, "acquire", counting_acquire)

    async with module_harness(engagement_id, "subdomain_brute") as ctx:
        await SubdomainBruteModule().run(ctx)

    # one acquire per DNS query issued - nothing bypasses the limiter
    assert acquire_calls["n"] == resolve_calls["n"] > 0, (
        f"{resolve_calls['n']} DNS queries but only {acquire_calls['n']} rate-limiter acquisitions"
    )


def _acoro(value):
    async def _c():
        return value

    return _c()


# ===========================================================================
# 3b. ADAPTIVE BACKOFF MATH  (regression locks - these are safe)
# ===========================================================================
def test_backoff_never_exceeds_base_rate():
    """Regression lock: current_rate stays within (0, base_rate] through any
    sequence of distress + recovery."""
    ctrl = BackoffController(10.0, cooldown_seconds=0.0)
    import random

    for _ in range(2000):
        rate = ctrl.record(throttled=random.random() < 0.3, connection_error=random.random() < 0.3)
        assert 0.0 < rate <= 10.0 + 1e-9
        assert 0.0 < ctrl.current_rate <= 10.0 + 1e-9


def test_backoff_extra_delay_is_bounded():
    """Regression lock: repeated trips do not stack the cool-down unboundedly."""
    ctrl = BackoffController(10.0, cooldown_seconds=15.0)
    for _ in range(50):
        ctrl.record(throttled=True)
    assert ctrl.extra_delay() <= 15.0 + 1e-6


# ===========================================================================
# 4. REDACTION LEAKS  (client mode + LLM payload)
# ===========================================================================
def _client(data: dict) -> tuple[dict, str]:
    out = redact_report(data, RedactionMode.CLIENT)
    return out, json.dumps(out)


def test_redaction_scrubs_windows_file_paths():
    """# BUG: ``_PATH_RE`` only matches a Windows drive path with a *double*
    backslash (JSON-escaped form). A normal ``C:\\Users\\...`` path in a
    scrub-key value survives client redaction. This tool runs on Windows, so
    the analyst's own working paths leak into the client deliverable.
    """
    winpath = "C:" + chr(92) + "Users" + chr(92) + "analyst" + chr(92) + "acme" + chr(92) + "creds.txt"
    assert _scrub_paths(winpath) == "[redacted]", "single-backslash Windows path not scrubbed"

    data = {
        "engagement": {"name": "x", "roe_yaml": "secret: yaml"},
        "assets": [
            {
                "value": "api.example.com",
                "evidence": [
                    {"summary": f"found at {winpath}", "raw_data": {"detail": winpath}}
                ],
            }
        ],
        "findings": [],
        "negative_findings": [],
        "relationships": [],
    }
    _, blob = _client(data)
    assert winpath not in blob


def test_redaction_scrubs_secrets_under_any_key():
    """# BUG: redaction is a key-name allowlist. A secret / path under any key
    not in ``_DROP_KEYS`` / ``_SCRUB_KEYS`` passes straight through to the client
    report. ``_DROP_KEYS`` even lists ``banner_raw`` while port_scan actually
    writes the key ``banner``.
    """
    data = {
        "engagement": {"name": "x", "roe_yaml": "y"},
        "assets": [
            {
                "value": "10.0.0.5:22",
                "evidence": [
                    {
                        "summary": "ssh",
                        "raw_data": {
                            "banner": "OpenSSH_9 config /etc/ssh/internal_secrets",
                            "api_token": "AKIA_LEAKED_TOKEN_1234",
                            "extrainfo": "/opt/app/private/key.pem",
                        },
                    }
                ],
            }
        ],
        "findings": [],
        "negative_findings": [],
        "relationships": [],
    }
    _, blob = _client(data)
    assert "AKIA_LEAKED_TOKEN_1234" not in blob, "secret under 'api_token' leaked"
    assert "/etc/ssh/internal_secrets" not in blob, "path under 'banner' leaked"
    assert "/opt/app/private/key.pem" not in blob, "path under 'extrainfo' leaked"


def test_redaction_covers_negative_findings_and_relationships():
    """# BUG: ``redact_report`` only walks the ``assets`` and ``findings``
    buckets. ``negative_findings`` summaries and ``relationships`` values are
    emitted to the client report (and the LLM payload) with no path scrub / no
    body drop.
    """
    data = {
        "engagement": {"name": "x", "roe_yaml": "y"},
        "assets": [],
        "findings": [],
        "negative_findings": [
            {"summary": "zone file at /etc/bind/zones/internal.db world-readable", "module": "dns"}
        ],
        "relationships": [
            {"source": "a", "target": "secret:key:/home/analyst/loot/creds.txt", "type": "serves"}
        ],
    }
    _, blob = _client(data)
    assert "/etc/bind/zones/internal.db" not in blob, "path leaked via negative_findings"
    assert "/home/analyst/loot/creds.txt" not in blob, "path leaked via relationships"


def test_redaction_known_drop_keys_still_work():
    """Regression lock: the documented drop / scrub behaviour is intact."""
    data = {
        "engagement": {"name": "x", "roe_yaml": "SECRET-ROE"},
        "assets": [
            {
                "value": "api.example.com",
                "evidence": [
                    {
                        "summary": "at /home/analyst/notes.txt",
                        "raw_data": {
                            "body": "<html>SECRET PAGE</html>",
                            "context": "aws_key = AKIAZZZ",
                            "value": "nginx",
                        },
                        "request_metadata": {"headers": {"Cookie": "sess=abc"}},
                    }
                ],
            }
        ],
        "findings": [],
        "negative_findings": [],
        "relationships": [],
    }
    out, blob = _client(data)
    assert "SECRET PAGE" not in blob
    assert "AKIAZZZ" not in blob
    assert "/home/analyst/notes.txt" not in blob
    assert "roe_yaml" not in out["engagement"]
    assert "sess=abc" not in blob  # request_metadata dropped
    assert "nginx" in blob  # non-sensitive kept


# ===========================================================================
# 5. LLM ANALYST - leak reaches the third-party endpoint
# ===========================================================================
@pytest.mark.asyncio
async def test_analyst_payload_redacts_secret_under_any_key(engagement_id, monkeypatch):
    """# BUG: the Analyst builds its payload from the client-redacted report, but
    because redaction is an incomplete key allowlist, a secret under an
    unexpected raw_data key is shipped to the remote LLM endpoint - exactly the
    data-leaving-the-host risk the redaction gate is supposed to close.
    """
    async with session_scope() as s:
        s.add(
            Asset(
                engagement_id=engagement_id,
                type=AssetType.SUBDOMAIN,
                value="api.example.com",
                in_scope_status=ScopeStatus.IN_SCOPE,
                confidence_score=0.9,
                interest_level=InterestLevel.NOTABLE,
            )
        )
    async with session_scope() as s:
        a = (
            await s.execute(select(Asset).where(Asset.value == "api.example.com"))
        ).scalar_one()
        s.add(
            Evidence(
                engagement_id=engagement_id,
                asset_id=a.id,
                source_module="dns_axfr",
                subject_type="dns_record",
                subject_value="_secret.api.example.com",
                raw_data={"name": "x", "rtype": "TXT", "vault_token": "s.LEAKEDVAULTTOKEN"},
                polarity=FindingPolarity.PRESENT,
            )
        )

    captured: dict = {}

    async def fake_chat(self, system, user, **kw):  # noqa: ANN001, ANN003
        captured["user"] = user
        from recon.llm.client import LLMResult

        return LLMResult(content='{"summary":"s","priorities":[],"next_steps":[]}',
                         model="m", usage={})

    monkeypatch.setattr("recon.llm.client.LLMClient.chat", fake_chat)

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        eng.llm_analysis_enabled = True
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        from recon.orchestrator.analyst import AnalystService

        await AnalystService().run(s, eng)

    assert "LEAKEDVAULTTOKEN" not in captured["user"], (
        "secret shipped to the remote LLM endpoint through incomplete redaction"
    )


@pytest.mark.asyncio
async def test_analyst_handles_null_llm_content(engagement_id, monkeypatch):
    """# BUG (low): if the model returns ``content: null`` (common when a model
    emits only tool_calls), ``_parse(None)`` raises AttributeError inside
    ``AnalystService.run`` - uncaught, so the analyst run 500s instead of
    degrading.
    """
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        eng.llm_analysis_enabled = True

    async def fake_chat(self, system, user, **kw):  # noqa: ANN001, ANN003
        from recon.llm.client import LLMResult

        return LLMResult(content=None, model="m", usage={})

    monkeypatch.setattr("recon.llm.client.LLMClient.chat", fake_chat)

    from recon.orchestrator.analyst import AnalystError, AnalystService

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        try:
            await AnalystService().run(s, eng)
        except AnalystError:
            pass  # acceptable: handled degradation
        except AttributeError as exc:  # pragma: no cover
            pytest.fail(f"analyst crashed on null LLM content: {exc!r}")


@pytest.mark.asyncio
async def test_analyst_blocked_when_disabled_regression(engagement_id):
    """Regression lock: analyst refuses to run when the engagement opt-in is off."""
    from recon.orchestrator.analyst import AnalystError, AnalystService

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        assert eng.llm_analysis_enabled is False
        with pytest.raises(AnalystError):
            await AnalystService().run(s, eng)


# ===========================================================================
# 8. dns_axfr - unbounded AXFR response into evidence
# ===========================================================================
@pytest.mark.asyncio
async def test_dns_axfr_caps_zone_records(engagement_id, monkeypatch):
    """# BUG (medium): a nameserver that answers AXFR is fully trusted - every
    record becomes an ``add_evidence`` call with no cap. A hostile / huge zone
    (an attacker who controls a nameserver of an in-scope domain, or a poisoned
    response) turns into unbounded Evidence rows and memory.
    """
    huge = [
        {"name": f"h{i}.example.com", "rtype": "A", "value": "203.0.113.1", "ttl": 60}
        for i in range(4000)
    ]

    async def fake_xfr(ns_addr, domain, timeout):  # noqa: ANN001
        return huge

    monkeypatch.setattr("recon.modules.active.dns_axfr._zone_transfer", fake_xfr)
    monkeypatch.setattr(
        DNSZoneTransferModule, "_nameservers", lambda self, ctx, r, d: _acoro(["ns1.evil."])
    )
    monkeypatch.setattr(
        DNSZoneTransferModule, "_ns_addresses", lambda self, r, ns: _acoro(["203.0.113.53"])
    )

    async with module_harness(engagement_id, "dns_axfr") as ctx:
        await DNSZoneTransferModule().run(ctx)

    recs = await evidence_for(engagement_id, subject_type="dns_record")
    assert len(recs) <= 1000, (
        f"AXFR wrote {len(recs)} unbounded dns_record evidence rows from one response"
    )
