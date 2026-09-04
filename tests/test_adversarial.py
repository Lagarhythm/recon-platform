"""Adversarial review of the recon platform.

Each test documents one issue. Tests marked ``# BUG:`` fail against the current
code and demonstrate the defect; the rest are regression locks confirming a
behaviour that is actually safe.

Run: ``uv run pytest tests/test_adversarial.py -q``
"""

from __future__ import annotations

import time

import httpx
import pytest
from sqlalchemy import select

from recon.core.roe import RoEError, load_roe
from recon.core.scope import ScopeManager, extract_host
from recon.correlation.engine import CorrelationEngine
from recon.db import session_scope
from recon.models.audit import AuditLogEntry
from recon.models.asset import Asset
from recon.models.engagement import Engagement
from recon.models.enums import AssetType, FindingPolarity, ScopeStatus
from recon.models.evidence import Evidence
from recon.net.http_client import ReconHTTPClient, ScopeViolation
from tests.conftest import EXAMPLE_ROE


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _mgr(roe_yaml: str = EXAMPLE_ROE) -> ScopeManager:
    config, _ = load_roe(roe_yaml)
    return ScopeManager(config)


async def _make_client(engagement_id: str, handler, *, allow_oos: bool = False) -> ReconHTTPClient:
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        roe_hash = eng.roe_config_hash
    roe, _ = load_roe(EXAMPLE_ROE)
    roe.evasion.jitter.enabled = False  # keep the test fast
    client = ReconHTTPClient(
        roe=roe,
        scope=ScopeManager(roe),
        engagement_id=engagement_id,
        roe_config_hash=roe_hash,
        scan_run_id=None,  # keep audit rows free of the scan_run FK for this harness
        allow_out_of_scope=allow_oos,
    )
    client._client = httpx.AsyncClient(
        follow_redirects=False, transport=httpx.MockTransport(handler)
    )
    return client


async def _audit_targets(engagement_id: str) -> list[str]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(AuditLogEntry).where(AuditLogEntry.engagement_id == engagement_id)
            )
        ).scalars()
        return [r.target for r in rows]


async def _add_evidence_raw(engagement_id: str, **kw) -> None:
    async with session_scope() as s:
        s.add(
            Evidence(
                engagement_id=engagement_id,
                source_module=kw.pop("module", "adv"),
                subject_type=kw.pop("subject_type"),
                subject_value=kw.pop("subject_value"),
                raw_data=kw.pop("raw_data", {}),
                polarity=kw.pop("polarity", FindingPolarity.PRESENT),
                is_error=kw.pop("is_error", False),
            )
        )


async def _correlate(engagement_id: str):
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        return await CorrelationEngine().correlate(s, eng)


# ===========================================================================
# 1. Scope enforcement
# ===========================================================================
def test_trailing_dot_fqdn_still_excluded():
    """BUG: an explicitly EXCLUDED host is classified IN_SCOPE when written with a
    trailing dot (a fully valid FQDN form that resolves identically).

    ScopeManager.classify does an exact-string membership test against
    ``excluded.hosts`` (recon/core/scope.py:99) *before* the pattern match, but
    ``extract_host`` (recon/core/scope.py:54) never strips a trailing '.'. So
    'mail.example.com.' misses the exclusion set, then matches the '*.example.com'
    in-scope pattern (which *does* rstrip('.')) and is greenlit.
    """
    m = _mgr()
    assert m.classify("mail.example.com").status is ScopeStatus.EXCLUDED
    # same host, trailing dot -> should still be EXCLUDED
    assert m.classify("mail.example.com.").status is ScopeStatus.EXCLUDED
    assert m.classify("https://mail.example.com./").status is ScopeStatus.EXCLUDED


def test_extract_host_strips_trailing_dot():
    """BUG: extract_host does not normalise the DNS root label."""
    assert extract_host("mail.example.com.") == "mail.example.com"


@pytest.mark.asyncio
async def test_redirect_to_excluded_host_is_scope_checked(engagement_id):
    """FIXED: the client follows redirects itself and re-classifies every hop.
    A 3xx Location to an EXCLUDED host raises ScopeViolation and no request is
    ever made to that host.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.host == "api.example.com":
            return httpx.Response(302, headers={"location": "http://mail.example.com/secret"})
        return httpx.Response(200, text="content")

    client = await _make_client(engagement_id, handler)
    try:
        with pytest.raises(ScopeViolation):
            await client.get("http://api.example.com/", follow_redirects=True)
    finally:
        await client.aclose()

    assert not any("mail.example.com" in u for u in seen), (
        f"outbound request reached an EXCLUDED host via redirect: {seen}"
    )


@pytest.mark.asyncio
async def test_in_scope_redirect_hop_is_audited(engagement_id):
    """FIXED: every redirect hop the client follows is written to the audit log,
    not just the original URL.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "https://api.example.com/app"})
        return httpx.Response(200, text="ok")

    client = await _make_client(engagement_id, handler)
    try:
        resp = await client.get("https://api.example.com/", follow_redirects=True)
    finally:
        await client.aclose()

    assert resp.status_code == 200
    targets = await _audit_targets(engagement_id)
    assert any(t.endswith("/") for t in targets)
    assert any(t.endswith("/app") for t in targets), (
        f"redirect hop not audited; targets were: {targets}"
    )


@pytest.mark.asyncio
async def test_direct_request_to_excluded_host_is_blocked_and_audited(engagement_id):
    """Regression lock: the *non-redirect* path is correctly gated - a direct
    request to an EXCLUDED host raises ScopeViolation and writes a blocked
    audit row.
    """
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        return httpx.Response(200)

    client = await _make_client(engagement_id, handler)
    try:
        with pytest.raises(ScopeViolation):
            await client.get("http://mail.example.com/")
    finally:
        await client.aclose()

    targets = await _audit_targets(engagement_id)
    assert any("mail.example.com" in t for t in targets)


# ===========================================================================
# 4. Correlation engine robustness
# ===========================================================================
@pytest.mark.asyncio
async def test_correlation_survives_bad_url_port(engagement_id):
    """BUG: a single ``url`` Evidence whose value has an out-of-range port makes
    the whole correlation run raise ValueError('Port out of range').

    ``_canon_url`` (recon/correlation/engine.py:99) touches ``parts.port`` with
    no guard, and ``correlate`` does not catch it. The crawler emits ``url``
    evidence verbatim from ``<a href>`` targets found on a scanned page
    (crawler.py:223), so a hostile/broken in-scope page can wipe the Asset Graph
    for the entire engagement and fail the scan run at the correlation step.
    """
    await _add_evidence_raw(
        engagement_id,
        subject_type="url",
        subject_value="http://api.example.com:99999/oops",
        raw_data={"status": 200},
    )
    await _correlate(engagement_id)  # BUG: raises ValueError instead of skipping the row


@pytest.mark.asyncio
async def test_correlation_survives_malformed_ipv6_url(engagement_id):
    """BUG: same class - an unbracketed/short IPv6 URL raises
    ValueError('Invalid IPv6 URL') out of urlsplit inside _canon_url.
    """
    await _add_evidence_raw(
        engagement_id,
        subject_type="url",
        subject_value="http://[::1",
        raw_data={},
    )
    await _correlate(engagement_id)  # BUG: raises


@pytest.mark.asyncio
async def test_correlation_survives_nonstring_attribute_ref(engagement_id):
    """BUG: an attribute Evidence (http_header/cookie/tls_cert/...) whose
    ``raw_data['url']`` is not a string crashes _route_evidence:
    ``"://" not in ref`` -> TypeError (recon/correlation/engine.py:231). Not
    caught by ``correlate``.
    """
    await _add_evidence_raw(
        engagement_id,
        subject_type="http_header",
        subject_value="api.example.com:Server",
        raw_data={"url": 12345, "name": "Server", "value": "nginx"},
    )
    await _correlate(engagement_id)  # BUG: raises TypeError


@pytest.mark.asyncio
async def test_correlation_survives_huge_and_weird_raw_data(engagement_id):
    """Regression lock: deeply-nested / None raw_data and odd dns rtypes are
    tolerated (these paths *are* guarded)."""
    await _add_evidence_raw(
        engagement_id,
        subject_type="subdomain",
        subject_value="ok.example.com",
        raw_data={"nested": {"a": {"b": {"c": list(range(50))}}}},
    )
    await _add_evidence_raw(
        engagement_id,
        module="dns",
        subject_type="dns_record",
        subject_value="ok.example.com",
        raw_data={"name": "ok.example.com", "rtype": "HINFO", "value": "weird"},
    )
    summary = await _correlate(engagement_id)
    assert summary.evidence_processed == 2
    async with session_scope() as s:
        vals = {
            a.value
            for a in (
                await s.execute(select(Asset).where(Asset.engagement_id == engagement_id))
            ).scalars()
        }
    assert "ok.example.com" in vals


# ===========================================================================
# 6. RoE parsing
# ===========================================================================
def test_roe_rejects_python_object_tag():
    """Regression lock: RoE loading uses yaml.safe_load - ``!!python/object``
    construction is refused, not executed.
    """
    with pytest.raises(RoEError):
        load_roe(
            'engagement: !!python/object/apply:os.system ["id"]\n'
            "scope: {in_scope: {domains: [example.com]}}\n"
        )


def test_roe_yaml_alias_bomb_rejected():
    """BUG: load_roe -> yaml.safe_load expands YAML aliases with no limit, so a
    "billion laughs" document (10x amplification per level) blows up parse time
    and memory. A 7-level bomb already takes multiple seconds; add two more
    levels and it OOMs. ``load_roe`` also parses the document twice (once here,
    once in ``canonical_hash``), doubling the cost. There is no node/expansion
    cap and no size limit on the uploaded RoE.
    """
    bomb = "\n".join(
        ["l0: &l0 [x,x,x,x,x,x,x,x,x,x]"]
        + [
            f"l{i}: &l{i} [" + ",".join([f"*l{i - 1}"] * 10) + "]"
            for i in range(1, 8)
        ]
    )
    bomb += "\nengagement: {name: x, client: y}\nscope: {in_scope: {domains: [example.com]}}\n"

    start = time.perf_counter()
    try:
        load_roe(bomb)
    except (RoEError, MemoryError):
        pass
    elapsed = time.perf_counter() - start
    # A safe parser rejects or cheaply handles this. Current code takes ~6s.
    assert elapsed < 1.0, f"alias-bomb RoE took {elapsed:.1f}s to parse (DoS)"
