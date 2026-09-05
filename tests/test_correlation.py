"""Correlation Engine: evidence -> Asset Graph."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from recon.config import get_settings
from recon.correlation.engine import CorrelationEngine
from recon.db import session_scope
from recon.models.asset import Asset, AssetRelationship
from recon.models.engagement import Engagement
from recon.models.enums import AssetType, FindingPolarity, InterestLevel, ScopeStatus
from recon.models.evidence import Evidence


async def _add_evidence(engagement_id, **kw):
    async with session_scope() as s:
        s.add(
            Evidence(
                engagement_id=engagement_id,
                source_module=kw.pop("module", "test"),
                subject_type=kw.pop("subject_type"),
                subject_value=kw.pop("subject_value"),
                raw_data=kw.pop("raw_data", {}),
                summary=kw.pop("summary", None),
                polarity=kw.pop("polarity", None) or FindingPolarity.PRESENT,
                is_error=kw.pop("is_error", False),
            )
        )


async def _correlate(engagement_id):
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        summary = await CorrelationEngine().correlate(s, eng)
    return summary


async def _assets(engagement_id, atype=None):
    async with session_scope() as s:
        stmt = select(Asset).where(Asset.engagement_id == engagement_id)
        if atype:
            stmt = stmt.where(Asset.type == atype)
        return list((await s.execute(stmt)).scalars())


@pytest.mark.asyncio
async def test_subdomain_and_ip_from_dns_records(engagement_id):
    await _add_evidence(
        engagement_id, module="dns", subject_type="dns_record",
        subject_value="api.example.com",
        raw_data={"name": "api.example.com", "rtype": "A", "value": "203.0.113.10"},
    )
    summary = await _correlate(engagement_id)
    assert summary.evidence_processed == 1

    subs = await _assets(engagement_id, AssetType.SUBDOMAIN)
    ips = await _assets(engagement_id, AssetType.IP)
    assert {a.value for a in subs} == {"api.example.com"}
    assert {a.value for a in ips} == {"203.0.113.10"}

    # resolves_to relationship exists
    async with session_scope() as s:
        rels = list((await s.execute(select(AssetRelationship))).scalars())
    assert any(r.relationship_type.value == "resolves_to" for r in rels)

    # the subdomain resolves into an in-scope CIDR -> in_scope
    assert subs[0].in_scope_status is ScopeStatus.IN_SCOPE


@pytest.mark.asyncio
async def test_confidence_rises_with_independent_sources(engagement_id):
    await _add_evidence(engagement_id, module="ct", subject_type="subdomain",
                        subject_value="www.example.com", raw_data={})
    await _correlate(engagement_id)
    a = (await _assets(engagement_id, AssetType.SUBDOMAIN))[0]
    one_source = a.confidence_score

    await _add_evidence(engagement_id, module="dns", subject_type="subdomain",
                        subject_value="www.example.com", raw_data={})
    await _correlate(engagement_id)
    a = (await _assets(engagement_id, AssetType.SUBDOMAIN))[0]
    assert a.confidence_score > one_source


@pytest.mark.asyncio
async def test_confidence_counts_distinct_raw_data_source_within_one_module(engagement_id):
    """One aggregator module (e.g. passive_subdomains) that hears a name from
    several passive sources must count each source (PRD v2.1 §5)."""
    await _add_evidence(engagement_id, module="passive_subdomains", subject_type="subdomain",
                        subject_value="api.example.com", raw_data={"source": "crt.sh"})
    await _correlate(engagement_id)
    one = (await _assets(engagement_id, AssetType.SUBDOMAIN))[0].confidence_score

    # same module, a *different* source -> confidence rises
    await _add_evidence(engagement_id, module="passive_subdomains", subject_type="subdomain",
                        subject_value="api.example.com", raw_data={"source": "otx"})
    await _correlate(engagement_id)
    two = (await _assets(engagement_id, AssetType.SUBDOMAIN))[0].confidence_score
    assert two > one

    # same module, a source already counted -> no change
    await _add_evidence(engagement_id, module="passive_subdomains", subject_type="subdomain",
                        subject_value="api.example.com", raw_data={"source": "crt.sh"})
    await _correlate(engagement_id)
    three = (await _assets(engagement_id, AssetType.SUBDOMAIN))[0].confidence_score
    assert three == two


@pytest.mark.asyncio
async def test_confidence_unchanged_for_sourceless_single_module(engagement_id):
    """A module that sets no raw_data['source'] (every v1 module) is unaffected:
    N sourceless evidence rows from one module still collapse to one source."""
    for _ in range(4):
        await _add_evidence(engagement_id, module="ct", subject_type="subdomain",
                            subject_value="www.example.com", raw_data={})
    await _correlate(engagement_id)
    a = (await _assets(engagement_id, AssetType.SUBDOMAIN))[0]
    assert a.confidence_score == 0.5  # floor - one distinct source


@pytest.mark.asyncio
async def test_negative_evidence_becomes_finding(engagement_id):
    await _add_evidence(
        engagement_id, module="dns", subject_type="dnssec",
        subject_value="example.com", summary="DNSSEC not configured",
        polarity=FindingPolarity.ABSENT,
    )
    await _correlate(engagement_id)
    findings = await _assets(engagement_id, AssetType.FINDING)
    assert len(findings) == 1
    assert findings[0].interest_level in (InterestLevel.NOTABLE, InterestLevel.HIGH_VALUE)


@pytest.mark.asyncio
async def test_secret_finding_is_high_value(engagement_id):
    await _add_evidence(
        engagement_id, module="js", subject_type="secret",
        subject_value="AKIA................", summary="AWS key in bundle.js",
        raw_data={"kind": "aws_access_key"},
    )
    await _correlate(engagement_id)
    findings = await _assets(engagement_id, AssetType.FINDING)
    assert findings and findings[0].interest_level is InterestLevel.HIGH_VALUE


@pytest.mark.asyncio
async def test_unverified_search_hit_is_evidence_only(engagement_id):
    """search.py demotes off-target search results to subject_type
    'unverified_search_hit' - the Correlation Engine must never materialise
    that as a Finding/Asset or let it feed a relationship hint. An unknown
    subject_type otherwise falls through to the generic FINDING bucket (see
    _route_evidence), which _interest then bumps to NOTABLE - that fallthrough
    is exactly what this evidence-only route must avoid."""
    await _add_evidence(
        engagement_id, module="search", subject_type="unverified_search_hit",
        subject_value="https://bls.gov/some/page",
        raw_data={"source": "dork/creds", "host": "bls.gov"},
        summary="unverified search hit (creds): https://bls.gov/some/page",
    )
    summary = await _correlate(engagement_id)
    assert summary.evidence_processed == 1
    assert await _assets(engagement_id) == []
    async with session_scope() as s:
        rels = list((await s.execute(select(AssetRelationship))).scalars())
    assert rels == []


@pytest.mark.asyncio
async def test_christopher_earl_shape_off_target_search_hits_stay_out_of_graph(
    engagement_id, monkeypatch
):
    """End-to-end ingestion -> correlation regression for the failed
    "Christopher Earl" practice scan: a search backend that ignores site:/
    filetype: operators and returns unrelated hosts (Correos de Mexico,
    BLS.gov, Census, Zippia, Xbox status) must not leave any Asset, Finding,
    or AssetRelationship behind after correlation, in a fresh engagement."""
    import httpx

    from recon.modules.osint.search import SearchDorkModule
    from tests.harness import FakeHTTP, module_harness

    monkeypatch.setattr("recon.modules.osint.search.search_backend", lambda: "searxng")
    monkeypatch.setenv("RECON_SEARXNG_URL", "http://127.0.0.1:8888")
    get_settings.cache_clear()

    def _searx(results):
        return httpx.Response(200, json={"query": "x", "results": results})

    off_target_hits = [
        {"url": "https://www.correos.gob.mx/page", "title": "Correos de Mexico",
         "content": "servicio postal", "engine": "bing"},
        {"url": "https://www.bls.gov/some/report.pdf", "title": "BLS report",
         "content": "labor statistics", "engine": "bing"},
        {"url": "https://www.census.gov/data.xlsx", "title": "Census data",
         "content": "population", "engine": "bing"},
        {"url": "https://www.zippia.com/christopher-earl", "title": "Christopher Earl - Zippia",
         "content": "career profile", "engine": "bing"},
        {"url": "https://support.xbox.com/status", "title": "Xbox Live status",
         "content": "service status", "engine": "bing"},
    ]

    def route(method, url):
        return _searx(off_target_hits)

    http = FakeHTTP({"127.0.0.1:8888": route})
    async with module_harness(engagement_id, "search", http=http) as ctx:
        ctx.roe.osint.company = "Christopher Earl"
        ctx.roe.osint.seed_domains = ["sinewbyte.com"]
        await SearchDorkModule().run(ctx)
    get_settings.cache_clear()

    from tests.harness import evidence_for

    unverified = await evidence_for(engagement_id, subject_type="unverified_search_hit")
    assert len(unverified) >= len(off_target_hits)

    await _correlate(engagement_id)
    assert await _assets(engagement_id) == []
    async with session_scope() as s:
        rels = list((await s.execute(select(AssetRelationship))).scalars())
    assert rels == []


@pytest.mark.asyncio
async def test_idempotent(engagement_id):
    await _add_evidence(engagement_id, module="ct", subject_type="subdomain",
                        subject_value="a.example.com", raw_data={})
    await _correlate(engagement_id)
    await _correlate(engagement_id)
    subs = await _assets(engagement_id, AssetType.SUBDOMAIN)
    assert len(subs) == 1


@pytest.mark.asyncio
async def test_out_of_scope_subdomain_flagged(engagement_id):
    await _add_evidence(engagement_id, module="ct", subject_type="subdomain",
                        subject_value="evil.attacker.net", raw_data={})
    await _correlate(engagement_id)
    async with session_scope() as s:
        a = (
            await s.execute(
                select(Asset).where(Asset.value == "evil.attacker.net")
            )
        ).scalar_one()
    assert a.in_scope_status is ScopeStatus.FLAGGED
