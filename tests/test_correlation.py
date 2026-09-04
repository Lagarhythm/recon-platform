"""Correlation Engine: evidence -> Asset Graph."""

from __future__ import annotations

import pytest
from sqlalchemy import select

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
