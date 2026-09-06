"""Unit tests for the same-run target-resolution contract (P0-2).

``ctx.resolve_targets`` builds an active module's target set from the CURRENT
scan run's Evidence (plus RoE-declared hosts/domains and, opt-in, prior
correlated Assets), applying scope + safe-form filtering centrally so an
EXCLUDED / out-of-scope / crafted value can never reach ``eligible``.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.enums import AssetType, InterestLevel, ScopeStatus
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun
from tests.harness import module_harness


async def _add_dns_evidence(ctx, host: str, ip: str) -> None:
    await ctx.add_evidence(
        subject_type="dns_record",
        subject_value=host,
        raw_data={"name": host, "rtype": "A", "value": ip, "ttl": 300},
        summary=f"{host} A {ip}",
    )
    await ctx.flush()


@pytest.mark.asyncio
async def test_current_run_dns_evidence_becomes_targets(engagement_id):
    async with module_harness(engagement_id, "port_scan") as ctx:
        await _add_dns_evidence(ctx, "api.example.com", "203.0.113.10")
        res = await ctx.resolve_targets("ip", "hostname")

    values = {c.value for c in res.eligible}
    assert "api.example.com" in values
    assert "203.0.113.10" in values
    dns_hosts = {c.value for c in res.eligible if c.source_kind == "current_run_dns"}
    assert {"api.example.com", "203.0.113.10"} <= dns_hosts


@pytest.mark.asyncio
async def test_prior_run_evidence_is_not_included(engagement_id):
    # Evidence from a different scan run must not silently enter this run.
    async with session_scope() as s:
        s.add(
            Evidence(
                engagement_id=engagement_id,
                scan_run_id=None,  # engagement-wide historical evidence, no run
                source_module="dns",
                subject_type="dns_record",
                subject_value="old.example.com",
                raw_data={"name": "old.example.com", "rtype": "A",
                          "value": "203.0.113.20"},
            )
        )

    async with module_harness(engagement_id, "port_scan") as ctx:
        res = await ctx.resolve_targets("ip", "hostname")

    assert "old.example.com" not in {c.value for c in res.eligible}
    assert "203.0.113.20" not in {c.value for c in res.eligible}


@pytest.mark.asyncio
async def test_excluded_target_never_eligible(engagement_id):
    # mail.example.com is in excluded.hosts of EXAMPLE_ROE.
    async with module_harness(engagement_id, "port_scan") as ctx:
        await _add_dns_evidence(ctx, "mail.example.com", "203.0.113.10")
        res = await ctx.resolve_targets("ip", "hostname")

    assert "mail.example.com" not in {c.value for c in res.eligible}
    excl = {c.value: c for c in res.excluded}
    assert "mail.example.com" in excl
    assert excl["mail.example.com"].exclusion_reason == "excluded_explicit"


@pytest.mark.asyncio
async def test_excluded_cidr_ip_never_eligible(engagement_id):
    # 203.0.113.128/28 is an excluded CIDR in EXAMPLE_ROE.
    async with module_harness(engagement_id, "port_scan") as ctx:
        await _add_dns_evidence(ctx, "vpn.example.com", "203.0.113.130")
        res = await ctx.resolve_targets("ip", "hostname")

    assert "203.0.113.130" not in {c.value for c in res.eligible}


@pytest.mark.asyncio
async def test_option_like_and_crafted_values_are_dropped(engagement_id):
    async with module_harness(engagement_id, "port_scan") as ctx:
        for bad in ("-oX /etc/passwd", "--script=vuln", "a.example.com;id",
                    "0.0.0.0/0", "10.0.0.0/8"):
            await ctx.add_evidence(
                subject_type="dns_record", subject_value=bad,
                raw_data={"name": bad, "rtype": "A", "value": "203.0.113.10"},
            )
        await ctx.flush()
        res = await ctx.resolve_targets("ip", "hostname")

    eligible = {c.value for c in res.eligible}
    for bad in ("-oX /etc/passwd", "--script=vuln", "a.example.com;id",
                "0.0.0.0/0", "10.0.0.0/8"):
        assert bad not in eligible
    # the legitimate A-record value still comes through
    assert "203.0.113.10" in eligible
    assert any(c.exclusion_reason == "unsafe_form" for c in res.excluded)


@pytest.mark.asyncio
async def test_prior_assets_are_opt_in_and_tagged(engagement_id):
    async with session_scope() as s:
        s.add(Asset(engagement_id=engagement_id, type=AssetType.IP,
                    value="203.0.113.50", in_scope_status=ScopeStatus.IN_SCOPE,
                    confidence_score=1.0, interest_level=InterestLevel.INFORMATIONAL))

    async with module_harness(engagement_id, "port_scan") as ctx:
        off = await ctx.resolve_targets("ip", "hostname")
        on = await ctx.resolve_targets("ip", "hostname", include_prior_assets=True)

    assert "203.0.113.50" not in {c.value for c in off.eligible}
    match = [c for c in on.eligible if c.value == "203.0.113.50"]
    assert match and match[0].source_kind == "prior_asset"


@pytest.mark.asyncio
async def test_current_run_outranks_prior_asset_in_dedupe(engagement_id):
    async with session_scope() as s:
        s.add(Asset(engagement_id=engagement_id, type=AssetType.DOMAIN,
                    value="api.example.com", in_scope_status=ScopeStatus.IN_SCOPE,
                    confidence_score=1.0, interest_level=InterestLevel.INFORMATIONAL))

    async with module_harness(engagement_id, "port_scan") as ctx:
        await _add_dns_evidence(ctx, "api.example.com", "203.0.113.10")
        res = await ctx.resolve_targets("hostname", include_prior_assets=True)

    match = [c for c in res.eligible if c.value == "api.example.com"]
    assert len(match) == 1
    assert match[0].source_kind == "current_run_dns"


@pytest.mark.asyncio
async def test_unaccounted_cidr_yields_zero_eligible_and_a_marker(engagement_id):
    # EXAMPLE_ROE has in_scope.cidrs = ["203.0.113.0/24"] and no current-run
    # discovery evidence, so it must not silently become a target.
    async with module_harness(engagement_id, "port_scan") as ctx:
        res = await ctx.resolve_targets("ip")

    assert res.eligible == []
    assert any(c.exclusion_reason == "unaccounted_cidr" for c in res.excluded)


@pytest.mark.asyncio
async def test_accounting_is_bounded_and_values_only(engagement_id):
    async with module_harness(engagement_id, "port_scan") as ctx:
        await _add_dns_evidence(ctx, "api.example.com", "203.0.113.10")
        res = await ctx.resolve_targets("ip", "hostname")
        acct = res.accounting(max_provenance=1)

    assert acct["eligible"] == len(res.eligible)
    assert len(acct["provenance"]) == 1
    assert set(acct["provenance"][0]) == {"value", "source_kind", "source_module"}
    assert "by_source" in acct and "by_disposition" in acct


@pytest.mark.asyncio
async def test_unknown_accept_type_is_rejected(engagement_id):
    async with module_harness(engagement_id, "port_scan") as ctx:
        with pytest.raises(ValueError):
            await ctx.resolve_targets("ip", "banana")


@pytest.mark.asyncio
async def test_flagged_target_needs_override(engagement_id):
    async with module_harness(engagement_id, "port_scan") as ctx:
        # not in any in-scope domain/cidr -> FLAGGED
        await ctx.add_evidence(
            subject_type="dns_record", subject_value="elsewhere.test",
            raw_data={"name": "elsewhere.test", "rtype": "A", "value": "198.51.100.7"},
        )
        await ctx.flush()
        without = await ctx.resolve_targets("ip", "hostname")
        ctx.allow_out_of_scope = True
        with_override = await ctx.resolve_targets("ip", "hostname")

    assert "elsewhere.test" not in {c.value for c in without.eligible}
    assert "elsewhere.test" in {c.value for c in with_override.eligible}
