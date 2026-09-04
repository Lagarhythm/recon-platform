"""scan_diff - no real network; DB-only module, so tests seed evidence/assets
and a baseline AssetSnapshot directly and assert on the ScanDelta/evidence it
writes."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.enums import AssetType, InterestLevel, ScopeStatus
from recon.models.scanrun import ScanRun
from recon.models.snapshot import AssetSnapshot, ScanDelta
from recon.modules.active.scan_diff import ScanDiffModule
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import evidence_for, module_harness


def _sub(v):
    return {"subject_type": "subdomain", "subject_value": v, "raw_data": {}}


def _service(host, port, *, product=None, version=None, name="http"):
    return {
        "subject_type": "service",
        "subject_value": f"{host}:{port}",
        "raw_data": {
            "host": host, "port": port, "name": name,
            "product": product, "version": version,
        },
    }


async def _seed_snapshot(engagement_id: str, signature_set: list[str]) -> str:
    """A committed baseline AssetSnapshot to diff against - needs a ScanRun
    row to satisfy the FK, but that run's own content is irrelevant here."""
    async with session_scope() as session:
        eng_run = await session.execute(
            select(ScanRun).where(ScanRun.engagement_id == engagement_id).limit(1)
        )
        run = eng_run.scalar_one_or_none()
        if run is None:
            run = ScanRun(
                engagement_id=engagement_id, roe_config_snapshot={}, roe_config_hash="x",
            )
            session.add(run)
            await session.flush()
        snap = AssetSnapshot(
            engagement_id=engagement_id, scan_run_id=run.id, signature_set=signature_set,
        )
        session.add(snap)
        await session.flush()
        return snap.id


async def _seed_finding_asset(
    engagement_id: str, value: str, interest: InterestLevel
) -> None:
    async with session_scope() as session:
        session.add(Asset(
            engagement_id=engagement_id, type=AssetType.FINDING, value=value,
            interest_level=interest, in_scope_status=ScopeStatus.IN_SCOPE,
        ))


async def _run(engagement_id, prior_evidence):
    async with module_harness(engagement_id, "scan_diff", prior_evidence=prior_evidence) as ctx:
        await ScanDiffModule().run(ctx)


async def _deltas(engagement_id: str) -> list:
    return await evidence_for(engagement_id, subject_type="delta")


async def _scan_deltas(engagement_id: str) -> list[ScanDelta]:
    async with session_scope() as session:
        rows = await session.execute(
            select(ScanDelta).where(ScanDelta.engagement_id == engagement_id)
        )
        return list(rows.scalars())


async def _snapshots(engagement_id: str) -> list[AssetSnapshot]:
    async with session_scope() as session:
        rows = await session.execute(
            select(AssetSnapshot).where(AssetSnapshot.engagement_id == engagement_id)
            .order_by(AssetSnapshot.taken_at)
        )
        return list(rows.scalars())


# --------------------------------------------------------------------------
def test_resolves_in_active_phase_after_port_scan_and_dir_fuzz():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["scan_diff"])]
    assert order.index("port_scan") < order.index("scan_diff")
    assert order.index("dir_fuzz") < order.index("scan_diff")
    assert MODULES["scan_diff"].phase.value == "active"


@pytest.mark.asyncio
async def test_first_run_writes_baseline_only_no_delta(engagement_id):
    await _run(engagement_id, [_sub("api.example.com")])

    snaps = await _snapshots(engagement_id)
    assert len(snaps) == 1
    assert "subdomain:api.example.com" in snaps[0].signature_set
    assert await _deltas(engagement_id) == []
    assert await _scan_deltas(engagement_id) == []


@pytest.mark.asyncio
async def test_new_subdomain_since_baseline_is_a_delta_added(engagement_id):
    await _seed_snapshot(engagement_id, ["subdomain:old.example.com"])
    await _run(engagement_id, [_sub("old.example.com"), _sub("new.example.com")])

    deltas = await _deltas(engagement_id)
    assert len(deltas) == 1
    d = deltas[0]
    assert d.subject_value == "subdomain:new.example.com"
    assert d.raw_data["delta"] == "added"

    [sd] = await _scan_deltas(engagement_id)
    assert sd.added == ["subdomain:new.example.com"]
    assert sd.removed == []


@pytest.mark.asyncio
async def test_vanished_subdomain_since_baseline_is_a_delta_removed(engagement_id):
    await _seed_snapshot(
        engagement_id, ["subdomain:old.example.com", "subdomain:gone.example.com"]
    )
    await _run(engagement_id, [_sub("old.example.com")])

    deltas = await _deltas(engagement_id)
    assert len(deltas) == 1
    assert deltas[0].subject_value == "subdomain:gone.example.com"
    assert deltas[0].raw_data["delta"] == "removed"


@pytest.mark.asyncio
async def test_service_version_bump_is_paired_as_changed_not_add_plus_remove(engagement_id):
    old_sig = "service:203.0.113.9:443:nginx/1.24"
    await _seed_snapshot(engagement_id, [old_sig])
    await _run(
        engagement_id,
        [_service("203.0.113.9", 443, product="nginx", version="1.25")],
    )

    deltas = await _deltas(engagement_id)
    assert len(deltas) == 1
    d = deltas[0]
    assert d.raw_data["delta"] == "changed"
    assert d.raw_data["was"] == old_sig
    assert d.raw_data["now"] == "service:203.0.113.9:443:nginx/1.25"

    [sd] = await _scan_deltas(engagement_id)
    assert sd.changed == [{
        "signature": "service:203.0.113.9:443", "was": old_sig,
        "now": "service:203.0.113.9:443:nginx/1.25",
    }]
    assert sd.added == [] and sd.removed == []


@pytest.mark.asyncio
async def test_new_high_value_finding_delta_inherits_high_value_interest(engagement_id):
    await _seed_snapshot(engagement_id, [])
    await _seed_finding_asset(
        engagement_id, "takeover:orphan.example.com", InterestLevel.HIGH_VALUE
    )
    await _run(engagement_id, [])

    deltas = await _deltas(engagement_id)
    assert len(deltas) == 1
    d = deltas[0]
    assert d.subject_value == "finding:takeover:orphan.example.com"
    assert d.raw_data["delta"] == "added"
    assert d.raw_data["interest"] == "high_value"


@pytest.mark.asyncio
async def test_excluded_host_is_never_a_signature(engagement_id):
    # mail.example.com is EXAMPLE_ROE's excluded host
    await _run(engagement_id, [
        _sub("mail.example.com"),
        _service("mail.example.com", 25, name="smtp"),
    ])
    [snap] = await _snapshots(engagement_id)
    assert not any("mail.example.com" in s for s in snap.signature_set)


@pytest.mark.asyncio
async def test_no_op_when_nothing_changed(engagement_id):
    await _seed_snapshot(engagement_id, ["subdomain:api.example.com"])
    await _run(engagement_id, [_sub("api.example.com")])
    assert await _deltas(engagement_id) == []
    [sd] = await _scan_deltas(engagement_id)
    assert sd.added == [] and sd.removed == [] and sd.changed == []
