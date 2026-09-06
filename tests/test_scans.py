"""Scan orchestration: passive-first, checkpoint, resumability, resilience, kill switch."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.engagement import Engagement
from recon.models.enums import ModulePhase, ModuleRunStatus, ScanRunStatus
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import scan_service
from tests.conftest import wait_for


class _FakePassiveA(ReconModule):
    name = "fake_pa"
    phase = ModulePhase.PASSIVE
    description = "fake passive a"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="a.example.com", raw_data={}
        )


class _FakePassiveB(ReconModule):
    name = "fake_pb"
    phase = ModulePhase.PASSIVE
    description = "fake passive b"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="b.example.com", raw_data={}
        )


class _FakeActive(ReconModule):
    name = "fake_act"
    phase = ModulePhase.ACTIVE
    description = "fake active"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="active.example.com", raw_data={}
        )


class _FakeFailing(ReconModule):
    name = "fake_fail"
    phase = ModulePhase.PASSIVE
    description = "always raises"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="partial.example.com", raw_data={}
        )
        raise RuntimeError("boom")


class _FakeSlow(ReconModule):
    name = "fake_slow"
    phase = ModulePhase.PASSIVE
    description = "loops until cancelled"

    async def run(self, ctx: ModuleContext) -> None:
        for _ in range(200):
            ctx.check_alive()
            await asyncio.sleep(0.05)


class _FakeOverrun(ReconModule):
    name = "fake_overrun"
    phase = ModulePhase.PASSIVE
    description = "overruns its wall-clock budget"
    max_runtime_seconds = 0.3

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="slowpartial.example.com", raw_data={}
        )
        for _ in range(200):
            ctx.check_alive()  # raises ModuleTimeout once the budget is spent
            await asyncio.sleep(0.05)


_FAKES = [
    _FakePassiveA, _FakePassiveB, _FakeActive, _FakeFailing, _FakeSlow, _FakeOverrun,
]


@pytest.fixture(autouse=True)
def _register_fakes():
    for cls in _FAKES:
        MODULES[cls.name] = cls()
    yield
    for cls in _FAKES:
        MODULES.pop(cls.name, None)


@pytest.fixture(autouse=True)
async def _cleanup_scans():
    yield
    kill_switch.reset()
    await scan_service.shutdown()
    scan_service._handles.clear()


async def _status(scan_run_id) -> ScanRunStatus:
    async with session_scope() as s:
        run = await s.get(ScanRun, scan_run_id)
        return run.status


async def _start(engagement_id, modules, **kw) -> str:
    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        run = await scan_service.start_scan(s, eng, modules, **kw)
        return run.id


async def _module_statuses(scan_run_id) -> dict[str, ModuleRunStatus]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(ScanModuleRun).where(ScanModuleRun.scan_run_id == scan_run_id)
            )
        ).scalars()
        return {r.module_name: r.status for r in rows}


async def _asset_values(engagement_id) -> set[str]:
    async with session_scope() as s:
        rows = (
            await s.execute(select(Asset.value).where(Asset.engagement_id == engagement_id))
        ).scalars()
        return set(rows)


async def _is(run_id, status):
    return (await _status(run_id)) is status


@pytest.mark.asyncio
async def test_passive_scan_completes_and_correlates(engagement_id):
    run_id = await _start(engagement_id, ["fake_pa", "fake_pb"])
    await wait_for(lambda: _is(run_id, ScanRunStatus.COMPLETED))
    values = await _asset_values(engagement_id)
    assert {"a.example.com", "b.example.com"} <= values


@pytest.mark.asyncio
async def test_passive_first_checkpoint_blocks_active(engagement_id):
    run_id = await _start(engagement_id, ["fake_pa", "fake_act"])
    await wait_for(lambda: _is(run_id, ScanRunStatus.AWAITING_CHECKPOINT))

    statuses = await _module_statuses(run_id)
    assert statuses["fake_pa"] is ModuleRunStatus.COMPLETED
    assert statuses["fake_act"] is ModuleRunStatus.PENDING
    assert "active.example.com" not in await _asset_values(engagement_id)

    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _is(run_id, ScanRunStatus.COMPLETED))
    # Post-S1b: a resumed run drains the active phase, but an ACTIVE module with
    # no permit-bound method profile is centrally skipped by the active-surface
    # gate - it never runs, so it produces no evidence/assets. Execution of an
    # allowlisted active module after resume is covered in
    # tests/test_active_surface_gate.py and tests/test_d0_e2e.py.
    from recon.models.enums import SkipReason

    rows = await _module_statuses(run_id)
    assert rows["fake_act"] is ModuleRunStatus.SKIPPED
    async with session_scope() as s:
        fa = (
            await s.execute(
                select(ScanModuleRun).where(
                    ScanModuleRun.scan_run_id == run_id,
                    ScanModuleRun.module_name == "fake_act",
                )
            )
        ).scalar_one()
    assert fa.skip_reason is SkipReason.ACTIVE_SURFACE_DISABLED
    assert "active.example.com" not in await _asset_values(engagement_id)


@pytest.mark.asyncio
async def test_module_failure_does_not_abort_run(engagement_id):
    run_id = await _start(engagement_id, ["fake_pa", "fake_fail", "fake_pb"])
    await wait_for(lambda: _is(run_id, ScanRunStatus.COMPLETED))

    statuses = await _module_statuses(run_id)
    assert statuses["fake_fail"] is ModuleRunStatus.FAILED
    assert statuses["fake_pa"] is ModuleRunStatus.COMPLETED
    assert statuses["fake_pb"] is ModuleRunStatus.COMPLETED
    values = await _asset_values(engagement_id)
    # evidence emitted before the module raised is still correlated
    assert {"a.example.com", "b.example.com", "partial.example.com"} <= values


@pytest.mark.asyncio
async def test_module_overrun_is_failed_and_run_continues(engagement_id):
    run_id = await _start(engagement_id, ["fake_overrun", "fake_pb"])
    await wait_for(lambda: _is(run_id, ScanRunStatus.COMPLETED))

    statuses = await _module_statuses(run_id)
    assert statuses["fake_overrun"] is ModuleRunStatus.FAILED
    assert statuses["fake_pb"] is ModuleRunStatus.COMPLETED

    async with session_scope() as s:
        row = (
            await s.execute(
                select(ScanModuleRun).where(
                    ScanModuleRun.scan_run_id == run_id,
                    ScanModuleRun.module_name == "fake_overrun",
                )
            )
        ).scalar_one()
        assert "timed out" in (row.error or "")

    # evidence emitted before the timeout is still correlated
    assert "slowpartial.example.com" in await _asset_values(engagement_id)


@pytest.mark.asyncio
async def test_cancel_then_resume_does_not_rerun_completed(engagement_id):
    run_id = await _start(engagement_id, ["fake_pa", "fake_slow"])
    await wait_for(
        lambda: _module_status_is(run_id, "fake_slow", ModuleRunStatus.RUNNING)
    )
    await scan_service.cancel_scan(run_id)
    await wait_for(lambda: _is(run_id, ScanRunStatus.PAUSED))

    assert (await _module_statuses(run_id))["fake_pa"] is ModuleRunStatus.COMPLETED

    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _is(run_id, ScanRunStatus.COMPLETED))
    # A module that actually ran keeps its COMPLETED status - it is not
    # relabelled "skipped" just because the run was resumed.
    assert (await _module_statuses(run_id))["fake_pa"] is ModuleRunStatus.COMPLETED


async def _module_status_is(run_id, module, status):
    return (await _module_statuses(run_id)).get(module) is status


@pytest.mark.asyncio
async def test_kill_switch_blocks_new_scan(engagement_id):
    kill_switch.engage("test")
    with pytest.raises(Exception):
        await _start(engagement_id, ["fake_pa"])
    kill_switch.reset()


@pytest.mark.asyncio
async def test_kill_switch_pauses_running_scan(engagement_id):
    run_id = await _start(engagement_id, ["fake_slow"])
    await wait_for(
        lambda: _module_status_is(run_id, "fake_slow", ModuleRunStatus.RUNNING)
    )
    kill_switch.engage("client called")
    await wait_for(lambda: _is(run_id, ScanRunStatus.PAUSED))
    kill_switch.reset()
