"""Reproduction fixtures for the two P1-assessment P0 pipeline defects.

Baseline: p1-report-quality @ 8d87052fbcb7143fb586a592498864fa85e15bb2.

Both tests assert the *acceptance* behaviour from
``recon-platform-p1-functional-assessment-2026-09-05.md`` and are expected to
FAIL on the baseline (``xfail(strict=True)``). When the P0 fix lands they flip to
XPASS, which strict-xfail turns into a failure - that is the signal to delete the
marker.

P0-1  "CIDR scope never becomes scan targets" - a /24-only RoE produces a green,
      zero-evidence run: no host discovery, ``dns`` and ``port_scan`` both report
      "nothing in scope", and the module runs are COMPLETED, indistinguishable
      from a clean scan (should be SKIPPED / completed-no-input).

P0-2  "Module dependencies do not provide same-run data" - with the
      passive->active checkpoint pre-authorised (``scan start --yes-active`` /
      ``active_confirmed=True``), correlation never runs between a passive
      dependency and its dependent active module, so the active module queries
      the Asset graph and finds nothing. Only a second scan (or a manual
      checkpoint pause, which does correlate) makes the data visible.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.engagement import Engagement
from recon.models.enums import ModulePhase, ModuleRunStatus, ScanRunStatus
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES
from recon.orchestrator.engagements import EngagementService
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import scan_service
from tests.conftest import wait_for

# --- fake modules -----------------------------------------------------------

#: every run of ``_ReproActive`` appends the target set it was handed
_ACTIVE_TARGETS_SEEN: list[list[str]] = []


class _ReproDNS(ReconModule):
    """Stand-in for the real ``dns`` module: writes a same-run A-record for an
    in-scope name, exactly as ``recon.modules.passive.dns`` does."""

    name = "repro_dns"
    phase = ModulePhase.PASSIVE
    description = "repro: emit one in-scope dns_record"

    async def run(self, ctx: ModuleContext) -> None:
        host = "www.example.com"
        await ctx.add_evidence(
            subject_type="dns_record",
            subject_value=host,
            raw_data={"name": host, "rtype": "A", "value": "203.0.113.10", "ttl": 300},
            summary=f"{host} A 203.0.113.10",
        )


class _ReproActive(ReconModule):
    """Stand-in for ``port_scan`` on the post-P0-2 contract: builds its target
    set from ``ctx.resolve_targets`` (current-run Evidence + RoE), and records a
    no-input outcome when nothing is eligible, the same way ``PortScanModule``
    now does."""

    name = "repro_active"
    phase = ModulePhase.ACTIVE
    depends_on = ("repro_dns",)
    description = "repro: read targets via the same-run target view"

    async def run(self, ctx: ModuleContext) -> None:
        from recon.models.enums import SkipReason

        resolution = await ctx.resolve_targets("ip", "hostname")
        _ACTIVE_TARGETS_SEEN.append(sorted(c.value for c in resolution.eligible))
        if not resolution.eligible:
            await ctx.mark_no_input(SkipReason.ZERO_ELIGIBLE_TARGETS)


_FAKES = [_ReproDNS, _ReproActive]


@pytest.fixture(autouse=True)
def _register_fakes():
    _ACTIVE_TARGETS_SEEN.clear()
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


# --- helpers ---------------------------------------------------------------

_CIDR_ONLY_ROE = """
engagement:
  name: "CIDR-only Home"
  client: "self"
  authorized_window:
    start: "2026-01-01T00:00:00Z"
    end: "2030-01-01T00:00:00Z"
scope:
  in_scope:
    cidrs: ["192.168.2.0/24"]
rate_limits:
  max_requests_per_second: 10
  max_concurrent_connections: 20
evasion:
  user_agents: ["UA-1"]
llm:
  analysis_enabled: false
"""


async def _make_engagement(roe_yaml: str) -> str:
    async with session_scope() as session:
        eng, _ = await EngagementService().create(session, roe_yaml)
        return eng.id


async def _start(engagement_id: str, modules: list[str], *, preauthorize_active: bool) -> str:
    async with session_scope() as session:
        eng = await session.get(Engagement, engagement_id)
        run = await scan_service.start_scan(session, eng, modules)
        run_id = run.id
    if preauthorize_active:
        # mirrors ReconClient._preauthorize_active (scan start --yes-active)
        async with session_scope() as session:
            run = await session.get(ScanRun, run_id)
            run.active_confirmed = True
    return run_id


async def _run_status(run_id: str) -> ScanRunStatus:
    async with session_scope() as s:
        return (await s.get(ScanRun, run_id)).status


async def _module_rows(run_id: str) -> dict[str, ScanModuleRun]:
    async with session_scope() as s:
        rows = (
            await s.execute(
                select(ScanModuleRun).where(ScanModuleRun.scan_run_id == run_id)
            )
        ).scalars()
        return {r.module_name: r for r in rows}


# --- P0-2 ----------------------------------------------------------------

# Regression lock (was xfail on the baseline; P0-2 fix makes it pass): with the
# passive->active checkpoint pre-authorised, a same-run dependency's Evidence is
# now visible to the dependent active module through ctx.resolve_targets without
# waiting for end-of-run correlation.
@pytest.mark.asyncio
async def test_p0_2_same_run_dependency_handoff(engagement_id):
    """`repro_dns,repro_active` in ONE pre-authorised run: the active module must
    receive the name `repro_dns` resolved this run."""
    run_id = await _start(
        engagement_id, ["repro_dns", "repro_active"], preauthorize_active=True
    )
    await wait_for(lambda: _is_done(run_id))

    # the dependency really did produce same-run evidence
    async with session_scope() as s:
        evs = (
            await s.execute(
                select(Evidence).where(
                    Evidence.engagement_id == engagement_id,
                    Evidence.subject_type == "dns_record",
                )
            )
        ).scalars().all()
    assert evs, "repro_dns wrote no evidence - test setup is wrong"

    assert _ACTIVE_TARGETS_SEEN, "repro_active never ran"
    assert "www.example.com" in _ACTIVE_TARGETS_SEEN[-1], (
        "active module saw no same-run dependency targets: "
        f"{_ACTIVE_TARGETS_SEEN[-1]!r}"
    )


@pytest.mark.asyncio
async def test_p0_2_same_run_handoff_manual_checkpoint(engagement_id):
    """The manual checkpoint flow (operator resumes at the passive->active
    pause) must also hand the dependency's same-run output to the active
    module - it worked before only because the pause happened to correlate."""
    run_id = await _start(
        engagement_id, ["repro_dns", "repro_active"], preauthorize_active=False
    )
    async def _at_checkpoint() -> bool:
        return (await _run_status(run_id)) is ScanRunStatus.AWAITING_CHECKPOINT

    await wait_for(_at_checkpoint)
    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _is_done(run_id))

    assert _ACTIVE_TARGETS_SEEN, "repro_active never ran"
    assert "www.example.com" in _ACTIVE_TARGETS_SEEN[-1], _ACTIVE_TARGETS_SEEN[-1]


async def _is_done(run_id: str) -> bool:
    st = await _run_status(run_id)
    return st in (ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.PAUSED)


# --- P0-1 ----------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="P0-1: no host discovery for a CIDR-only RoE. The P0-2 fix now makes "
    "the active module record SKIPPED/zero_eligible_targets (no longer a green "
    "COMPLETED), but nothing discovers live IPs from the /24 yet - that is "
    "P0-1's host_discovery module, still gated on Security.",
    strict=True,
)
async def test_p0_1_cidr_only_scope_is_accounted_for():
    engagement_id = await _make_engagement(_CIDR_ONLY_ROE)
    run_id = await _start(
        engagement_id, ["repro_dns", "repro_active"], preauthorize_active=True
    )
    await wait_for(lambda: _is_done(run_id))

    rows = await _module_rows(run_id)

    # Acceptance: a run that discovered/accounted for nothing must not look like
    # a clean scan. The active module run must be SKIPPED with a no-input reason.
    assert rows["repro_active"].status is ModuleRunStatus.SKIPPED, (
        f"CIDR-only active run ended {rows['repro_active'].status.value}, "
        "expected SKIPPED (completed-no-input)"
    )

    # Acceptance: host discovery must have produced at least one live-IP asset
    # from the /24 and handed it to the active module.
    assert _ACTIVE_TARGETS_SEEN and _ACTIVE_TARGETS_SEEN[-1], (
        "no live-IP targets were discovered from the in-scope /24"
    )
