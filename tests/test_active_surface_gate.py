"""Central fail-closed active-scan surface gate (Security P0-1 re-review, S1b).

The only sanctioned active-traffic path this release is the D0 connect-bind
liveness driver. Every registered ``phase=ACTIVE`` module is gated centrally by
``ScanService._active_surface_skip`` *before* ``ModuleContext`` / adapter entry:

* a module not on ``_ACTIVE_SURFACE_ALLOWLIST`` is skipped regardless of
  authorization state (``active_surface_disabled``);
* an allowlisted local-only module (``scan_diff``) still needs a durable
  ``AuthorizationSnapshot`` - a domain-only RoE has none, so it skips
  (``unverified_targets``).

These tests prove the adapter bodies are never entered, that no egress leaves the
process, that a newly registered ACTIVE module is disabled by default, and that
the skips render as coverage gaps rather than completed coverage.
"""

from __future__ import annotations

import types

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.authz import AuthorizationSnapshot, LivenessAttestation
from recon.models.engagement import Engagement
from recon.models.enums import (
    ModulePhase,
    ModuleRunStatus,
    ScanRunStatus,
    SkipReason,
)
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES, iter_modules
from recon.orchestrator.engagements import EngagementService
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import (
    _ACTIVE_SURFACE_ALLOWLIST,
    _ACTIVE_SURFACE_NETWORK_DENIED,
    scan_service,
)
from tests.conftest import wait_for

pytestmark = pytest.mark.asyncio

_HOST = "app.example.com"
_IP = "203.0.113.10"

_EXACT_HOST_ROE = f"""
engagement:
  name: "Active surface gate - exact host"
  client: "self"
  authorized_window: {{start: "2026-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z"}}
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
    cidrs: ["203.0.113.0/24"]
    hosts: ["{_HOST}"]
rate_limits: {{max_requests_per_second: 50, max_concurrent_connections: 20}}
evasion: {{user_agents: ["UA-1"]}}
llm: {{analysis_enabled: false}}
"""

_DOMAIN_ONLY_ROE = """
engagement:
  name: "Active surface gate - domain only"
  client: "self"
  authorized_window: {start: "2026-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z"}
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
rate_limits: {max_requests_per_second: 50, max_concurrent_connections: 20}
evasion: {user_agents: ["UA-1"]}
llm: {analysis_enabled: false}
"""


class _FakeDNS(ReconModule):
    name = "dns"
    phase = ModulePhase.PASSIVE
    description = "fake dns: one A record for the exact in-scope host"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="dns_record",
            subject_value=_HOST,
            raw_data={"name": _HOST, "rtype": "A", "value": _IP, "ttl": 300},
            summary=f"{_HOST} A {_IP}",
        )


class _NoOp(ReconModule):
    """Inert stand-in for a transitive passive dependency we do not want to
    exercise - keeps dependency resolution happy without real traffic."""

    phase = ModulePhase.PASSIVE

    async def run(self, ctx: ModuleContext) -> None:
        return


# --- static classification checks (no DB) ---------------------------------


async def test_every_active_module_is_classified():
    """A newly registered ACTIVE module must be explicitly classified. This
    fails loudly rather than silently defaulting a network-capable adapter into
    the run - the runtime gate still fails closed (allowlist-only), but an
    unclassified module is a decision someone skipped."""
    active = {m.name for m in iter_modules() if m.phase is ModulePhase.ACTIVE}
    classified = _ACTIVE_SURFACE_ALLOWLIST | _ACTIVE_SURFACE_NETWORK_DENIED
    assert active == classified, (
        f"unclassified ACTIVE modules: {sorted(active - classified)}; "
        f"stale classifications: {sorted(classified - active)}"
    )


async def test_allowlist_and_denied_are_disjoint():
    assert not (_ACTIVE_SURFACE_ALLOWLIST & _ACTIVE_SURFACE_NETWORK_DENIED)


async def test_no_network_module_is_allowlisted():
    """Only local-only modules may be allowlisted; the network set is the
    inverse and is never runnable this release."""
    assert _ACTIVE_SURFACE_ALLOWLIST == {"scan_diff"}


# --- orchestrated behaviour ---------------------------------------------


@pytest.fixture
def _only(monkeypatch):
    """Restrict ``MODULES`` to ``dns`` + a named module under test, and spy on
    every gated module's ``run`` so a test can assert the adapter body was never
    entered. Also records any raw socket connect / subprocess exec."""
    saved = dict(MODULES)

    entered: list[str] = []

    def _spy_factory(name: str, orig):
        async def _run(self, ctx):  # noqa: ANN001
            entered.append(name)
            return await orig(self, ctx)

        return _run

    for name in _ACTIVE_SURFACE_NETWORK_DENIED | _ACTIVE_SURFACE_ALLOWLIST:
        mod = saved.get(name)
        if mod is not None:
            monkeypatch.setattr(type(mod), "run", _spy_factory(name, type(mod).run))

    connects: list[tuple] = []
    nmap_calls: list[list[str]] = []

    class _FakeWriter:
        def get_extra_info(self, key):  # noqa: ANN001
            return (_IP, 443) if key == "peername" else None

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def _fake_open_connection(host, port):  # noqa: ANN001
        connects.append((host, port))
        return (object(), _FakeWriter())

    async def _fake_run_command(argv, **kw):  # noqa: ANN001, ANN003
        nmap_calls.append(list(argv))
        raise AssertionError("no subprocess should be spawned by a gated module")

    monkeypatch.setattr("asyncio.open_connection", _fake_open_connection)
    monkeypatch.setattr("recon.net.external.run_command", _fake_run_command)

    _real_ok = _ACTIVE_SURFACE_NETWORK_DENIED | _ACTIVE_SURFACE_ALLOWLIST

    def _install(*names: str) -> None:
        MODULES.clear()
        MODULES["dns"] = _FakeDNS()
        need: set[str] = set(names)
        frontier = list(names)
        while frontier:
            for dep in saved[frontier.pop()].depends_on:
                if dep in saved and dep not in need:
                    need.add(dep)
                    frontier.append(dep)
        need.discard("dns")  # already installed as the fake above
        for n in need:
            if n in names or n in _real_ok:
                MODULES[n] = saved[n]  # real: the module under test, or a gated one
            else:
                stub = _NoOp()
                stub.name = n
                MODULES[n] = stub

    yield types.SimpleNamespace(
        install=_install, entered=entered, connects=connects, nmap_calls=nmap_calls
    )

    MODULES.clear()
    MODULES.update(saved)


@pytest.fixture(autouse=True)
async def _cleanup():
    yield
    kill_switch.reset()
    await scan_service.shutdown()
    scan_service._handles.clear()


async def _mk_engagement(roe: str) -> str:
    async with session_scope() as session:
        session.add(User(username="operator", password_hash="x"))
        eng, _ = await EngagementService().create(session, roe)
        return eng.id


async def _run_status(run_id: str) -> ScanRunStatus:
    async with session_scope() as s:
        return (await s.get(ScanRun, run_id)).status


async def _run_to_completion(engagement_id: str, modules: tuple[str, ...]) -> str:
    async with session_scope() as session:
        eng = await session.get(Engagement, engagement_id)
        run = await scan_service.start_scan(session, eng, list(modules))
        run_id = run.id

    await wait_for(lambda: _at_checkpoint(run_id))
    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _done(run_id))
    return run_id


async def _at_checkpoint(run_id: str) -> bool:
    return (await _run_status(run_id)) is ScanRunStatus.AWAITING_CHECKPOINT


async def _done(run_id: str) -> bool:
    return (await _run_status(run_id)) in (
        ScanRunStatus.COMPLETED,
        ScanRunStatus.FAILED,
        ScanRunStatus.PAUSED,
    )


async def _module_rows(run_id: str) -> dict[str, ScanModuleRun]:
    async with session_scope() as s:
        return {
            r.module_name: r
            for r in (
                await s.execute(
                    select(ScanModuleRun).where(ScanModuleRun.scan_run_id == run_id)
                )
            ).scalars()
        }


@pytest.mark.parametrize("modname", sorted(_ACTIVE_SURFACE_NETWORK_DENIED))
async def test_domain_only_denied_module_no_egress(_only, modname):
    """Domain-only RoE: no snapshot is created, the gated module's adapter is
    never entered, nothing leaves the process, and the run records an explicit
    terminal skip (not a completed / clean-empty result)."""
    _only.install(modname)
    engagement_id = await _mk_engagement(_DOMAIN_ONLY_ROE)
    run_id = await _run_to_completion(engagement_id, ("dns", modname))

    assert modname not in _only.entered
    assert _only.connects == []
    assert _only.nmap_calls == []

    async with session_scope() as s:
        snaps = (
            await s.execute(
                select(AuthorizationSnapshot).where(
                    AuthorizationSnapshot.scan_run_id == run_id
                )
            )
        ).scalars().all()
    assert snaps == []

    rows = await _module_rows(run_id)
    assert rows[modname].status is ModuleRunStatus.SKIPPED
    assert rows[modname].skip_reason is SkipReason.ACTIVE_SURFACE_DISABLED
    assert (await _run_status(run_id)) is ScanRunStatus.COMPLETED


@pytest.mark.parametrize("modname", sorted(_ACTIVE_SURFACE_NETWORK_DENIED))
async def test_snapshot_present_denied_module_still_skipped(_only, modname):
    """Even a valid exact-host snapshot + D0 attestation does not enable a
    network-capable ACTIVE module - it has no permit binding, so the gate skips
    it and the adapter is never entered."""
    _only.install(modname)
    engagement_id = await _mk_engagement(_EXACT_HOST_ROE)
    run_id = await _run_to_completion(engagement_id, ("dns", modname))

    async with session_scope() as s:
        snap = (
            await s.execute(
                select(AuthorizationSnapshot).where(
                    AuthorizationSnapshot.scan_run_id == run_id
                )
            )
        ).scalar_one()
        atts = (
            await s.execute(
                select(LivenessAttestation).where(
                    LivenessAttestation.scan_run_id == run_id
                )
            )
        ).scalars().all()
    assert snap is not None
    assert len(atts) == 1  # D0 still ran and attested the exact host

    assert modname not in _only.entered
    rows = await _module_rows(run_id)
    assert rows[modname].status is ModuleRunStatus.SKIPPED
    assert rows[modname].skip_reason is SkipReason.ACTIVE_SURFACE_DISABLED


async def test_scan_diff_skipped_without_snapshot(_only):
    """The allowlisted local-only module still fails closed with no snapshot."""
    _only.install("scan_diff")
    engagement_id = await _mk_engagement(_DOMAIN_ONLY_ROE)
    run_id = await _run_to_completion(engagement_id, ("dns", "scan_diff"))

    assert "scan_diff" not in _only.entered
    rows = await _module_rows(run_id)
    assert rows["scan_diff"].status is ModuleRunStatus.SKIPPED
    assert rows["scan_diff"].skip_reason is SkipReason.UNVERIFIED_TARGETS


async def test_scan_diff_runs_with_snapshot(_only):
    """The allowlisted local-only module runs once a snapshot exists - it emits
    no network traffic, so it is on the surface."""
    _only.install("scan_diff")
    engagement_id = await _mk_engagement(_EXACT_HOST_ROE)
    run_id = await _run_to_completion(engagement_id, ("dns", "scan_diff"))

    assert "scan_diff" in _only.entered
    # the only connects are D0's, all to the resolved in-scope IP
    assert _only.connects and all(host == _IP for host, _ in _only.connects)
    rows = await _module_rows(run_id)
    assert rows["scan_diff"].status is ModuleRunStatus.COMPLETED


async def test_disabled_module_renders_as_coverage_gap(_only):
    """A centrally-disabled module must not read as completed coverage in the
    report data - it is an explicit gap with an operator-facing label."""
    from recon.reporting.collect import build_report_data

    _only.install("subdomain_brute")
    engagement_id = await _mk_engagement(_DOMAIN_ONLY_ROE)
    run_id = await _run_to_completion(engagement_id, ("dns", "subdomain_brute"))

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        report = await build_report_data(s, eng)

    run = next(r for r in report["scan_runs"] if r["id"] == run_id)
    outcomes = {row["name"]: row for row in run["module_outcomes"]}
    assert outcomes["subdomain_brute"]["status"] == "skipped"
    assert outcomes["subdomain_brute"]["coverage_gap"] is True
    assert outcomes["subdomain_brute"]["skip_reason"] == "active_surface_disabled"
    assert "no approved active-scan method" in outcomes["subdomain_brute"]["reason"]
    assert report["summary"]["incomplete_coverage"] is True


async def test_resumed_run_keeps_disabled_skip_reason(_only):
    """A paused/resumed run must not relabel a centrally-disabled module as a
    benign ``resumed_prior_run`` (which would hide the coverage gap)."""
    _only.install("dns_axfr")
    engagement_id = await _mk_engagement(_DOMAIN_ONLY_ROE)
    run_id = await _run_to_completion(engagement_id, ("dns", "dns_axfr"))

    # simulate a resume of the already-finished active phase
    async with session_scope() as s:
        run = await s.get(ScanRun, run_id)
        run.status = ScanRunStatus.PAUSED
    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _done(run_id))

    rows = await _module_rows(run_id)
    assert rows["dns_axfr"].status is ModuleRunStatus.SKIPPED
    assert rows["dns_axfr"].skip_reason is SkipReason.ACTIVE_SURFACE_DISABLED
    assert "dns_axfr" not in _only.entered
