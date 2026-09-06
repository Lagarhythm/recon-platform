"""Shared fixtures for the ``tests/active/`` package.

This package holds the Package 3 abuse-and-acceptance suite
(``PLANS/RECON_P0_PACKAGE3_SECURITY_GATE.md`` / the revised target contract)
re-pointed at the **implemented** FK-backed active-scan boundary:

* ``recon.orchestrator.authorization.create_active_snapshot`` (checkpoint
  persistence + exact-host ``AuthorizedTarget`` rows),
* ``recon.orchestrator.permit_resolver.ActivePermitResolver`` (the only minter)
  + ``make_predispatch_check`` (dispatch-time re-verification),
* ``recon.net.permit.ActiveTargetPermit`` (opaque, non-caller-constructible),
* ``recon.net.active_executor.ActiveExecutor`` (permit-only, ``getpeername``
  rebind check),
* ``recon.orchestrator.d0.run_d0_connect_bind`` (the D0 driver).

``RecordingBoundary`` stands in for the OS network syscalls behind
``ActiveExecutor`` - every TCP connect and every subprocess exec is appended to
``.network_calls`` and performs no real I/O. For every *negative* abuse case
``.network_calls`` must stay ``[]``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio

from recon.core.roe import RoEConfig
from recon.core.scope import ScopeManager
from recon.db import session_scope
from recon.models.authz import AuthorizationSnapshot
from recon.models.engagement import Engagement
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.net.external import CommandResult
from recon.net.rate_limit import RateLimiter
from recon.orchestrator.authorization import create_active_snapshot
from recon.orchestrator.d0 import run_d0_connect_bind
from recon.orchestrator.engagements import EngagementService
from recon.orchestrator.permit_resolver import ActivePermitResolver, make_predispatch_check

TS = datetime(2026, 6, 1, tzinfo=UTC)

HOST = "app.example.com"
HOST_IP = "203.0.113.10"

# domains has NO wildcard, so any subdomain that is not an exact in_scope.host is
# FLAGGED; 198.51.100.0/24 is not in any in-scope CIDR.
ACTIVE_ROE = """
engagement:
  name: "Active Boundary Abuse Suite"
  client: "self"
  authorized_window: {start: "2026-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z"}
scope:
  in_scope:
    domains: ["example.com"]
    cidrs: ["203.0.113.0/24"]
    hosts: ["app.example.com"]
  excluded:
    hosts: ["evil.example.com"]
    cidrs: ["203.0.113.128/25"]
rate_limits: {max_requests_per_second: 50, max_concurrent_connections: 20}
evasion: {user_agents: ["UA-1"]}
llm: {analysis_enabled: false}
"""

_NMAP_XML = f"""<?xml version="1.0"?><nmaprun>
<host><status state="up"/>
<address addr="{HOST_IP}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.24"/></port></ports>
</host></nmaprun>"""


class _FakeWriter:
    def __init__(self, peer_ip: str, port: int = 443) -> None:
        self._peer = (peer_ip, port)

    def get_extra_info(self, key: str):
        return self._peer if key == "peername" else None

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


class RecordingBoundary:
    """Drop-in stand-in for the OS network syscalls behind ``ActiveExecutor``.

    Nothing here opens a socket or spawns a process. Every attempted network
    operation is recorded in ``network_calls`` as a tuple:
    ``("connect", host, port)`` or ``("exec", argv_list)``.
    """

    def __init__(self, *, peer_ip: str | None = None) -> None:
        self.network_calls: list[tuple] = []
        #: if set, every fake connect reports this as ``getpeername()`` - used to
        #: exercise the executor's redirect / DNS-rebind rejection.
        self.peer_ip_override = peer_ip
        #: if True, a fake connect is *recorded* then refused (a probe miss).
        self.refuse = False

    async def open_connection(self, host, port):
        self.network_calls.append(("connect", host, port))
        if self.refuse:
            raise ConnectionRefusedError(f"refused {host}:{port}")
        peer = self.peer_ip_override or host
        return (object(), _FakeWriter(peer, port))

    async def run_command(self, argv, **_kwargs):
        self.network_calls.append(("exec", list(argv)))
        return CommandResult(argv=list(argv), returncode=0, stdout=_NMAP_XML, stderr="")

    def install(self, monkeypatch) -> RecordingBoundary:
        monkeypatch.setattr("asyncio.open_connection", self.open_connection)
        return self


@pytest.fixture
def boundary() -> RecordingBoundary:
    return RecordingBoundary()


@pytest_asyncio.fixture
async def active_engagement() -> str:
    """A committed engagement from ``ACTIVE_ROE`` plus one operator ``User``
    (so ``create_active_snapshot`` can resolve the sole actor). Returns its id."""
    async with session_scope() as session:
        session.add(User(username=f"op-{uuid.uuid4().hex[:10]}", password_hash="x"))
        eng, _ = await EngagementService().create(session, ACTIVE_ROE)
        return eng.id


async def seed_active_run(session, engagement_id: str) -> ScanRun:
    run = ScanRun(
        engagement_id=engagement_id,
        roe_config_snapshot={},
        roe_config_hash="h",
        modules_requested=["dns", "port_scan"],
        modules_completed=["dns"],
        status="running",
        active_confirmed=True,
    )
    session.add(run)
    await session.flush()
    session.add(
        ScanModuleRun(
            scan_run_id=run.id,
            engagement_id=engagement_id,
            module_name="dns",
            phase="passive",
            status="completed",
        )
    )
    await session.flush()
    return run


async def add_dns_answer(session, run: ScanRun, name: str, value: str, rtype: str = "A") -> None:
    session.add(
        Evidence(
            engagement_id=run.engagement_id,
            scan_run_id=run.id,
            source_module="dns",
            subject_type="dns_record",
            subject_value=name,
            raw_data={"name": name, "rtype": rtype, "value": value, "ttl": 300},
        )
    )
    await session.flush()


async def roe_for(session, engagement_id: str) -> RoEConfig:
    eng = await session.get(Engagement, engagement_id)
    return RoEConfig.model_validate(eng.roe_config)


async def drive_d0(
    engagement_id: str,
    *,
    answers: dict[str, set[str]],
    boundary: RecordingBoundary,
    monkeypatch,
    flow: str = "interactive",
    is_cancelled=None,
):
    """Run the real D0 driver with a real ``ActiveExecutor`` whose only network
    egress is ``boundary``. Returns ``(run_id, snapshot_id, D0Result)``.

    The snapshot + DNS evidence are committed *before* D0 runs, mirroring
    ``scans.py`` (the executor's dispatch-time recheck opens its own session and
    must see the persisted authorization)."""
    from recon.core.active_policy import active_policy
    from recon.core.dns_answers import run_dns_answers
    from recon.net.active_executor import ActiveExecutor
    from recon.orchestrator.killswitch import kill_switch

    boundary.install(monkeypatch)

    async with session_scope() as session:
        run = await seed_active_run(session, engagement_id)
        for name, ips in answers.items():
            for ip in ips:
                await add_dns_answer(session, run, name, ip)
        roe = await roe_for(session, engagement_id)
        snapshot = await create_active_snapshot(session, run, roe, flow=flow)
        run_id, snapshot_id = run.id, snapshot.id

    cancel = is_cancelled or (lambda: False)
    async with session_scope() as session:
        run = await session.get(ScanRun, run_id)
        snapshot = await session.get(AuthorizationSnapshot, snapshot_id)
        roe = await roe_for(session, engagement_id)
        scope = ScopeManager(roe)
        policy = active_policy(snapshot.policy_version)
        dns_answers = await run_dns_answers(session, run_id)
        predispatch = make_predispatch_check(
            session_scope,
            policy=policy,
            scope_classifier=scope.classify,
            dns_answers=dns_answers,
        )
        executor = ActiveExecutor(
            rate_limiter=RateLimiter(100),
            kill_switch=kill_switch,
            is_cancelled=cancel,
            predispatch_check=predispatch,
            command_runner=boundary.run_command,
        )
        result = await run_d0_connect_bind(
            session,
            run=run,
            snapshot=snapshot,
            scope=scope,
            rate_limiter=RateLimiter(100),
            is_cancelled=cancel,
            executor=executor,
        )
    return run_id, snapshot_id, result


def make_resolver(session, *, run_id, snapshot_id, dns_answers, scope, smr_id=None, policy=None):
    from recon.core.active_policy import BOOTSTRAP_POLICY

    return ActivePermitResolver(
        session,
        scan_run_id=run_id,
        scan_module_run_id=smr_id or run_id,
        module_name="dns",
        snapshot_id=snapshot_id,
        policy=policy or BOOTSTRAP_POLICY,
        scope_classifier=scope.classify,
        dns_answers=dns_answers,
    )
