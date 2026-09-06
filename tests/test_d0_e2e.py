"""D0 end to end through ScanService: one `dns,port_scan` invocation, the
passive dns answer becomes a permit-gated connect-bind attestation bound to a
checkpoint-acknowledged CIDR, and ``port_scan`` - which is out of the G2 active
surface (Security G2 re-review, S2) - records a clean ``SKIPPED /
unverified_targets`` and issues **no** nmap call (P0-1 acceptance)."""

from __future__ import annotations

import types

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.authz import AddressAudit, AuthorizationSnapshot, LivenessAttestation
from recon.models.engagement import Engagement
from recon.models.enums import (
    AddressOutcome,
    ModulePhase,
    ModuleRunStatus,
    ScanRunStatus,
    SkipReason,
)
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES
from recon.net.external import CommandResult
from recon.orchestrator.engagements import EngagementService
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import scan_service
from tests.conftest import wait_for

pytestmark = pytest.mark.asyncio

_HOST = "app.example.com"
_IP = "203.0.113.10"

_ROE = f"""
engagement:
  name: "D0 E2E"
  client: "self"
  authorized_window: {{start: "2026-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z"}}
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
    cidrs: ["203.0.113.0/24"]
    hosts: ["{_HOST}"]
  excluded: {{cidrs: ["203.0.113.128/25"]}}
rate_limits: {{max_requests_per_second: 50, max_concurrent_connections: 20}}
evasion: {{user_agents: ["UA-1"]}}
llm: {{analysis_enabled: false}}
"""

_NMAP_XML = f"""<?xml version="1.0"?><nmaprun>
<host><status state="up"/>
<address addr="{_IP}" addrtype="ipv4"/>
<hostnames><hostname name="{_HOST}"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.24"/></port></ports>
</host></nmaprun>"""


# tests mutate this to steer the fake dns module's single A answer
_DNS_ANSWER = {"name": _HOST, "ip": _IP}


class _FakeDNS(ReconModule):
    name = "dns"
    phase = ModulePhase.PASSIVE
    description = "fake dns: one A record"

    async def run(self, ctx: ModuleContext) -> None:
        if _DNS_ANSWER is None:
            return
        await ctx.add_evidence(
            subject_type="dns_record",
            subject_value=_DNS_ANSWER["name"],
            raw_data={
                "name": _DNS_ANSWER["name"], "rtype": "A",
                "value": _DNS_ANSWER["ip"], "ttl": 300,
            },
            summary=f"{_DNS_ANSWER['name']} A {_DNS_ANSWER['ip']}",
        )


@pytest.fixture(autouse=True)
def _reset_dns_answer():
    global _DNS_ANSWER
    saved = dict(_DNS_ANSWER) if _DNS_ANSWER else None
    yield
    _DNS_ANSWER = saved


@pytest.fixture(autouse=True)
def _fakes(monkeypatch):
    real_dns = MODULES.get("dns")
    MODULES["dns"] = _FakeDNS()

    # port_scan is out of the G2 surface and no longer execs anything; this
    # records any subprocess exec so the test can assert there was none.
    nmap_calls: list[list[str]] = []

    async def _fake_run_command(argv, **kw):
        nmap_calls.append(list(argv))
        return CommandResult(argv=argv, returncode=0, stdout=_NMAP_XML, stderr="")

    monkeypatch.setattr("recon.net.external.run_command", _fake_run_command)

    class _FakeWriter:
        def __init__(self, ip):
            self._ip = ip

        def get_extra_info(self, key):
            return (self._ip, 443) if key == "peername" else None

        def close(self):
            pass

        async def wait_closed(self):
            pass

    connects: list[tuple] = []

    async def _fake_open_connection(host, port):
        connects.append((host, port))
        return (object(), _FakeWriter(host))

    monkeypatch.setattr("asyncio.open_connection", _fake_open_connection)

    yield types.SimpleNamespace(nmap_calls=nmap_calls, connects=connects)

    if real_dns is not None:
        MODULES["dns"] = real_dns
    else:
        MODULES.pop("dns", None)


@pytest.fixture(autouse=True)
async def _cleanup():
    yield
    kill_switch.reset()
    await scan_service.shutdown()
    scan_service._handles.clear()


async def _run_status(run_id):
    async with session_scope() as s:
        return (await s.get(ScanRun, run_id)).status


async def _start_resume_finish(engagement_id, modules=("dns", "port_scan")):
    async with session_scope() as session:
        eng = await session.get(Engagement, engagement_id)
        run = await scan_service.start_scan(session, eng, list(modules))
        run_id = run.id

    async def _at_checkpoint():
        return (await _run_status(run_id)) is ScanRunStatus.AWAITING_CHECKPOINT

    await wait_for(_at_checkpoint)
    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _done(run_id))
    return run_id


async def test_d0_full_chain_one_invocation(_fakes):
    nmap_calls = _fakes.nmap_calls
    async with session_scope() as session:
        session.add(User(username="operator", password_hash="x"))
        eng, _ = await EngagementService().create(session, _ROE)
        engagement_id = eng.id

    async with session_scope() as session:
        eng = await session.get(Engagement, engagement_id)
        run = await scan_service.start_scan(session, eng, ["dns", "port_scan"])
        run_id = run.id

    async def _at_checkpoint():
        return (await _run_status(run_id)) is ScanRunStatus.AWAITING_CHECKPOINT

    await wait_for(_at_checkpoint)
    async with session_scope() as s:
        await scan_service.resume_scan(s, run_id)
    await wait_for(lambda: _done(run_id))

    async with session_scope() as s:
        snap = (await s.execute(select(AuthorizationSnapshot).where(
            AuthorizationSnapshot.scan_run_id == run_id))).scalar_one()
        att = (await s.execute(select(LivenessAttestation).where(
            LivenessAttestation.scan_run_id == run_id))).scalar_one()
        audits = (await s.execute(select(AddressAudit).where(
            AddressAudit.scan_run_id == run_id))).scalars().all()
        svc_ev = (await s.execute(select(Evidence).where(
            Evidence.scan_run_id == run_id, Evidence.subject_type == "service"))).scalars().all()
        live_ev = await s.get(Evidence, att.evidence_id)
        mruns = {
            r.module_name: r
            for r in (await s.execute(select(ScanModuleRun).where(
                ScanModuleRun.scan_run_id == run_id))).scalars().all()
        }

    # port_scan is out of the G2 surface: no nmap call, no service evidence.
    assert nmap_calls == []
    assert svc_ev == []

    # D0 still ran: the passive A answer became a permit-gated, CIDR-bound
    # connect attestation.
    from recon.orchestrator.permit_resolver import canonical_probe_hash

    assert canonical_probe_hash(live_ev.raw_data) == att.content_hash
    assert att.observed_ip == _IP and att.source_hostname == _HOST
    assert att.authorization_snapshot_id == snap.id
    assert [a.outcome for a in audits] == [AddressOutcome.LIVE]
    assert mruns["port_scan"].status is ModuleRunStatus.SKIPPED
    assert mruns["port_scan"].skip_reason is SkipReason.UNVERIFIED_TARGETS


_DOMAIN_ONLY_ROE = """
engagement:
  name: "Domain only"
  client: "self"
  authorized_window: {start: "2026-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z"}
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
rate_limits: {max_requests_per_second: 50, max_concurrent_connections: 20}
evasion: {user_agents: ["UA-1"]}
llm: {analysis_enabled: false}
"""


async def test_domain_only_roe_no_egress(_fakes):
    """S1: a domain-only RoE (no exact hosts, no CIDR) never creates an
    authorization snapshot, never promotes a passive-evidence target, and
    port_scan fails closed to SKIPPED/unverified_targets with zero egress."""
    async with session_scope() as session:
        session.add(User(username="operator", password_hash="x"))
        eng, _ = await EngagementService().create(session, _DOMAIN_ONLY_ROE)
        engagement_id = eng.id

    run_id = await _start_resume_finish(engagement_id)

    async with session_scope() as s:
        snaps = (await s.execute(select(AuthorizationSnapshot).where(
            AuthorizationSnapshot.scan_run_id == run_id))).scalars().all()
        atts = (await s.execute(select(LivenessAttestation).where(
            LivenessAttestation.scan_run_id == run_id))).scalars().all()
        svc_ev = (await s.execute(select(Evidence).where(
            Evidence.scan_run_id == run_id, Evidence.subject_type == "service"))).scalars().all()
        mruns = {
            r.module_name: r
            for r in (await s.execute(select(ScanModuleRun).where(
                ScanModuleRun.scan_run_id == run_id))).scalars().all()
        }

    assert snaps == []
    assert atts == []
    assert svc_ev == []
    assert _fakes.nmap_calls == []
    assert _fakes.connects == []
    assert mruns["port_scan"].status is ModuleRunStatus.SKIPPED
    assert mruns["port_scan"].skip_reason is SkipReason.UNVERIFIED_TARGETS


async def test_poisoned_exact_host_dns_no_egress(_fakes):
    """Q1: an exact authorized hostname whose (poisoned) A answer points outside
    every checkpoint-acknowledged CIDR mints no permit - zero socket connects at
    mint time - and port_scan still skips."""
    global _DNS_ANSWER
    _DNS_ANSWER = {"name": _HOST, "ip": "198.51.100.9"}  # outside 203.0.113.0/24

    async with session_scope() as session:
        session.add(User(username="operator", password_hash="x"))
        eng, _ = await EngagementService().create(session, _ROE)
        engagement_id = eng.id

    run_id = await _start_resume_finish(engagement_id)

    async with session_scope() as s:
        snap = (await s.execute(select(AuthorizationSnapshot).where(
            AuthorizationSnapshot.scan_run_id == run_id))).scalar_one()
        atts = (await s.execute(select(LivenessAttestation).where(
            LivenessAttestation.scan_run_id == run_id))).scalars().all()
        audits = (await s.execute(select(AddressAudit).where(
            AddressAudit.scan_run_id == run_id))).scalars().all()
        mruns = {
            r.module_name: r
            for r in (await s.execute(select(ScanModuleRun).where(
                ScanModuleRun.scan_run_id == run_id))).scalars().all()
        }

    assert snap is not None  # snapshot IS created (exact host + CIDR present)
    assert atts == []  # but the poisoned answer never binds
    assert _fakes.connects == []  # zero socket connects at mint time
    assert _fakes.nmap_calls == []
    assert all(a.outcome is not AddressOutcome.LIVE for a in audits)
    assert mruns["port_scan"].status is ModuleRunStatus.SKIPPED
    assert mruns["port_scan"].skip_reason is SkipReason.UNVERIFIED_TARGETS


async def _done(run_id) -> bool:
    st = await _run_status(run_id)
    return st in (ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.PAUSED)
