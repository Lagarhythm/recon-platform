"""D0 end to end through ScanService: one `dns,port_scan` invocation, the
passive dns answer becomes a permit-gated connect-bind attestation, and
port_scan issues exactly one nmap call against the attested IP - never the
hostname, never an unattested address (P0-1 acceptance)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.authz import AddressAudit, AuthorizationSnapshot, LivenessAttestation
from recon.models.engagement import Engagement
from recon.models.enums import AddressOutcome, ModulePhase, ModuleRunStatus, ScanRunStatus
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


class _FakeDNS(ReconModule):
    name = "dns"
    phase = ModulePhase.PASSIVE
    description = "fake dns: one in-scope A record"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="dns_record",
            subject_value=_HOST,
            raw_data={"name": _HOST, "rtype": "A", "value": _IP, "ttl": 300},
            summary=f"{_HOST} A {_IP}",
        )


@pytest.fixture(autouse=True)
def _fakes(monkeypatch):
    real_dns = MODULES.get("dns")
    MODULES["dns"] = _FakeDNS()

    monkeypatch.setattr(
        "recon.modules.active.port_scan.find_binary", lambda _n: "/usr/bin/nmap"
    )

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

    async def _fake_open_connection(host, port):
        return (object(), _FakeWriter(host))

    monkeypatch.setattr("asyncio.open_connection", _fake_open_connection)

    yield nmap_calls

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


async def test_d0_full_chain_one_invocation(_fakes):
    nmap_calls = _fakes
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

    # exactly one nmap call, IP-only, hostname never in argv
    assert len(nmap_calls) == 1, nmap_calls
    argv = nmap_calls[0]
    assert _IP in argv and _HOST not in argv
    assert "__DESTINATION__" not in argv

    from recon.orchestrator.permit_resolver import canonical_probe_hash

    assert canonical_probe_hash(live_ev.raw_data) == att.content_hash
    assert att.observed_ip == _IP and att.source_hostname == _HOST
    assert att.authorization_snapshot_id == snap.id
    assert [a.outcome for a in audits] == [AddressOutcome.LIVE]
    assert svc_ev and any("443" in e.subject_value for e in svc_ev)
    assert mruns["port_scan"].status is ModuleRunStatus.COMPLETED


async def _done(run_id) -> bool:
    st = await _run_status(run_id)
    return st in (ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.PAUSED)
