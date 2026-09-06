"""D0 connect-bind driver: dns answers + authorized hostname -> attestation +
audit, or a documented miss (P0-1 / G0 Section 2.3)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from recon.core.roe import RoEConfig
from recon.core.scope import ScopeManager
from recon.db import session_scope
from recon.models.authz import (
    AddressAudit,
    AuthorizedTarget,
    LivenessAttestation,
)
from recon.models.engagement import Engagement
from recon.models.enums import AddressOutcome
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.net.active_executor import ProbeResult
from recon.net.permit import PermitError
from recon.orchestrator.authorization import create_active_snapshot
from recon.orchestrator.d0 import run_d0_connect_bind
from recon.orchestrator.engagements import EngagementService

pytestmark = pytest.mark.asyncio

_TS = datetime(2026, 6, 1, tzinfo=UTC)

_ROE = """
engagement:
  name: "D0 Test"
  client: "self"
  authorized_window: {start: "2026-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z"}
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
    cidrs: ["203.0.113.0/24"]
    hosts: ["app.example.com"]
  excluded:
    hosts: ["evil.example.com"]
rate_limits: {max_requests_per_second: 10, max_concurrent_connections: 20}
evasion: {user_agents: ["UA-1"]}
llm: {analysis_enabled: false}
"""

_HOST = "app.example.com"
_IP = "203.0.113.10"


class _FakeExecutor:
    """Deterministic stand-in for ActiveExecutor: maps destination IP -> outcome."""

    def __init__(self, plan: dict[str, str], *, raise_on: set[str] | None = None) -> None:
        self._plan = plan
        self._raise_on = raise_on or set()
        self.calls: list[str] = []

    async def run(self, permit) -> ProbeResult:
        self.calls.append(permit.destination_ip)
        if permit.destination_ip in self._raise_on:
            raise PermitError(f"peer mismatch for {permit.destination_ip}")
        outcome = self._plan.get(permit.destination_ip, "completed")
        return ProbeResult(
            permit_id=permit.permit_id,
            operation=permit.operation,
            method_profile_id=permit.method_profile_id,
            destination_ip=permit.destination_ip,
            dispatched=True,
            outcome=outcome,
            detail=f"fake {outcome}",
            peer_ip=permit.destination_ip if outcome == "completed" else None,
            started_at=_TS,
            ended_at=_TS,
        )


async def _seed_run(session, engagement_id: str) -> ScanRun:
    session.add(User(username=f"op-{uuid.uuid4().hex[:10]}", password_hash="x"))
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
            scan_run_id=run.id, engagement_id=engagement_id,
            module_name="dns", phase="passive", status="completed",
        )
    )
    await session.flush()
    return run


async def _dns_ev(session, run: ScanRun, name: str, ip: str, rtype: str = "A") -> None:
    session.add(
        Evidence(
            engagement_id=run.engagement_id,
            scan_run_id=run.id,
            source_module="dns",
            subject_type="dns_record",
            subject_value=name,
            raw_data={"name": name, "rtype": rtype, "value": ip, "ttl": 300},
        )
    )
    await session.flush()


@pytest.fixture
async def _engagement_id():
    async with session_scope() as session:
        eng, _ = await EngagementService().create(session, _ROE)
        return eng.id


async def _drive(engagement_id, *, answers, executor):
    async with session_scope() as session:
        run = await _seed_run(session, engagement_id)
        for name, ips in answers.items():
            for ip in ips:
                await _dns_ev(session, run, name, ip)
        eng = await session.get(Engagement, engagement_id)
        roe = RoEConfig.model_validate(eng.roe_config)
        snapshot = await create_active_snapshot(session, run, roe)
        scope = ScopeManager(roe)
        from recon.net.rate_limit import RateLimiter

        result = await run_d0_connect_bind(
            session, run=run, snapshot=snapshot, scope=scope,
            rate_limiter=RateLimiter(100), is_cancelled=lambda: False,
            executor=executor,
        )
        run_id = run.id
    return run_id, result


async def test_snapshot_creates_one_authorized_target_per_exact_host(_engagement_id):
    async with session_scope() as session:
        run = await _seed_run(session, _engagement_id)
        eng = await session.get(Engagement, _engagement_id)
        roe = RoEConfig.model_validate(eng.roe_config)
        snap = await create_active_snapshot(session, run, roe)
        targets = (
            await session.execute(
                select(AuthorizedTarget).where(AuthorizedTarget.snapshot_id == snap.id)
            )
        ).scalars().all()
    assert {t.value for t in targets} == {_HOST}  # domains/apex not authorized
    assert snap.policy_version == "p1"


async def test_live_bind_mints_attestation_evidence_and_audit(_engagement_id):
    ex = _FakeExecutor({_IP: "completed"})
    run_id, result = await _drive(_engagement_id, answers={_HOST: {_IP}}, executor=ex)
    assert ex.calls == [_IP]
    assert len(result.attestation_ids) == 1
    async with session_scope() as s:
        att = (await s.execute(select(LivenessAttestation).where(
            LivenessAttestation.scan_run_id == run_id))).scalar_one()
        audit = (await s.execute(select(AddressAudit).where(
            AddressAudit.scan_run_id == run_id))).scalar_one()
        ev = await s.get(Evidence, att.evidence_id)
    assert att.observed_ip == _IP and att.source_hostname == _HOST
    assert audit.outcome is AddressOutcome.LIVE
    assert audit.liveness_attestation_id == att.id
    from recon.orchestrator.permit_resolver import canonical_probe_hash

    assert ev.subject_type == "live_host"
    assert canonical_probe_hash(ev.raw_data) == att.content_hash


async def test_non_exact_hostname_mints_nothing(_engagement_id):
    ex = _FakeExecutor({})
    # a subdomain of an in-scope domain, but not an exact in_scope.host
    run_id, result = await _drive(
        _engagement_id, answers={"other.example.com": {_IP}}, executor=ex
    )
    assert ex.calls == []
    assert result.attestation_ids == []
    async with session_scope() as s:
        atts = (await s.execute(select(LivenessAttestation).where(
            LivenessAttestation.scan_run_id == run_id))).scalars().all()
    assert atts == []


async def test_peer_mismatch_audits_excluded_no_attestation(_engagement_id):
    ex = _FakeExecutor({}, raise_on={_IP})
    run_id, result = await _drive(_engagement_id, answers={_HOST: {_IP}}, executor=ex)
    assert result.attestation_ids == []
    async with session_scope() as s:
        audit = (await s.execute(select(AddressAudit).where(
            AddressAudit.scan_run_id == run_id))).scalar_one()
    assert audit.outcome is AddressOutcome.EXCLUDED


async def test_refused_connect_audits_no_response_no_attestation(_engagement_id):
    ex = _FakeExecutor({_IP: "refused"})
    run_id, result = await _drive(_engagement_id, answers={_HOST: {_IP}}, executor=ex)
    assert result.attestation_ids == []
    async with session_scope() as s:
        audit = (await s.execute(select(AddressAudit).where(
            AddressAudit.scan_run_id == run_id))).scalar_one()
    assert audit.outcome is AddressOutcome.NO_RESPONSE


async def test_poisoned_answer_outside_authorized_cidr_mints_nothing(_engagement_id):
    # the hostname is an exact in_scope.host, but this run's DNS answer points at
    # an IP in no in-scope CIDR (a poisoned / hijacked A record). getpeername
    # defeats a post-connect rebind; it does not authenticate the answer (Q1).
    ex = _FakeExecutor({})
    run_id, result = await _drive(
        _engagement_id, answers={_HOST: {"198.51.100.9"}}, executor=ex
    )
    assert ex.calls == []
    assert result.attestation_ids == []
    async with session_scope() as s:
        atts = (await s.execute(select(LivenessAttestation).where(
            LivenessAttestation.scan_run_id == run_id))).scalars().all()
    assert atts == []


async def test_max_addresses_per_run_caps_binding(_engagement_id, monkeypatch):
    from recon.core import active_policy as ap

    capped = ap.ActiveScanPolicy(
        version="p1",
        method_allowlist=frozenset({"dns_connect_bind_v1"}),
        max_addresses_per_run=1,
        max_aggregate_cidr_addresses=256,
        per_method_rate={"dns_connect_bind_v1": 2.0},
        per_method_concurrency={"dns_connect_bind_v1": 2},
        per_method_ports={"dns_connect_bind_v1": (443,)},
        probe_timeout_seconds=2.0,
        max_retries=0,
        total_time_budget_seconds=30.0,
    )
    monkeypatch.setitem(ap._POLICIES, "p1", capped)
    ex = _FakeExecutor({})
    await _drive(
        _engagement_id, answers={_HOST: {"203.0.113.10", "203.0.113.11"}}, executor=ex
    )
    assert len(ex.calls) == 1
