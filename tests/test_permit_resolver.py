"""ActivePermitResolver is the only minter, and it re-verifies the whole
authorization chain at mint time; make_predispatch_check re-verifies again
immediately before dispatch (G0 Part 3, Security B1 verification 1 + 4)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from recon.core.active_policy import BOOTSTRAP_POLICY
from recon.db import session_scope
from recon.models.authz import (
    DNS_CONNECT_BIND_V1,
    AuthorizationSnapshot,
    AuthorizedTarget,
    LivenessAttestation,
)
from recon.models.enums import ScopeStatus
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.net.permit import PermitError, is_genuine_permit
from recon.orchestrator.permit_resolver import (
    ActivePermitResolver,
    canonical_probe_hash,
    make_predispatch_check,
)

pytestmark = pytest.mark.asyncio

_TS = datetime(2026, 6, 1, tzinfo=UTC)
_HOST = "app.example.com"
_IP = "203.0.113.10"


class _Decision:
    def __init__(self, status: ScopeStatus) -> None:
        self.status = status


def _classifier(status=ScopeStatus.IN_SCOPE):
    return lambda *a, **kw: _Decision(status)


async def _seed(session, engagement_id: str, *, revoked: bool = False) -> dict:
    user = User(username=f"op-{uuid.uuid4().hex[:12]}", password_hash="x")
    session.add(user)
    await session.flush()

    run = ScanRun(
        engagement_id=engagement_id,
        roe_config_snapshot={},
        roe_config_hash="h",
        modules_requested=[],
        modules_completed=[],
        status="running",
    )
    session.add(run)
    await session.flush()

    smr = ScanModuleRun(
        scan_run_id=run.id,
        engagement_id=engagement_id,
        module_name="dns",
        phase="active",
        status="running",
    )
    session.add(smr)

    snap = AuthorizationSnapshot(
        scan_run_id=run.id,
        engagement_id=engagement_id,
        roe_config_hash="h",
        scope_policy_hash="sp",
        authorized_by_user_id=user.id,
        authorized_at=_TS,
        checkpoint_ack_hash="ack",
        checkpoint_payload={},
        flow="interactive",
        policy_version=BOOTSTRAP_POLICY.version,
    )
    if revoked:
        snap.revoked_at = _TS
        snap.revoked_by_user_id = user.id
        snap.revoked_reason = "test"
    session.add(snap)
    await session.flush()

    target = AuthorizedTarget(
        snapshot_id=snap.id,
        target_type="hostname",
        value=_HOST,
        source="roe_host",
    )
    session.add(target)
    await session.flush()

    return {
        "user_id": user.id,
        "run_id": run.id,
        "smr_id": smr.id,
        "snapshot_id": snap.id,
        "target_id": target.id,
    }


async def _attestation(session, ids: dict, engagement_id: str, *, observed_ip=_IP) -> str:
    raw = {"host": _HOST, "ip": observed_ip, "port": 443}
    ev = Evidence(
        engagement_id=engagement_id,
        source_module="dns",
        scan_run_id=ids["run_id"],
        subject_type="ip",
        subject_value=observed_ip,
        raw_data=raw,
    )
    session.add(ev)
    await session.flush()
    att = LivenessAttestation(
        scan_run_id=ids["run_id"],
        engagement_id=engagement_id,
        evidence_id=ev.id,
        content_hash=canonical_probe_hash(raw),
        method_profile_id=DNS_CONNECT_BIND_V1,
        observed_at=_TS,
        observed_ip=observed_ip,
        emitting_module="dns",
        authorization_snapshot_id=ids["snapshot_id"],
        authorized_target_id=ids["target_id"],
        source_hostname=_HOST,
    )
    session.add(att)
    await session.flush()
    return att.id


def _resolver(session, ids, *, dns_answers, classifier=None):
    return ActivePermitResolver(
        session,
        scan_run_id=ids["run_id"],
        scan_module_run_id=ids["smr_id"],
        module_name="dns",
        snapshot_id=ids["snapshot_id"],
        policy=BOOTSTRAP_POLICY,
        scope_classifier=classifier or _classifier(),
        dns_answers=dns_answers,
    )


# --- D0 connect-bind minting ------------------------------------------


async def test_mint_dns_connect_bind_happy_path(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permits = await r.mint_dns_connect_bind_permits(_HOST)
    assert len(permits) == 1
    p = permits[0]
    assert is_genuine_permit(p)
    assert p.destination_ip == _IP
    assert p.operation == "dns_connect_bind"
    assert p.authorized_target_id == ids["target_id"]
    assert p.authorized_cidr_id is None


async def test_non_exact_hostname_mints_nothing(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={"evil.example.com": {_IP}})
        with pytest.raises(PermitError):
            await r.mint_dns_connect_bind_permits("evil.example.com")


async def test_revoked_snapshot_mints_nothing(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id, revoked=True)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        with pytest.raises(PermitError):
            await r.mint_dns_connect_bind_permits(_HOST)


async def test_no_dns_answer_mints_nothing(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={})
        with pytest.raises(PermitError):
            await r.mint_dns_connect_bind_permits(_HOST)


async def test_excluded_answer_is_dropped(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(
            session, ids, dns_answers={_HOST: {_IP}},
            classifier=_classifier(ScopeStatus.EXCLUDED),
        )
        with pytest.raises(PermitError):
            await r.mint_dns_connect_bind_permits(_HOST)


async def test_cidr_discovery_is_disabled(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        with pytest.raises(PermitError):
            await r.resolve_authorized_cidrs()
        with pytest.raises(PermitError):
            await r.mint_discovery_permits()


# --- port-scan minting from an attestation ---------------------------


async def test_mint_portscan_permit_happy_path(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        att_id = await _attestation(session, ids, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permit = await r.mint_portscan_permit(att_id, argv_shape=("nmap", "__DESTINATION__"))
    assert permit.operation == "port_scan"
    assert permit.destination_ip == _IP
    assert permit.liveness_attestation_id == att_id
    assert permit.authorized_target_id == ids["target_id"]


async def test_portscan_permit_rejects_attestation_from_another_run(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        att_id = await _attestation(session, ids, engagement_id)
        other = await _seed(session, engagement_id)
        r = _resolver(session, other, dns_answers={_HOST: {_IP}})
        with pytest.raises(PermitError):
            await r.mint_portscan_permit(att_id, argv_shape=("nmap", "__DESTINATION__"))


async def test_portscan_permit_rejects_ip_not_in_run_dns(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        att_id = await _attestation(session, ids, engagement_id, observed_ip="198.51.100.5")
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})  # 198.51.100.5 not here
        with pytest.raises(PermitError):
            await r.mint_portscan_permit(att_id, argv_shape=("nmap", "__DESTINATION__"))


async def test_portscan_permit_rejects_tampered_evidence(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        att_id = await _attestation(session, ids, engagement_id)
        att = await session.get(LivenessAttestation, att_id)
        ev = await session.get(Evidence, att.evidence_id)
        ev.raw_data = {"host": _HOST, "ip": _IP, "port": 443, "tampered": True}
        await session.flush()
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        with pytest.raises(PermitError):
            await r.mint_portscan_permit(att_id, argv_shape=("nmap", "__DESTINATION__"))


# --- dispatch-time re-verification ----------------------------------


async def test_predispatch_passes_for_a_fresh_permit(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permits = await r.mint_dns_connect_bind_permits(_HOST)
    check = make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=_classifier(),
        dns_answers={_HOST: {_IP}},
    )
    await check(permits[0])  # no raise


async def test_predispatch_rejects_after_revocation(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permits = await r.mint_dns_connect_bind_permits(_HOST)

    async with session_scope() as session:
        snap = await session.get(AuthorizationSnapshot, ids["snapshot_id"])
        snap.revoked_at = _TS

    check = make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=_classifier(),
        dns_answers={_HOST: {_IP}},
    )
    with pytest.raises(PermitError):
        await check(permits[0])


async def test_predispatch_rejects_a_now_out_of_scope_destination(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permits = await r.mint_dns_connect_bind_permits(_HOST)
    check = make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=_classifier(ScopeStatus.EXCLUDED),
        dns_answers={_HOST: {_IP}},
    )
    with pytest.raises(PermitError):
        await check(permits[0])


async def test_predispatch_rejects_rebind_dns_drift(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permits = await r.mint_dns_connect_bind_permits(_HOST)
    check = make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=_classifier(),
        dns_answers={_HOST: {"198.51.100.99"}},  # answer changed
    )
    with pytest.raises(PermitError):
        await check(permits[0])
