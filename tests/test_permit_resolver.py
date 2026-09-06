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
    AuthorizationSnapshot,
    AuthorizedCidr,
    AuthorizedTarget,
)
from recon.models.enums import ScopeStatus
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.net.permit import PermitError, PermitRevokedError, is_genuine_permit
from recon.orchestrator.permit_resolver import (
    ActivePermitResolver,
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
    # Q1: the snapshot records the checkpoint-acknowledged address space so D0
    # can verify a resolved IP is inside it, not merely resolved from the name.
    cidr = AuthorizedCidr(
        snapshot_id=snap.id,
        cidr="203.0.113.0/24",
        ip_version=4,
        address_count=256,
        source="roe_cidr",
    )
    session.add(cidr)
    await session.flush()

    return {
        "user_id": user.id,
        "run_id": run.id,
        "smr_id": smr.id,
        "snapshot_id": snap.id,
        "target_id": target.id,
        "cidr_id": cidr.id,
    }


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


async def test_answer_outside_authorized_cidr_mints_nothing(engagement_id) -> None:
    # exact authorized hostname, but a poisoned answer pointing at an IP inside
    # no checkpoint-acknowledged CIDR (Q1).
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {"198.51.100.9"}})
        with pytest.raises(PermitError, match="Q1"):
            await r.mint_dns_connect_bind_permits(_HOST)


async def test_cidr_discovery_is_disabled(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        with pytest.raises(PermitError):
            await r.resolve_authorized_cidrs()
        with pytest.raises(PermitError):
            await r.mint_discovery_permits()


async def test_no_portscan_minter_in_g2() -> None:
    # port scanning is out of the G2 active surface (S2); the minter is gone,
    # not dormant - there is nothing to forge a LivenessAttestation against.
    assert not hasattr(ActivePermitResolver, "mint_portscan_permit")


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
    with pytest.raises(PermitRevokedError) as exc_info:
        await check(permits[0])
    assert exc_info.value.reason == "revoked"


async def test_predispatch_rejects_supersession(engagement_id) -> None:
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        r = _resolver(session, ids, dns_answers={_HOST: {_IP}})
        permits = await r.mint_dns_connect_bind_permits(_HOST)

    async with session_scope() as session:
        other = await _seed(session, engagement_id)
        snap = await session.get(AuthorizationSnapshot, ids["snapshot_id"])
        snap.superseded_by_id = other["snapshot_id"]

    check = make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=_classifier(),
        dns_answers={_HOST: {_IP}},
    )
    with pytest.raises(PermitRevokedError) as exc_info:
        await check(permits[0])
    assert exc_info.value.reason == "superseded"


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


async def test_predispatch_rejects_ip_outside_authorized_cidr(engagement_id) -> None:
    # a permit whose destination is a *current* DNS answer for the authorized
    # hostname (rebind check passes) but is inside no checkpoint-acknowledged
    # CIDR: the Q1 re-check at dispatch time still blocks it.
    from recon.net.permit import mint_permit

    poisoned_ip = "198.51.100.9"
    async with session_scope() as session:
        ids = await _seed(session, engagement_id)
        snap = await session.get(AuthorizationSnapshot, ids["snapshot_id"])
        forged = mint_permit(
            destination_ip=poisoned_ip,
            operation="dns_connect_bind",
            method_profile_id="dns_connect_bind_v1",
            effective_argv_shape=(),
            scan_run_id=ids["run_id"],
            scan_module_run_id=ids["smr_id"],
            module_name="dns",
            authorization_snapshot_id=snap.id,
            authorized_cidr_id=None,
            authorized_target_id=ids["target_id"],
            parent_authorized_cidr=None,
            source_hostname=_HOST,
            checkpoint_ack_hash=snap.checkpoint_ack_hash,
            policy_version=snap.policy_version,
            liveness_attestation_id=None,
        )
    check = make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=_classifier(),
        dns_answers={_HOST: {poisoned_ip}},
    )
    with pytest.raises(PermitError, match="Q1"):
        await check(forged)
