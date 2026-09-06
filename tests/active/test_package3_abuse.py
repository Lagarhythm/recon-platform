"""Package 3 abuse & acceptance suite, re-pointed at the *implemented* FK-backed
active-scan boundary (P0-1 / G2 phase 5).

Each ``test_abuse_N`` maps to requirement N of
``PLANS/RECON_P0_PACKAGE3_SECURITY_GATE.md`` §"Required abuse and acceptance
tests" (== the nine tests in ``RECON_P0_P01_REVISED_TARGET_CONTRACT.md``). The
CIDR-discovery requirements (4, parts of 5, 7's raw-capability path) are verified
as *disabled* - ``BOOTSTRAP_POLICY.method_allowlist == {dns_connect_bind_v1}``
and every CIDR entry point raises - because CIDR discovery is not enabled in
P0-1. Full ``/24`` reconciliation is a G3 acceptance test.

Invariant across every negative case: ``boundary.network_calls == []``.
"""

from __future__ import annotations

import inspect
import uuid

import pytest
from sqlalchemy import select

from recon.core import active_policy as active_policy_mod
from recon.core.active_policy import BOOTSTRAP_POLICY, ActiveScanPolicy
from recon.core.scope import ScopeManager
from recon.db import session_scope
from recon.models.authz import (
    DNS_CONNECT_BIND_V1,
    AddressAudit,
    AuthorizationSnapshot,
    AuthorizedCidr,
    AuthorizedTarget,
    LivenessAttestation,
)
from recon.models.enums import AddressOutcome, SkipReason
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanRun
from recon.net.active_executor import ActiveExecutor
from recon.net.permit import ActiveTargetPermit, PermitError, is_genuine_permit, mint_permit
from recon.orchestrator.authorization import create_active_snapshot
from recon.orchestrator.permit_resolver import (
    canonical_probe_hash,
    make_predispatch_check,
)
from tests.active.conftest import (
    HOST,
    HOST_IP,
    TS,
    RecordingBoundary,
    add_dns_answer,
    drive_d0,
    make_resolver,
    roe_for,
    seed_active_run,
)

# asyncio_mode = "auto" (pyproject) collects the async tests here; the handful of
# synchronous introspection tests stay sync.


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class _RL:
    async def acquire(self) -> None:
        return None


class _KS:
    is_engaged = False


async def _noop_predispatch(_permit) -> None:
    return None


def _bare_executor(**overrides) -> ActiveExecutor:
    kwargs = {
        "rate_limiter": _RL(),
        "kill_switch": _KS(),
        "is_cancelled": lambda: False,
        "predispatch_check": _noop_predispatch,
    }
    kwargs.update(overrides)
    return ActiveExecutor(**kwargs)


async def _seed_snapshot(session, engagement_id: str, *, revoked: bool = False):
    run = await seed_active_run(session, engagement_id)
    await add_dns_answer(session, run, HOST, HOST_IP)
    roe = await roe_for(session, engagement_id)
    snap = await create_active_snapshot(session, run, roe)
    if revoked:
        snap.revoked_at = TS
        await session.flush()
    target = (
        await session.execute(
            select(AuthorizedTarget).where(AuthorizedTarget.snapshot_id == snap.id)
        )
    ).scalar_one()
    return run, snap, target


async def _insert_attestation(session, run, snap, target, *, observed_ip=HOST_IP, **overrides):
    raw = {"schema": "recon.d0_probe.v1", "hostname": target.value, "observed_ip": observed_ip}
    ev = Evidence(
        engagement_id=run.engagement_id,
        scan_run_id=run.id,
        source_module="dns",
        subject_type="live_host",
        subject_value=observed_ip,
        raw_data=raw,
    )
    session.add(ev)
    await session.flush()
    fields = {
        "scan_run_id": run.id,
        "engagement_id": run.engagement_id,
        "evidence_id": ev.id,
        "content_hash": canonical_probe_hash(raw),
        "method_profile_id": DNS_CONNECT_BIND_V1,
        "observed_at": TS,
        "observed_ip": observed_ip,
        "emitting_module": "dns",
        "authorization_snapshot_id": snap.id,
        "authorized_target_id": target.id,
        "source_hostname": target.value,
    }
    fields.update(overrides)
    att = LivenessAttestation(**fields)
    session.add(att)
    await session.flush()
    return att, ev


_BOUNDARY_MODULES = (
    "recon.orchestrator.authorization",
    "recon.orchestrator.permit_resolver",
    "recon.net.active_executor",
    "recon.net.permit",
    "recon.orchestrator.d0",
)


def _boundary_source() -> str:
    import importlib

    return "\n".join(
        inspect.getsource(importlib.import_module(m)) for m in _BOUNDARY_MODULES
    )


# --------------------------------------------------------------------------
# 1. unsafe / out-of-scope inputs never reach a network syscall
# --------------------------------------------------------------------------


async def test_abuse_1_out_of_scope_hostname_never_probed(active_engagement, boundary, monkeypatch):
    # a hostname that is neither an exact in_scope.host nor in the snapshot
    run_id, _snap_id, result = await drive_d0(
        active_engagement,
        answers={"attacker.example.org": {HOST_IP}, "evil.example.com": {HOST_IP}},
        boundary=boundary,
        monkeypatch=monkeypatch,
    )
    assert boundary.network_calls == []
    assert result.attestation_ids == []
    async with session_scope() as s:
        atts = (
            await s.execute(select(LivenessAttestation).where(LivenessAttestation.scan_run_id == run_id))
        ).scalars().all()
    assert atts == []


@pytest.mark.parametrize(
    "bad_answer",
    ["203.0.113.010", "10.0.0.1:8080", "::1%eth0", "http://203.0.113.10", "203.0.113.10/32", "not-an-ip"],
)
async def test_abuse_1_malformed_or_ambiguous_ip_is_not_probed(
    active_engagement, boundary, monkeypatch, bad_answer
):
    _run_id, _snap_id, result = await drive_d0(
        active_engagement,
        answers={HOST: {bad_answer}},
        boundary=boundary,
        monkeypatch=monkeypatch,
    )
    assert boundary.network_calls == []
    assert result.attestation_ids == []


async def test_abuse_1_injected_liveness_evidence_does_not_authorize_a_probe(
    active_engagement, boundary, monkeypatch
):
    # an attacker inserts a fabricated ``live_host`` Evidence row directly. It has
    # no LivenessAttestation, so nothing downstream can turn it into a permit.
    async with session_scope() as session:
        run = await seed_active_run(session, active_engagement)
        session.add(
            Evidence(
                engagement_id=run.engagement_id,
                scan_run_id=run.id,
                source_module="dns",
                subject_type="live_host",
                subject_value="198.51.100.200",
                raw_data={"observed_ip": "198.51.100.200", "forged": True},
            )
        )
        await session.flush()
        roe = await roe_for(session, active_engagement)
        snap = await create_active_snapshot(session, run, roe)
        scope = ScopeManager(roe)
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={}, scope=scope
        )
        atts = (
            await session.execute(select(LivenessAttestation).where(LivenessAttestation.scan_run_id == run.id))
        ).scalars().all()
        assert atts == []
        # no attestation id exists to mint against
        with pytest.raises(PermitError):
            await resolver.mint_portscan_permit(str(uuid.uuid4()), argv_shape=("nmap", "__DESTINATION__"))
    assert boundary.network_calls == []


# --------------------------------------------------------------------------
# 2. boundary bypass fails closed - only a valid opaque permit reaches egress
# --------------------------------------------------------------------------


async def test_abuse_2_executor_rejects_raw_string_and_lookalikes():
    ex = _bare_executor()
    with pytest.raises(PermitError):
        await ex.run("203.0.113.10")
    with pytest.raises(PermitError):
        await ex.run(b"203.0.113.10")
    with pytest.raises(PermitError):
        await ex.run({"destination_ip": "203.0.113.10"})

    class _Lookalike:
        destination_ip = "203.0.113.10"
        operation = "dns_connect_bind"
        dispatch_nonce = "x"
        is_expired = False

    with pytest.raises(PermitError):
        await ex.run(_Lookalike())


def test_abuse_2_permit_is_not_caller_constructible():
    fields = {
        "destination_ip": "203.0.113.10",
        "operation": "dns_connect_bind",
        "method_profile_id": DNS_CONNECT_BIND_V1,
        "effective_argv_shape": (),
        "scan_run_id": "r",
        "scan_module_run_id": "m",
        "module_name": "dns",
        "authorization_snapshot_id": "s",
        "authorized_cidr_id": None,
        "authorized_target_id": "t",
        "parent_authorized_cidr": None,
        "source_hostname": "app.example.com",
        "checkpoint_ack_hash": "a",
        "policy_version": "p1",
        "liveness_attestation_id": None,
    }
    with pytest.raises(PermitError):
        ActiveTargetPermit(**fields)
    # the module-private mint path still works and is the only one
    assert is_genuine_permit(mint_permit(**fields))


def test_abuse_2_executor_exposes_no_target_string_entry_point():
    public = [n for n in dir(ActiveExecutor) if not n.startswith("_")]
    assert public == ["run"], public
    params = [p for p in inspect.signature(ActiveExecutor.run).parameters if p != "self"]
    assert params == ["permit"], params


# --------------------------------------------------------------------------
# 3. a context boolean cannot authorize traffic (FLAGGED needs a recorded
#    amendment - not wired for D0 in P0-1, so the boolean simply has no effect)
# --------------------------------------------------------------------------


async def test_abuse_3_allow_out_of_scope_boolean_does_not_expand_the_active_boundary(
    active_engagement, boundary, monkeypatch
):
    async with session_scope() as session:
        run = await seed_active_run(session, active_engagement)
        run.allow_out_of_scope = True  # attacker / operator sets the legacy flag
        # a FLAGGED subdomain (domains has no wildcard) resolving outside every
        # in-scope CIDR
        await add_dns_answer(session, run, "staging.example.com", "198.51.100.7")
        roe = await roe_for(session, active_engagement)
        snap = await create_active_snapshot(session, run, roe)
        scope = ScopeManager(roe)
        assert scope.classify("staging.example.com", resolved_ips=["198.51.100.7"]).status.value == "flagged"

        targets = (
            await session.execute(select(AuthorizedTarget).where(AuthorizedTarget.snapshot_id == snap.id))
        ).scalars().all()
        # only the EXACT in_scope.host is authorized - never the domain, never a
        # FLAGGED subdomain, never a CIDR
        assert {t.value for t in targets} == {HOST}

        from recon.core.dns_answers import run_dns_answers

        resolver = make_resolver(
            session,
            run_id=run.id,
            snapshot_id=snap.id,
            dns_answers=await run_dns_answers(session, run.id),
            scope=scope,
        )
        with pytest.raises(PermitError):
            await resolver.mint_dns_connect_bind_permits("staging.example.com")
    assert boundary.network_calls == []


def test_abuse_3_no_active_boundary_module_reads_allow_out_of_scope():
    src = _boundary_source()
    for token in ("allow_out_of_scope", "allow_oos"):
        assert token not in src, f"active boundary references {token!r} - a boolean cannot expand scope"


# --------------------------------------------------------------------------
# 4. complete /24 accounting - CIDR discovery is DISABLED for P0-1
# --------------------------------------------------------------------------


async def test_abuse_4_cidr_discovery_entry_points_all_raise(active_engagement, boundary):
    async with session_scope() as session:
        run, snap, _target = await _seed_snapshot(session, active_engagement)
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        with pytest.raises(PermitError):
            await resolver.resolve_authorized_cidrs()
        with pytest.raises(PermitError):
            await resolver.mint_discovery_permits()

        # the checkpoint snapshot never materialises a CIDR authorization row,
        # even though the RoE has an in-scope CIDR
        cidrs = (
            await session.execute(select(AuthorizedCidr).where(AuthorizedCidr.snapshot_id == snap.id))
        ).scalars().all()
        assert cidrs == []
    assert boundary.network_calls == []


# --------------------------------------------------------------------------
# 5. blast-radius limits reject before any traffic
# --------------------------------------------------------------------------


async def test_abuse_5_disallowed_method_cannot_mint(active_engagement, boundary):
    async with session_scope() as session:
        run, snap, target = await _seed_snapshot(session, active_engagement)
        att, _ev = await _insert_attestation(
            session, run, snap, target, method_profile_id="masscan_syn_v1"
        )
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        with pytest.raises(PermitError):
            await resolver.mint_portscan_permit(att.id, argv_shape=("nmap", "__DESTINATION__"))
    assert boundary.network_calls == []


async def test_abuse_5_max_addresses_per_run_is_enforced(active_engagement, boundary, monkeypatch):
    capped = ActiveScanPolicy(
        version="p1",
        method_allowlist=frozenset({DNS_CONNECT_BIND_V1}),
        max_addresses_per_run=1,
        max_aggregate_cidr_addresses=256,
        per_method_rate={DNS_CONNECT_BIND_V1: 2.0},
        per_method_concurrency={DNS_CONNECT_BIND_V1: 2},
        per_method_ports={DNS_CONNECT_BIND_V1: (443,)},
        probe_timeout_seconds=2.0,
        max_retries=0,
        total_time_budget_seconds=30.0,
    )
    monkeypatch.setitem(active_policy_mod._POLICIES, "p1", capped)

    _run_id, _snap_id, _result = await drive_d0(
        active_engagement,
        answers={HOST: {"203.0.113.10", "203.0.113.11", "203.0.113.12"}},
        boundary=boundary,
        monkeypatch=monkeypatch,
    )
    connects = [c for c in boundary.network_calls if c[0] == "connect"]
    assert len(connects) == 1, boundary.network_calls


# --------------------------------------------------------------------------
# 6. forged / stale / passive liveness cannot mint a port-scan permit
# --------------------------------------------------------------------------


async def test_abuse_6_valid_same_run_attestation_mints_exactly_one_permit(active_engagement, boundary):
    async with session_scope() as session:
        run, snap, target = await _seed_snapshot(session, active_engagement)
        att, _ev = await _insert_attestation(session, run, snap, target)
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        permit = await resolver.mint_portscan_permit(att.id, argv_shape=("nmap", "__DESTINATION__"))
    assert permit.operation == "port_scan"
    assert permit.destination_ip == HOST_IP
    assert permit.liveness_attestation_id == att.id
    assert boundary.network_calls == []  # minting is not dispatch


async def test_abuse_6_tampered_evidence_is_rejected(active_engagement, boundary):
    async with session_scope() as session:
        run, snap, target = await _seed_snapshot(session, active_engagement)
        att, ev = await _insert_attestation(session, run, snap, target)
        ev.raw_data = {**ev.raw_data, "tampered": True}
        await session.flush()
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        with pytest.raises(PermitError):
            await resolver.mint_portscan_permit(att.id, argv_shape=("nmap", "__DESTINATION__"))
    assert boundary.network_calls == []


async def test_abuse_6_attestation_from_another_run_is_rejected(active_engagement, boundary):
    async with session_scope() as session:
        run_a, snap_a, target_a = await _seed_snapshot(session, active_engagement)
        att, _ev = await _insert_attestation(session, run_a, snap_a, target_a)
        run_b, snap_b, _target_b = await _seed_snapshot(session, active_engagement)
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver_b = make_resolver(
            session, run_id=run_b.id, snapshot_id=snap_b.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        with pytest.raises(PermitError):
            await resolver_b.mint_portscan_permit(att.id, argv_shape=("nmap", "__DESTINATION__"))
    assert boundary.network_calls == []


async def test_abuse_6_observed_ip_not_in_this_run_dns_is_rejected(active_engagement, boundary):
    async with session_scope() as session:
        run, snap, target = await _seed_snapshot(session, active_engagement)
        att, _ev = await _insert_attestation(session, run, snap, target, observed_ip="203.0.113.55")
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        with pytest.raises(PermitError):
            await resolver.mint_portscan_permit(att.id, argv_shape=("nmap", "__DESTINATION__"))
    assert boundary.network_calls == []


async def test_abuse_6_passive_dns_record_never_becomes_attested_liveness(
    active_engagement, boundary, monkeypatch
):
    # a run whose only "evidence" for the host is a passive A record: D0 attempts
    # the connect-bind, but a miss (refused) yields no attestation, so port_scan
    # has nothing to mint against - a plain DNS answer is never attested liveness.
    boundary.refuse = True
    run_id, _snap_id, result = await drive_d0(
        active_engagement,
        answers={HOST: {HOST_IP}},
        boundary=boundary,
        monkeypatch=monkeypatch,
    )
    assert result.attestation_ids == []
    async with session_scope() as s:
        atts = (
            await s.execute(select(LivenessAttestation).where(LivenessAttestation.scan_run_id == run_id))
        ).scalars().all()
    assert atts == []


# --------------------------------------------------------------------------
# 7. capability failure fails closed - no privilege escalation, no fallback
# --------------------------------------------------------------------------


def test_abuse_7_no_privilege_escalation_in_the_active_boundary():
    src = _boundary_source()
    for token in (
        "SOCK_RAW",
        "IPPROTO_ICMP",
        "setuid",
        "seteuid",
        "setgid",
        "pkexec",
        "CAP_NET_RAW",
        "os.system(",
    ):
        assert token not in src, f"active boundary contains {token!r}"


def test_abuse_7_capability_unavailable_skip_reason_exists():
    assert SkipReason.CAPABILITY_UNAVAILABLE.value == "capability_unavailable"


async def test_abuse_7_capability_method_has_no_implicit_tcp_fallback(active_engagement, boundary):
    async with session_scope() as session:
        run, snap, target = await _seed_snapshot(session, active_engagement)
        # an attestation claiming a raw-capability method - not allowlisted
        att, _ev = await _insert_attestation(session, run, snap, target, method_profile_id="icmp_ping_v1")
        scope = ScopeManager(await roe_for(session, active_engagement))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        with pytest.raises(PermitError):
            await resolver.mint_portscan_permit(att.id, argv_shape=("nmap", "__DESTINATION__"))
    # it does NOT silently fall back to dns_connect_bind_v1
    assert boundary.network_calls == []


# --------------------------------------------------------------------------
# 8. authorization revocation / supersession blocks queued work at dispatch
# --------------------------------------------------------------------------


async def _mint_live_permit(engagement_id):
    """Seed + mint one genuine D0 connect-bind permit; return (permit, snap_id, run_id).

    Committed on exit, so a later session and the executor's fresh-session
    dispatch recheck both see the persisted authorization."""
    async with session_scope() as session:
        run, snap, _target = await _seed_snapshot(session, engagement_id)
        scope = ScopeManager(await roe_for(session, engagement_id))
        resolver = make_resolver(
            session, run_id=run.id, snapshot_id=snap.id, dns_answers={HOST: {HOST_IP}}, scope=scope
        )
        permits = await resolver.mint_dns_connect_bind_permits(HOST)
        return permits[0], snap.id, run.id


async def _real_predispatch(engagement_id):
    async with session_scope() as session:
        scope = ScopeManager(await roe_for(session, engagement_id))
    return make_predispatch_check(
        session_scope,
        policy=BOOTSTRAP_POLICY,
        scope_classifier=scope.classify,
        dns_answers={HOST: {HOST_IP}},
    )


async def test_abuse_8_revocation_between_mint_and_dispatch_blocks_the_syscall(
    active_engagement, boundary, monkeypatch
):
    boundary.install(monkeypatch)
    permit, snap_id, _run_id = await _mint_live_permit(active_engagement)

    async with session_scope() as session:
        snap = await session.get(AuthorizationSnapshot, snap_id)
        snap.revoked_at = TS
        snap.revoked_reason = "operator pulled authorization"

    ex = _bare_executor(
        predispatch_check=await _real_predispatch(active_engagement),
        command_runner=boundary.run_command,
    )
    with pytest.raises(PermitError):
        await ex.run(permit)
    assert boundary.network_calls == []


async def test_abuse_8_supersession_between_mint_and_dispatch_blocks_the_syscall(
    active_engagement, boundary, monkeypatch
):
    boundary.install(monkeypatch)
    permit, snap_id, _run_id = await _mint_live_permit(active_engagement)

    async with session_scope() as session:
        # a second snapshot supersedes the first
        _run2, snap2, _t2 = await _seed_snapshot(session, active_engagement)
        snap = await session.get(AuthorizationSnapshot, snap_id)
        snap.superseded_by_id = snap2.id

    ex = _bare_executor(
        predispatch_check=await _real_predispatch(active_engagement),
        command_runner=boundary.run_command,
    )
    with pytest.raises(PermitError):
        await ex.run(permit)
    assert boundary.network_calls == []


async def test_abuse_8_d0_driver_records_a_terminal_non_success_audit_on_revocation(
    active_engagement, boundary, monkeypatch
):
    """Revocation lands after the permit is minted but at dispatch time: the D0
    driver must persist a terminal non-success ``AddressAudit`` and mint no
    attestation, with zero network egress."""
    boundary.install(monkeypatch)

    class _RevokeAtDispatch:
        def __init__(self, inner: ActiveExecutor) -> None:
            self._inner = inner

        async def run(self, permit):
            # revocation lands (committed) between mint and dispatch
            async with session_scope() as s:
                snap = await s.get(AuthorizationSnapshot, permit.authorization_snapshot_id)
                snap.revoked_at = TS
            return await self._inner.run(permit)

    from recon.core.dns_answers import run_dns_answers
    from recon.net.rate_limit import RateLimiter
    from recon.orchestrator.d0 import run_d0_connect_bind
    from recon.orchestrator.killswitch import kill_switch

    async with session_scope() as session:
        run = await seed_active_run(session, active_engagement)
        await add_dns_answer(session, run, HOST, HOST_IP)
        roe = await roe_for(session, active_engagement)
        snap = await create_active_snapshot(session, run, roe)
        run_id, snap_id = run.id, snap.id

    async with session_scope() as session:
        run = await session.get(ScanRun, run_id)
        snap = await session.get(AuthorizationSnapshot, snap_id)
        roe = await roe_for(session, active_engagement)
        scope = ScopeManager(roe)
        dns_answers = await run_dns_answers(session, run_id)
        predispatch = make_predispatch_check(
            session_scope, policy=BOOTSTRAP_POLICY,
            scope_classifier=scope.classify, dns_answers=dns_answers,
        )
        inner = ActiveExecutor(
            rate_limiter=RateLimiter(100),
            kill_switch=kill_switch,
            is_cancelled=lambda: False,
            predispatch_check=predispatch,
            command_runner=boundary.run_command,
        )
        result = await run_d0_connect_bind(
            session, run=run, snapshot=snap, scope=scope,
            rate_limiter=RateLimiter(100), is_cancelled=lambda: False,
            executor=_RevokeAtDispatch(inner),
        )

    assert result.attestation_ids == []
    assert boundary.network_calls == []
    async with session_scope() as s:
        audits = (
            await s.execute(select(AddressAudit).where(AddressAudit.scan_run_id == run_id))
        ).scalars().all()
    assert len(audits) == 1
    assert audits[0].outcome in {AddressOutcome.EXCLUDED, AddressOutcome.CANCELLED}
    assert audits[0].liveness_attestation_id is None


# --------------------------------------------------------------------------
# 9. interactive and pre-authorized checkpoint flows are equivalent
# --------------------------------------------------------------------------


async def test_abuse_9_interactive_and_pre_authorized_snapshots_are_equivalent(active_engagement):
    async with session_scope() as session:
        run_i = await seed_active_run(session, active_engagement)
        run_p = await seed_active_run(session, active_engagement)
        roe = await roe_for(session, active_engagement)
        snap_i = await create_active_snapshot(session, run_i, roe, flow="interactive")
        snap_p = await create_active_snapshot(session, run_p, roe, flow="pre_authorized")

        targets_i = {
            t.value
            for t in (
                await session.execute(select(AuthorizedTarget).where(AuthorizedTarget.snapshot_id == snap_i.id))
            ).scalars().all()
        }
        targets_p = {
            t.value
            for t in (
                await session.execute(select(AuthorizedTarget).where(AuthorizedTarget.snapshot_id == snap_p.id))
            ).scalars().all()
        }

    assert snap_i.flow == "interactive" and snap_p.flow == "pre_authorized"
    assert snap_i.checkpoint_ack_hash == snap_p.checkpoint_ack_hash
    assert snap_i.scope_policy_hash == snap_p.scope_policy_hash
    assert snap_i.policy_version == snap_p.policy_version
    assert targets_i == targets_p == {HOST}


async def test_abuse_9_both_flows_produce_equivalent_probe_behaviour(active_engagement, monkeypatch):
    b_i = RecordingBoundary()
    _run_i, _snap_i, res_i = await drive_d0(
        active_engagement, answers={HOST: {HOST_IP}}, boundary=b_i, monkeypatch=monkeypatch, flow="interactive"
    )
    b_p = RecordingBoundary()
    _run_p, _snap_p, res_p = await drive_d0(
        active_engagement, answers={HOST: {HOST_IP}}, boundary=b_p, monkeypatch=monkeypatch, flow="pre_authorized"
    )
    assert len(b_i.network_calls) == len(b_p.network_calls) == 1
    assert len(res_i.attestation_ids) == len(res_p.attestation_ids) == 1
