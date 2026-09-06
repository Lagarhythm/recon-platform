"""D0 - ``dns_connect_bind_v1`` connect-time liveness binding (P0-1 / G0 Section 2.3).

Runs once, after the passive ``dns`` module and before the active modules, for a
run that passed the active checkpoint. For every exact in-scope hostname that
this run's DNS actually resolved:

1. the resolver mints one connect-bind permit per distinct resolved IP;
2. the executor makes one rate-limited TCP connect to the single policy port and
   verifies ``getpeername()`` == the permitted IP (rebind / redirect defence);
3. a completed connect writes hashed ``live_host`` Evidence + a
   :class:`~recon.models.authz.LivenessAttestation` + an ``AddressAudit(live)``;
   a miss writes ``AddressAudit(no_response|error|excluded)`` and no attestation.

``port_scan`` then draws its permit from each attestation via
``mint_portscan_permit``. Plain DNS evidence never becomes attested liveness.

CIDR discovery is not handled here - it is disabled in ``BOOTSTRAP_POLICY``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.active_policy import active_policy
from recon.core.dns_answers import run_dns_answers
from recon.core.scope import ScopeManager
from recon.db import session_scope
from recon.models.authz import (
    DNS_CONNECT_BIND_V1,
    AddressAudit,
    AuthorizationSnapshot,
    AuthorizedTarget,
    LivenessAttestation,
)
from recon.models.base import utcnow
from recon.models.enums import AddressOutcome
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.net.active_executor import ActiveExecutor
from recon.net.permit import PermitError
from recon.net.rate_limit import RateLimiter
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.permit_resolver import (
    ActivePermitResolver,
    canonical_probe_hash,
    make_predispatch_check,
)

logger = logging.getLogger("recon.d0")

_OUTCOME_BY_PROBE: dict[str, AddressOutcome] = {
    "completed": AddressOutcome.LIVE,
    "refused": AddressOutcome.NO_RESPONSE,
    "timeout": AddressOutcome.NO_RESPONSE,
    "no_response": AddressOutcome.NO_RESPONSE,
    "error": AddressOutcome.ERROR,
}


@dataclass
class D0Result:
    attestation_ids: list[str] = field(default_factory=list)
    audit_ids: list[str] = field(default_factory=list)
    hostnames_considered: int = 0
    permits_minted: int = 0
    skipped_unauthorized: list[str] = field(default_factory=list)


async def run_d0_connect_bind(
    session: AsyncSession,
    *,
    run: ScanRun,
    snapshot: AuthorizationSnapshot,
    scope: ScopeManager,
    rate_limiter: RateLimiter,
    is_cancelled,
    executor: ActiveExecutor | None = None,
) -> D0Result:
    """Execute D0 for ``run`` under ``snapshot``. The caller owns the transaction."""
    policy = active_policy(snapshot.policy_version)
    result = D0Result()

    if not policy.allows_method(DNS_CONNECT_BIND_V1):
        logger.warning("D0 method not allowlisted in policy %s; nothing to do", policy.version)
        return result

    dns_answers = await run_dns_answers(session, run.id)

    targets = (
        await session.execute(
            select(AuthorizedTarget).where(
                AuthorizedTarget.snapshot_id == snapshot.id,
                AuthorizedTarget.target_type == "hostname",
            )
        )
    ).scalars().all()
    if not targets:
        return result

    smr_id = (
        await session.execute(
            select(ScanModuleRun.id).where(
                ScanModuleRun.scan_run_id == run.id,
                ScanModuleRun.module_name == "dns",
            )
        )
    ).scalar_one_or_none()

    resolver = ActivePermitResolver(
        session,
        scan_run_id=run.id,
        scan_module_run_id=smr_id or run.id,
        module_name="dns",
        snapshot_id=snapshot.id,
        policy=policy,
        scope_classifier=scope.classify,
        dns_answers=dns_answers,
    )
    predispatch = make_predispatch_check(
        session_scope,
        policy=policy,
        scope_classifier=scope.classify,
        dns_answers=dns_answers,
    )
    executor = executor or ActiveExecutor(
        rate_limiter=rate_limiter,
        kill_switch=kill_switch,
        is_cancelled=is_cancelled,
        predispatch_check=predispatch,
    )

    deadline = time.monotonic() + policy.total_time_budget_seconds
    seen_ips: set[str] = set()

    for target in targets:
        result.hostnames_considered += 1
        try:
            permits = await resolver.mint_dns_connect_bind_permits(target.value)
        except PermitError as exc:
            # not an exactly-authorized answer / no DNS answer this run / every
            # answer excluded -> no binding step, dns_record Evidence only.
            result.skipped_unauthorized.append(target.value)
            logger.info("D0 skip %s: %s", target.value, exc)
            continue

        for permit in permits:
            if permit.destination_ip in seen_ips:
                continue
            if len(seen_ips) >= policy.max_addresses_per_run:
                logger.warning("D0 hit max_addresses_per_run=%d", policy.max_addresses_per_run)
                break
            if time.monotonic() >= deadline or is_cancelled():
                await _write_audit(
                    session, run, snapshot, target, permit.destination_ip,
                    AddressOutcome.CANCELLED, permit_id=permit.permit_id,
                )
                result.audit_ids.append("cancelled")
                continue
            seen_ips.add(permit.destination_ip)
            result.permits_minted += 1
            await _probe_one(session, run, snapshot, target, permit, executor, result)

    return result


async def _probe_one(session, run, snapshot, target, permit, executor, result) -> None:
    started = utcnow()
    try:
        probe = await executor.run(permit)
    except PermitError as exc:
        # dispatch-time rejection (rebind, revoked, out of scope, kill switch).
        outcome = (
            AddressOutcome.CANCELLED
            if kill_switch.is_engaged
            else AddressOutcome.EXCLUDED
        )
        audit = await _write_audit(
            session, run, snapshot, target, permit.destination_ip, outcome,
            permit_id=permit.permit_id, started_at=started, detail=str(exc)[:500],
        )
        result.audit_ids.append(audit.id)
        return

    outcome = _OUTCOME_BY_PROBE.get(probe.outcome, AddressOutcome.ERROR)
    attestation_id = None
    if outcome is AddressOutcome.LIVE:
        attestation_id = await _attest(session, run, snapshot, target, permit, probe)
        result.attestation_ids.append(attestation_id)

    audit = await _write_audit(
        session, run, snapshot, target, permit.destination_ip, outcome,
        permit_id=permit.permit_id, started_at=started, ended_at=probe.ended_at,
        liveness_attestation_id=attestation_id, detail=probe.detail[:500],
    )
    result.audit_ids.append(audit.id)


async def _attest(session, run, snapshot, target, permit, probe) -> str:
    record = {
        "schema": "recon.d0_probe.v1",
        "hostname": target.value,
        "observed_ip": permit.destination_ip,
        "peer_ip": probe.peer_ip,
        "method_profile_id": DNS_CONNECT_BIND_V1,
        "detail": probe.detail,
    }
    # content_hash is over EXACTLY the persisted Evidence.raw_data, so the
    # permit resolver can prove the attestation refers to unmodified evidence.
    content_hash = canonical_probe_hash(record)
    ev = Evidence(
        engagement_id=run.engagement_id,
        scan_run_id=run.id,
        source_module="dns",
        subject_type="live_host",
        subject_value=permit.destination_ip,
        raw_data=record,
        summary=f"{target.value} bound live at {permit.destination_ip} (dns_connect_bind_v1)",
    )
    session.add(ev)
    await session.flush()

    att = LivenessAttestation(
        scan_run_id=run.id,
        engagement_id=run.engagement_id,
        evidence_id=ev.id,
        content_hash=content_hash,
        method_profile_id=DNS_CONNECT_BIND_V1,
        observed_at=utcnow(),
        observed_ip=permit.destination_ip,
        emitting_module="dns",
        authorization_snapshot_id=snapshot.id,
        authorized_target_id=target.id,
        source_hostname=target.value,
    )
    session.add(att)
    await session.flush()
    ev.liveness_attestation_id = att.id
    await session.flush()
    return att.id


async def _write_audit(
    session, run, snapshot, target, candidate_ip, outcome, *,
    permit_id=None, started_at=None, ended_at=None,
    liveness_attestation_id=None, detail=None,
) -> AddressAudit:
    audit = AddressAudit(
        scan_run_id=run.id,
        engagement_id=run.engagement_id,
        candidate_ip=candidate_ip,
        authorization_snapshot_id=snapshot.id,
        authorized_target_id=target.id,
        source_hostname=target.value,
        method_profile_id=DNS_CONNECT_BIND_V1,
        permit_id=permit_id,
        started_at=started_at,
        ended_at=ended_at,
        outcome=outcome,
        liveness_attestation_id=liveness_attestation_id,
        detail=detail,
        idempotency_key=f"{snapshot.id}:{target.id}:{candidate_ip}",
    )
    session.add(audit)
    await session.flush()
    return audit
