"""Authorized retention / redaction workflow for active-scan audit evidence
(P0-1 / B2).

Default path: there is **no** delete path. Every forensic FK in
``recon/models/authz.py`` is ``ondelete="RESTRICT"``, so a plain engagement
delete raises while any ``AuthorizationSnapshot`` / manifest / audit / attestation
row exists (``EngagementService.purge`` guards against this and points here).

``purge_engagement`` is the one authorized removal path. Ordering guarantees:

1. Refuse if any scan run for the engagement is live.
2. Serialise every forensic row to a canonical JSON bundle.
3. Write + ``fsync`` + read-back-verify the bundle into the engagement-independent
   retention namespace (``RetentionArtifactStore``). Nothing destructive has
   happened yet - a write/verify failure just raises.
4. Insert the ``RetentionArtifact`` row and the append-only
   ``AuditRetentionExport`` row (with the bundle's id + SHA, composite-FK bound).
5. Only now delete the forensic rows children-first, then the engagement.

A filesystem write and a DB transaction cannot be one literal atomic unit. The
invariant is instead: **the verified bundle blob is durable before the export
row, and the export row exists before any forensic row is deleted** - all DB work
in step 4-5 is one transaction the caller commits. If the caller's transaction
rolls back after step 3, the only residue is an orphan blob with no export row;
``RetentionArtifactStore.sweep_orphans`` (bounded, SHA-keyed) reclaims those.
"""

from __future__ import annotations

import json
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.artifacts.retention_store import RetentionArtifactError, RetentionArtifactStore
from recon.models.authz import (
    AddressAudit,
    AuditRetentionExport,
    AuthorizationAmendment,
    AuthorizationSnapshot,
    AuthorizedCidr,
    AuthorizedTarget,
    CandidateManifest,
    CandidateManifestEntry,
    LivenessAttestation,
)
from recon.models.base import utcnow
from recon.models.enums import ScanRunStatus
from recon.models.scanrun import ScanRun

logger = logging.getLogger("recon.retention")

# scan-run states that mean "work may still be dispatched" - refuse to purge.
_LIVE_RUN_STATES = {
    ScanRunStatus.RUNNING,
    ScanRunStatus.PAUSED,
    ScanRunStatus.AWAITING_CHECKPOINT,
}


class RetentionError(RuntimeError):
    """A retention purge could not be completed."""


class RetentionRequiredError(RetentionError):
    """A plain engagement delete was attempted while active-scan forensic
    evidence exists. Use ``purge_engagement`` (which exports first)."""


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


async def engagement_has_active_scan_evidence(
    session: AsyncSession, engagement_id: str
) -> bool:
    row = (
        await session.execute(
            select(AuthorizationSnapshot.id)
            .where(AuthorizationSnapshot.engagement_id == engagement_id)
            .limit(1)
        )
    ).first()
    return row is not None


def _bundle_dict(
    engagement_id: str,
    *,
    reason: str,
    actor_user_id: str,
    snapshots: list[AuthorizationSnapshot],
    cidrs: list[AuthorizedCidr],
    targets: list[AuthorizedTarget],
    amendments: list[AuthorizationAmendment],
    manifests: list[CandidateManifest],
    entries: list[CandidateManifestEntry],
    audits: list[AddressAudit],
    attestations: list[LivenessAttestation],
) -> dict:
    """Everything Security's B2 review requires preserved: every manifest hash,
    the snapshot->CIDR/target authorization binding, the terminal outcome per
    address, and the deletion actor + time."""
    return {
        "schema": "recon.audit_retention_bundle.v1",
        "engagement_id": engagement_id,
        "exported_by_user_id": actor_user_id,
        "exported_at": utcnow().isoformat(),
        "reason": reason,
        "authorization_snapshots": sorted(
            (
                {
                    "id": s.id,
                    "scan_run_id": s.scan_run_id,
                    "engagement_id": s.engagement_id,
                    "roe_config_hash": s.roe_config_hash,
                    "scope_policy_hash": s.scope_policy_hash,
                    "authorized_by_user_id": s.authorized_by_user_id,
                    "authorized_at": s.authorized_at.isoformat(),
                    "checkpoint_ack_hash": s.checkpoint_ack_hash,
                    "flow": s.flow,
                    "policy_version": s.policy_version,
                    "revoked_at": s.revoked_at.isoformat() if s.revoked_at else None,
                    "revoked_by_user_id": s.revoked_by_user_id,
                    "revoked_reason": s.revoked_reason,
                    "superseded_by_id": s.superseded_by_id,
                }
                for s in snapshots
            ),
            key=lambda d: d["id"],
        ),
        "authorized_cidrs": sorted(
            (
                {
                    "id": c.id,
                    "snapshot_id": c.snapshot_id,
                    "cidr": c.cidr,
                    "ip_version": c.ip_version,
                    "address_count": c.address_count,
                    "source": c.source,
                    "amendment_id": c.amendment_id,
                }
                for c in cidrs
            ),
            key=lambda d: d["id"],
        ),
        "authorized_targets": sorted(
            (
                {
                    "id": t.id,
                    "snapshot_id": t.snapshot_id,
                    "target_type": t.target_type,
                    "value": t.value,
                    "source": t.source,
                    "amendment_id": t.amendment_id,
                }
                for t in targets
            ),
            key=lambda d: d["id"],
        ),
        "authorization_amendments": sorted(
            (
                {
                    "id": a.id,
                    "scan_run_id": a.scan_run_id,
                    "engagement_id": a.engagement_id,
                    "exact_targets": a.exact_targets,
                    "justification": a.justification,
                    "authorized_by_user_id": a.authorized_by_user_id,
                    "authorized_at": a.authorized_at.isoformat(),
                    "checkpoint_ack_hash": a.checkpoint_ack_hash,
                    "revoked_at": a.revoked_at.isoformat() if a.revoked_at else None,
                }
                for a in amendments
            ),
            key=lambda d: d["id"],
        ),
        "candidate_manifests": sorted(
            (
                {
                    "id": m.id,
                    "scan_run_id": m.scan_run_id,
                    "scan_module_run_id": m.scan_module_run_id,
                    "authorization_snapshot_id": m.authorization_snapshot_id,
                    "manifest_hash": m.manifest_hash,
                    "total_addresses": m.total_addresses,
                    "probeable_addresses": m.probeable_addresses,
                    "excluded_addresses": m.excluded_addresses,
                    "policy_version": m.policy_version,
                    "method_profile_id": m.method_profile_id,
                }
                for m in manifests
            ),
            key=lambda d: d["id"],
        ),
        "candidate_manifest_entries": sorted(
            (
                {
                    "id": e.id,
                    "manifest_id": e.manifest_id,
                    "authorization_snapshot_id": e.authorization_snapshot_id,
                    "candidate_ip": e.candidate_ip,
                    "authorized_cidr_id": e.authorized_cidr_id,
                    "parent_authorized_cidr": e.parent_authorized_cidr,
                    "excluded": e.excluded,
                    "exclusion_reason": e.exclusion_reason,
                }
                for e in entries
            ),
            key=lambda d: d["id"],
        ),
        "address_audits": sorted(
            (
                {
                    "id": a.id,
                    "manifest_id": a.manifest_id,
                    "manifest_entry_id": a.manifest_entry_id,
                    "scan_run_id": a.scan_run_id,
                    "engagement_id": a.engagement_id,
                    "candidate_ip": a.candidate_ip,
                    "authorization_snapshot_id": a.authorization_snapshot_id,
                    "authorized_cidr_id": a.authorized_cidr_id,
                    "authorized_target_id": a.authorized_target_id,
                    "parent_authorized_cidr": a.parent_authorized_cidr,
                    "source_hostname": a.source_hostname,
                    "permit_id": a.permit_id,
                    "method_profile_id": a.method_profile_id,
                    "started_at": a.started_at.isoformat() if a.started_at else None,
                    "ended_at": a.ended_at.isoformat() if a.ended_at else None,
                    "outcome": a.outcome.value if hasattr(a.outcome, "value") else a.outcome,
                    "liveness_attestation_id": a.liveness_attestation_id,
                    "detail": a.detail,
                    "idempotency_key": a.idempotency_key,
                }
                for a in audits
            ),
            key=lambda d: d["id"],
        ),
        "liveness_attestations": sorted(
            (
                {
                    "id": la.id,
                    "scan_run_id": la.scan_run_id,
                    "engagement_id": la.engagement_id,
                    "evidence_id": la.evidence_id,
                    "content_hash": la.content_hash,
                    "method_profile_id": la.method_profile_id,
                    "observed_at": la.observed_at.isoformat(),
                    "observed_ip": la.observed_ip,
                    "emitting_module": la.emitting_module,
                    "authorization_snapshot_id": la.authorization_snapshot_id,
                    "authorized_cidr_id": la.authorized_cidr_id,
                    "authorized_target_id": la.authorized_target_id,
                    "parent_authorized_cidr": la.parent_authorized_cidr,
                    "source_hostname": la.source_hostname,
                }
                for la in attestations
            ),
            key=lambda d: d["id"],
        ),
    }


async def purge_engagement(
    session: AsyncSession,
    engagement_id: str,
    *,
    actor_user_id: str,
    reason: str,
    store: RetentionArtifactStore | None = None,
) -> AuditRetentionExport | None:
    """Delete an engagement and all its data. If the engagement carries no
    active-scan forensic evidence this is a plain cascade delete and returns
    ``None``. Otherwise it exports a verified retention bundle first and returns
    the ``AuditRetentionExport``.

    The caller owns the transaction: this coroutine only ``flush``es. Commit on
    success; on any exception, roll back (an orphan bundle blob is harmless and
    reclaimed by ``RetentionArtifactStore.sweep_orphans``).
    """
    if not reason or not reason.strip():
        raise RetentionError("a retention purge requires a non-empty reason")

    live = (
        await session.execute(
            select(ScanRun.id).where(
                ScanRun.engagement_id == engagement_id,
                ScanRun.status.in_(_LIVE_RUN_STATES),
            )
        )
    ).first()
    if live is not None:
        raise RetentionError(
            f"engagement {engagement_id} has a live scan run ({live[0]}); "
            "stop or complete it before purging"
        )

    snapshots = list(
        (
            await session.execute(
                select(AuthorizationSnapshot).where(
                    AuthorizationSnapshot.engagement_id == engagement_id
                )
            )
        )
        .scalars()
        .all()
    )

    if not snapshots:
        await _delete_engagement(session, engagement_id)
        await session.flush()
        return None

    snapshot_ids = [s.id for s in snapshots]

    cidrs = list(
        (await session.execute(select(AuthorizedCidr).where(AuthorizedCidr.snapshot_id.in_(snapshot_ids)))).scalars().all()
    )
    targets = list(
        (await session.execute(select(AuthorizedTarget).where(AuthorizedTarget.snapshot_id.in_(snapshot_ids)))).scalars().all()
    )
    amendments = list(
        (await session.execute(select(AuthorizationAmendment).where(AuthorizationAmendment.engagement_id == engagement_id))).scalars().all()
    )
    manifests = list(
        (await session.execute(select(CandidateManifest).where(CandidateManifest.authorization_snapshot_id.in_(snapshot_ids)))).scalars().all()
    )
    manifest_ids = [m.id for m in manifests]
    entries = list(
        (await session.execute(select(CandidateManifestEntry).where(CandidateManifestEntry.manifest_id.in_(manifest_ids)))).scalars().all()
        if manifest_ids
        else []
    )
    audits = list(
        (await session.execute(select(AddressAudit).where(AddressAudit.authorization_snapshot_id.in_(snapshot_ids)))).scalars().all()
    )
    attestations = list(
        (await session.execute(select(LivenessAttestation).where(LivenessAttestation.authorization_snapshot_id.in_(snapshot_ids)))).scalars().all()
    )

    bundle = _bundle_dict(
        engagement_id,
        reason=reason,
        actor_user_id=actor_user_id,
        snapshots=snapshots,
        cidrs=cidrs,
        targets=targets,
        amendments=amendments,
        manifests=manifests,
        entries=entries,
        audits=audits,
        attestations=attestations,
    )
    data = _canonical(bundle)

    store = store or RetentionArtifactStore()
    try:
        retention_artifact = store.store_bytes(data)
        # Explicit second read-back-verify from disk before any destructive work.
        store.open_bytes(retention_artifact)
    except RetentionArtifactError as exc:
        raise RetentionError(f"retention bundle could not be secured: {exc}") from exc

    session.add(retention_artifact)
    await session.flush()

    export = AuditRetentionExport(
        engagement_id=engagement_id,
        exported_by_user_id=actor_user_id,
        exported_at=utcnow(),
        reason=reason,
        bundle_artifact_id=retention_artifact.id,
        bundle_artifact_sha256=retention_artifact.sha256,
        snapshot_count=len(snapshots),
        manifest_count=len(manifests),
        address_audit_count=len(audits),
        attestation_count=len(attestations),
        manifest_hashes=sorted(m.manifest_hash for m in manifests),
    )
    session.add(export)
    await session.flush()

    # Children-first, one flush per level, so every RESTRICT FK (including the
    # composite manifest-chain FKs the unit-of-work sort does not model) is
    # satisfied at each step.
    async def _delete_all(rows) -> None:
        for row in rows:
            await session.delete(row)
        await session.flush()

    await _delete_all(audits)
    await _delete_all(entries)
    await _delete_all(attestations)
    await _delete_all(manifests)
    await _delete_all(cidrs)
    await _delete_all(targets)
    await _delete_all(amendments)
    # Break the snapshot self-FK before deleting the snapshot rows.
    for snapshot in snapshots:
        snapshot.superseded_by_id = None
    await session.flush()
    await _delete_all(snapshots)

    await _delete_engagement(session, engagement_id)
    await session.flush()

    logger.info(
        "purged engagement %s with retention export %s (bundle %s, %d audit rows)",
        engagement_id,
        export.id,
        retention_artifact.sha256,
        len(audits),
    )
    return export


async def _delete_engagement(session: AsyncSession, engagement_id: str) -> None:
    """Detach operator active-engagement pointers, then delete the engagement
    (the remaining non-forensic children cascade at the DB level)."""
    from recon.orchestrator.engagements import EngagementNotFound, EngagementService

    try:
        await EngagementService()._delete_engagement_row(session, engagement_id)
    except EngagementNotFound:
        # already gone - nothing to do
        return
