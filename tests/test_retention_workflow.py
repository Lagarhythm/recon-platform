"""P0-1 / B2: RetentionArtifactStore + purge_engagement() and the
filesystem/DB failure-boundary recovery behaviour (Security round-3 G2 condition).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from recon.artifacts.retention_store import (
    RetentionArtifactError,
    RetentionArtifactStore,
)
from recon.config import get_settings
from recon.db import session_scope
from recon.models.authz import (
    AddressAudit,
    AuditRetentionExport,
    AuthorizationSnapshot,
    AuthorizedCidr,
    AuthorizedTarget,
    CandidateManifest,
    CandidateManifestEntry,
    LivenessAttestation,
    RetentionArtifact,
)
from recon.models.engagement import Engagement
from recon.models.enums import AddressOutcome
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.models.user import User
from recon.orchestrator.engagements import EngagementService
from recon.orchestrator.retention import (
    RetentionError,
    RetentionRequiredError,
    purge_engagement,
)

pytestmark = pytest.mark.asyncio

_TS = datetime(2026, 6, 1, tzinfo=UTC)


async def _seed_active_chain(session, engagement_id: str) -> dict:
    """A committed engagement + one active scan run with a full CIDR chain
    (snapshot -> cidr -> manifest -> entry -> audit), one D0 hostname chain
    (target -> attestation -> audit), and the evidence row the attestation
    points at. Returns the ids."""
    user = User(username=f"op-{engagement_id[:8]}", password_hash="x")
    session.add(user)
    await session.flush()

    run = ScanRun(
        engagement_id=engagement_id,
        roe_config_snapshot={},
        roe_config_hash="h",
        modules_requested=[],
        modules_completed=[],
        status="completed",
    )
    session.add(run)
    await session.flush()

    smr = ScanModuleRun(
        scan_run_id=run.id,
        engagement_id=engagement_id,
        module_name="host_discovery",
        phase="active",
        status="completed",
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
        policy_version="p1",
    )
    session.add(snap)
    await session.flush()

    cidr = AuthorizedCidr(
        snapshot_id=snap.id,
        cidr="10.0.0.0/24",
        ip_version=4,
        address_count=256,
        source="roe_cidr",
    )
    target = AuthorizedTarget(
        snapshot_id=snap.id,
        target_type="hostname",
        value="host.example.com",
        source="roe_host",
    )
    session.add_all([cidr, target])
    await session.flush()

    manifest = CandidateManifest(
        scan_run_id=run.id,
        scan_module_run_id=smr.id,
        authorization_snapshot_id=snap.id,
        manifest_hash="mh-" + engagement_id[:8],
        total_addresses=1,
        probeable_addresses=1,
        excluded_addresses=0,
        policy_version="p1",
        method_profile_id="cidr_syn_v1",
    )
    session.add(manifest)
    await session.flush()

    entry = CandidateManifestEntry(
        manifest_id=manifest.id,
        authorization_snapshot_id=snap.id,
        candidate_ip="10.0.0.5",
        authorized_cidr_id=cidr.id,
        parent_authorized_cidr="10.0.0.0/24",
        excluded=False,
    )
    session.add(entry)
    await session.flush()

    evidence = Evidence(
        engagement_id=engagement_id,
        source_module="dns",
        subject_type="live_host",
        subject_value="10.0.0.9",
        raw_data={},
    )
    session.add(evidence)
    await session.flush()

    attestation = LivenessAttestation(
        scan_run_id=run.id,
        engagement_id=engagement_id,
        evidence_id=evidence.id,
        content_hash="ch",
        method_profile_id="dns_connect_bind_v1",
        observed_at=_TS,
        observed_ip="10.0.0.9",
        emitting_module="dns",
        authorization_snapshot_id=snap.id,
        authorized_target_id=target.id,
        source_hostname="host.example.com",
    )
    session.add(attestation)
    await session.flush()

    cidr_audit = AddressAudit(
        manifest_id=manifest.id,
        manifest_entry_id=entry.id,
        scan_run_id=run.id,
        engagement_id=engagement_id,
        candidate_ip="10.0.0.5",
        authorization_snapshot_id=snap.id,
        authorized_cidr_id=cidr.id,
        parent_authorized_cidr="10.0.0.0/24",
        method_profile_id="cidr_syn_v1",
        outcome=AddressOutcome.NO_RESPONSE,
        idempotency_key=f"{manifest.manifest_hash}:10.0.0.5",
    )
    d0_audit = AddressAudit(
        scan_run_id=run.id,
        engagement_id=engagement_id,
        candidate_ip="10.0.0.9",
        authorization_snapshot_id=snap.id,
        authorized_target_id=target.id,
        source_hostname="host.example.com",
        method_profile_id="dns_connect_bind_v1",
        outcome=AddressOutcome.LIVE,
        liveness_attestation_id=attestation.id,
        idempotency_key=f"{snap.id}:{target.id}:10.0.0.9",
    )
    session.add_all([cidr_audit, d0_audit])
    await session.flush()

    return {
        "user_id": user.id,
        "run_id": run.id,
        "snapshot_id": snap.id,
        "manifest_hash": manifest.manifest_hash,
    }


# --------------------------------------------------------------------------- #
# RetentionArtifactStore
# --------------------------------------------------------------------------- #
async def test_store_round_trip_and_namespace(tmp_path):
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")
    data = b'{"k":"v"}'
    art = store.store_bytes(data)
    assert art.sha256 == hashlib.sha256(data).hexdigest()
    assert art.byte_size == len(data)
    assert store.open_bytes(art) == data
    # stored under the retention base, never an engagement path
    resolved = store.absolute_path(art.stored_path)
    assert resolved.parent == (tmp_path / "retention").resolve()
    assert get_settings().artifacts_dir.resolve() not in resolved.parents


async def test_store_rejects_empty_and_traversal(tmp_path):
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")
    with pytest.raises(RetentionArtifactError):
        store.store_bytes(b"")
    with pytest.raises(RetentionArtifactError):
        store.absolute_path("../../etc/passwd")


async def test_open_bytes_detects_missing_and_corruption(tmp_path):
    base = tmp_path / "retention"
    store = RetentionArtifactStore(base_dir=base)
    art = store.store_bytes(b"payload-1")
    (base / art.sha256).unlink()
    with pytest.raises(RetentionArtifactError):
        store.open_bytes(art)
    (base / art.sha256).write_bytes(b"tampered")
    with pytest.raises(RetentionArtifactError):
        store.open_bytes(art)


async def test_sweep_orphans_keeps_known(tmp_path):
    base = tmp_path / "retention"
    store = RetentionArtifactStore(base_dir=base)
    keep = store.store_bytes(b"keep-me")
    orphan = store.store_bytes(b"orphan-me")
    removed = store.sweep_orphans(known_sha256={keep.sha256})
    assert removed == [orphan.sha256]
    assert store.exists(keep.sha256)
    assert not store.exists(orphan.sha256)


# --------------------------------------------------------------------------- #
# purge_engagement - happy paths
# --------------------------------------------------------------------------- #
async def test_purge_without_active_scan_evidence_is_plain_delete(engagement_id):
    async with session_scope() as session:
        export = await purge_engagement(
            session, engagement_id, actor_user_id="sys", reason="client closeout"
        )
        assert export is None
    async with session_scope() as session:
        assert (
            await session.get(Engagement, engagement_id)
        ) is None


async def test_engagement_service_purge_refuses_when_evidence_exists(engagement_id):
    async with session_scope() as session:
        await _seed_active_chain(session, engagement_id)
    async with session_scope() as session:
        with pytest.raises(RetentionRequiredError):
            await EngagementService().purge(session, engagement_id)
    # nothing deleted
    async with session_scope() as session:
        assert await session.get(Engagement, engagement_id) is not None
        assert (
            await session.scalar(select(func.count()).select_from(AddressAudit))
        ) == 2


async def test_purge_with_evidence_exports_then_deletes(engagement_id, tmp_path):
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")
    async with session_scope() as session:
        seeded = await _seed_active_chain(session, engagement_id)

    async with session_scope() as session:
        export = await purge_engagement(
            session,
            engagement_id,
            actor_user_id=seeded["user_id"],
            reason="contractual data destruction",
            store=store,
        )
        assert export is not None
        export_id = export.id
        bundle_sha = export.bundle_artifact_sha256

    async with session_scope() as session:
        # engagement + every forensic row gone
        assert await session.get(Engagement, engagement_id) is None
        for model in (
            AuthorizationSnapshot,
            AuthorizedCidr,
            AuthorizedTarget,
            CandidateManifest,
            CandidateManifestEntry,
            AddressAudit,
            LivenessAttestation,
        ):
            assert (
                await session.scalar(select(func.count()).select_from(model))
            ) == 0, model
        # export row + retention artifact survive, with no engagement FK
        export = await session.get(AuditRetentionExport, export_id)
        assert export is not None
        assert export.engagement_id == engagement_id
        assert export.address_audit_count == 2
        assert export.attestation_count == 1
        assert seeded["manifest_hash"] in export.manifest_hashes
        art = await session.scalar(
            select(RetentionArtifact).where(RetentionArtifact.sha256 == bundle_sha)
        )
        assert art is not None

    # the bundle bytes are still readable by bundle_artifact_id and verify
    data = store.open_bytes(art)
    assert hashlib.sha256(data).hexdigest() == bundle_sha
    bundle = json.loads(data)
    assert bundle["engagement_id"] == engagement_id
    assert bundle["reason"] == "contractual data destruction"
    assert bundle["exported_by_user_id"] == seeded["user_id"]
    assert {a["outcome"] for a in bundle["address_audits"]} == {"no_response", "live"}
    assert bundle["candidate_manifests"][0]["manifest_hash"] == seeded["manifest_hash"]
    assert bundle["liveness_attestations"][0]["source_hostname"] == "host.example.com"


async def test_bundle_survives_even_after_wiping_engagement_dir(engagement_id, tmp_path):
    """The retention blob lives outside artifacts_dir/<engagement_id>/, so
    deleting that tree cannot reach it."""
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")
    async with session_scope() as session:
        seeded = await _seed_active_chain(session, engagement_id)
    async with session_scope() as session:
        export = await purge_engagement(
            session, engagement_id, actor_user_id=seeded["user_id"],
            reason="x", store=store,
        )
        sha = export.bundle_artifact_sha256

    eng_dir = get_settings().artifacts_dir / engagement_id
    import shutil

    shutil.rmtree(eng_dir, ignore_errors=True)
    assert store.exists(sha)
    assert hashlib.sha256(store.open_bytes_by_sha(sha)).hexdigest() == sha


# --------------------------------------------------------------------------- #
# purge_engagement - refusal + failure-boundary recovery
# --------------------------------------------------------------------------- #
async def test_purge_refuses_while_scan_run_is_live(engagement_id):
    async with session_scope() as session:
        await _seed_active_chain(session, engagement_id)
        run = await session.scalar(
            select(ScanRun).where(ScanRun.engagement_id == engagement_id)
        )
        run.status = "running"
    async with session_scope() as session:
        with pytest.raises(RetentionError):
            await purge_engagement(
                session, engagement_id, actor_user_id="sys", reason="x"
            )
    async with session_scope() as session:
        assert await session.get(Engagement, engagement_id) is not None


async def test_purge_requires_reason(engagement_id):
    async with session_scope() as session:
        with pytest.raises(RetentionError):
            await purge_engagement(
                session, engagement_id, actor_user_id="sys", reason="  "
            )


async def test_bundle_write_failure_rolls_back_whole_purge(engagement_id, tmp_path, monkeypatch):
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")

    def _boom(_data, **_kw):
        raise RetentionArtifactError("disk full")

    monkeypatch.setattr(store, "store_bytes", _boom)

    async with session_scope() as session:
        seeded = await _seed_active_chain(session, engagement_id)

    with pytest.raises(RetentionError):
        async with session_scope() as session:
            await purge_engagement(
                session, engagement_id, actor_user_id=seeded["user_id"],
                reason="x", store=store,
            )

    async with session_scope() as session:
        assert await session.get(Engagement, engagement_id) is not None
        assert (
            await session.scalar(select(func.count()).select_from(AddressAudit))
        ) == 2
        assert (
            await session.scalar(select(func.count()).select_from(AuditRetentionExport))
        ) == 0
        assert (
            await session.scalar(select(func.count()).select_from(RetentionArtifact))
        ) == 0


async def test_bundle_verify_failure_rolls_back_whole_purge(engagement_id, tmp_path, monkeypatch):
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")

    def _bad_verify(_artifact):
        raise RetentionArtifactError("readback sha mismatch")

    monkeypatch.setattr(store, "open_bytes", _bad_verify)

    async with session_scope() as session:
        seeded = await _seed_active_chain(session, engagement_id)

    with pytest.raises(RetentionError):
        async with session_scope() as session:
            await purge_engagement(
                session, engagement_id, actor_user_id=seeded["user_id"],
                reason="x", store=store,
            )

    async with session_scope() as session:
        assert await session.get(Engagement, engagement_id) is not None
        assert (
            await session.scalar(select(func.count()).select_from(AuditRetentionExport))
        ) == 0
    # a blob may have been written before the (mocked) verify failed - it is an
    # orphan with no export row and sweep_orphans reclaims it.
    removed = store.sweep_orphans(known_sha256=set())
    assert len(removed) <= 1


async def test_failure_after_export_row_rolls_back_and_orphan_is_sweepable(
    engagement_id, tmp_path, monkeypatch
):
    """Inject a failure during forensic-row deletion (after the export row is
    flushed). The caller's transaction rolls back: engagement + forensic rows +
    export row all revert together; the written bundle blob is the only residue
    and sweep_orphans reclaims it."""
    store = RetentionArtifactStore(base_dir=tmp_path / "retention")
    import recon.orchestrator.retention as retention_mod

    async def _boom(*_a, **_kw):
        raise RuntimeError("crash mid-delete")

    monkeypatch.setattr(retention_mod, "_delete_engagement", _boom)

    async with session_scope() as session:
        seeded = await _seed_active_chain(session, engagement_id)

    with pytest.raises(RuntimeError):
        async with session_scope() as session:
            await purge_engagement(
                session, engagement_id, actor_user_id=seeded["user_id"],
                reason="x", store=store,
            )

    async with session_scope() as session:
        assert await session.get(Engagement, engagement_id) is not None
        assert (
            await session.scalar(select(func.count()).select_from(AddressAudit))
        ) == 2
        assert (
            await session.scalar(select(func.count()).select_from(AuditRetentionExport))
        ) == 0
        known = set(
            await session.scalars(select(RetentionArtifact.sha256))
        )
    removed = store.sweep_orphans(known_sha256=known)
    assert len(removed) == 1
