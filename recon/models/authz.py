"""Active-scan authorization boundary (P0-1 / G0).

Every row here is immutable forensic evidence. Nothing in this module has an
update or delete path except the single ``AuthorizationSnapshot`` /
``AuthorizationAmendment`` ``revoke`` transitions (write-once) and the audited
``purge_engagement`` retention workflow (``recon/orchestrator/retention.py``).

Referential guarantees (Security G0 review, blockers B1 + B2):

* **B1 - authorization is FK-backed, not a free string.** Every CIDR-derived row
  carries a real ``authorized_cidr_id`` FK; every D0 hostname row carries a real
  ``authorized_target_id`` FK; exactly one of the two is set
  (``ck_*_exactly_one_authz_ref``). Composite FKs pin the denormalised value
  (``parent_authorized_cidr`` == ``authorized_cidr.cidr``; ``source_hostname`` ==
  ``authorized_target.value``), the snapshot owner
  (``authorized_*.snapshot_id`` == the row's ``authorization_snapshot_id``) and
  the snapshot's run + engagement. The manifest -> entry -> audit chain is
  FK-locked to one ``(snapshot, run)`` pair.
* **B2 - audit evidence survives deletion.** Every FK toward an engagement /
  run / snapshot / manifest / evidence / artifact is ``ondelete="RESTRICT"``, so
  a plain ``DELETE FROM engagement`` raises while any active-scan row exists. The
  only removal path is ``purge_engagement``, which first writes a verified,
  engagement-independent ``RetentionArtifact`` bundle.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, UUIDPk, utcnow
from recon.models.enums import AddressOutcome, enum_col

# method_profile_id of the only active method approved for P0-1 (Security gate).
DNS_CONNECT_BIND_V1 = "dns_connect_bind_v1"


class AuthorizationSnapshot(UUIDPk, Base):
    """Immutable record of exactly what active scanning was authorized for one
    scan run, captured at active-checkpoint acknowledgement. Append-only: the
    only mutation is a single ``revoke`` that sets ``revoked_*`` once. Never
    cascade-deleted (B2) - removal only via ``purge_engagement`` (retention.py).
    """

    __tablename__ = "authorization_snapshot"
    __table_args__ = (
        # (id, scan_run_id) / (id, engagement_id) are composite-FK targets so a
        # derived attestation/audit/manifest row cannot name a different run's
        # snapshot (B1 round 2/3).
        UniqueConstraint("id", "scan_run_id", name="uq_authz_snapshot_id_run"),
        UniqueConstraint("id", "engagement_id", name="uq_authz_snapshot_id_engagement"),
        Index("ix_authz_snapshot_run", "scan_run_id"),
    )

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="RESTRICT"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="RESTRICT"), nullable=False
    )

    # --- pinned RoE / scope identity ---
    roe_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: sha256 over the canonicalised {in_scope, excluded, authorized_window}
    #: subset only - an unrelated RoE edit does not invalidate an active-scan
    #: authorization mid-run, a scope/exclusion edit does.

    # --- who authorized, when, and what they acknowledged ---
    authorized_by_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    authorized_at: Mapped[datetime] = mapped_column(DateTimeUTC, nullable=False)
    checkpoint_ack_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: sha256 over the exact checkpoint payload shown to the operator (Security
    #: invariant 7): CIDRs, address count, methods, ports, rate/concurrency,
    #: time budget, exclusions, privilege/capability state.
    checkpoint_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    flow: Mapped[str] = mapped_column(String(16), nullable=False)
    #: "interactive" | "pre_authorized" - the two checkpoint paths (abuse test 9).

    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    #: the blast-radius ActiveScanPolicy bundle in force (recon/core/active_policy.py).

    # --- revocation / supersession (write-once) ---
    revoked_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    revoked_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="RESTRICT"), nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    superseded_by_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.superseded_by_id is None


class AuthorizedCidr(UUIDPk, Base):
    """One authorized network within a snapshot. Canonical form only. ``id`` is a
    real FK target for every CIDR-derived manifest / permit / attestation / audit
    row (B1)."""

    __tablename__ = "authorized_cidr"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "cidr", name="uq_authorized_cidr"),
        # (id, cidr): composite-FK target pinning a derived row's denormalised
        # parent_authorized_cidr to THIS row's canonical value (B1).
        UniqueConstraint("id", "cidr", name="uq_authorized_cidr_id_value"),
        # (id, snapshot_id): composite-FK target pinning a derived row's
        # authorization_snapshot_id to THIS row's owning snapshot (B1 round 2).
        UniqueConstraint("id", "snapshot_id", name="uq_authorized_cidr_id_snapshot"),
        Index("ix_authorized_cidr_snapshot", "snapshot_id"),
    )

    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=False,
    )
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)  # canonical
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False)
    address_count: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # "roe_cidr"|"amendment"
    amendment_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("authorization_amendment.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class AuthorizedTarget(UUIDPk, Base):
    """One explicitly-authorized non-CIDR target within a snapshot. Immutable,
    snapshot-owned. For P0-1 the only supported ``target_type`` is ``"hostname"``
    and the only mechanism that consumes it is D0 (dns_connect_bind_v1).
    ``"ip"`` is reserved for an amendment listing an exact single address and is
    not wired in P0-1. Exact ``RoE.in_scope.hosts`` entries only - never a domain
    apex, wildcard, or subdomain (Security "EXACT authorized hostname only")."""

    __tablename__ = "authorized_target"
    __table_args__ = (
        UniqueConstraint(
            "snapshot_id", "target_type", "value", name="uq_authorized_target"
        ),
        # (id, value): composite-FK target pinning an attestation's
        # source_hostname to THIS row's canonical value (B1).
        UniqueConstraint("id", "value", name="uq_authorized_target_id_value"),
        # (id, snapshot_id): snapshot-ownership composite-FK target (B1 round 2).
        UniqueConstraint("id", "snapshot_id", name="uq_authorized_target_id_snapshot"),
        CheckConstraint(
            "target_type IN ('hostname', 'ip')", name="ck_authorized_target_type"
        ),
        Index("ix_authorized_target_snapshot", "snapshot_id"),
    )

    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(253), nullable=False)
    #: hostname: exact, IDNA-normalised, lower-cased, no trailing dot, no wildcard.
    #: ip: single canonical address (reserved).
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # "roe_host"|"amendment"
    amendment_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("authorization_amendment.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class AuthorizationAmendment(UUIDPk, Base):
    """A persisted, per-run authorization to actively touch a specific set of
    targets the RoE scope would otherwise FLAG. Exact targets only - never a
    wildcard, never a boolean. Requires its own checkpoint acknowledgement.
    Materialised into AuthorizedCidr / AuthorizedTarget rows
    (``source='amendment'``) so downstream FK bindings stay uniform. Replaces
    ``ScanRun.allow_out_of_scope`` for the P0-1 active path."""

    __tablename__ = "authorization_amendment"
    __table_args__ = (Index("ix_authz_amendment_run", "scan_run_id"),)

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="RESTRICT"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="RESTRICT"), nullable=False
    )
    roe_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    exact_targets: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    #: list of {"value": "<canonical ip or host>", "target_type": "ip"|"hostname"}
    justification: Mapped[str] = mapped_column(String(512), nullable=False)

    authorized_by_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    authorized_at: Mapped[datetime] = mapped_column(DateTimeUTC, nullable=False)
    checkpoint_ack_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    revoked_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class RetentionArtifact(UUIDPk, Base):
    """Content-addressed blob owned by the retention subsystem - NOT by any
    engagement. Written under a fixed namespace (``settings.retention_dir`` ==
    ``data_dir/retention/``), a sibling of ``artifacts/``, never under
    ``artifacts_dir/<engagement_id>/``, so no engagement delete and no
    ``Artifact`` CASCADE can reach it. Append-only; RESTRICT from
    ``AuditRetentionExport`` (B2)."""

    __tablename__ = "retention_artifact"
    __table_args__ = (
        UniqueConstraint("sha256", name="uq_retention_artifact_sha"),
        # (id, sha256): composite-FK target so an AuditRetentionExport's declared
        # bundle SHA must equal the stored blob's SHA (B2 round 2).
        UniqueConstraint("id", "sha256", name="uq_retention_artifact_id_sha"),
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    stored_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    #: relative to settings.retention_dir; for P0-1 == the bare "<sha256>".
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class LivenessAttestation(UUIDPk, Base):
    """Immutable proof that a specific IP was observed live this run by an
    approved method. The ONLY thing that lets a downstream active permit (port
    scan) be minted for that IP. Passive CT / DNS / historical Assets can never
    produce one. Never cascade-deleted (B2)."""

    __tablename__ = "liveness_attestation"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "observed_ip",
            "method_profile_id",
            name="uq_liveness_run_ip_method",
        ),
        # B1: exactly one authorization reference is set.
        CheckConstraint(
            "(authorized_cidr_id IS NOT NULL) <> (authorized_target_id IS NOT NULL)",
            name="ck_liveness_exactly_one_authz_ref",
        ),
        # B1: a CIDR attestation carries parent_authorized_cidr + NULL
        # source_hostname; a D0 attestation carries source_hostname + NULL cidr.
        CheckConstraint(
            "(authorized_cidr_id IS NULL) OR "
            "(parent_authorized_cidr IS NOT NULL AND source_hostname IS NULL)",
            name="ck_liveness_cidr_shape",
        ),
        CheckConstraint(
            "(authorized_target_id IS NULL) OR "
            "(source_hostname IS NOT NULL AND parent_authorized_cidr IS NULL)",
            name="ck_liveness_target_shape",
        ),
        # B1: value composite FKs - denormalised value == referenced canonical
        # value. MATCH SIMPLE skips a pair whose authorized_*_id leg is NULL.
        ForeignKeyConstraint(
            ["authorized_cidr_id", "parent_authorized_cidr"],
            ["authorized_cidr.id", "authorized_cidr.cidr"],
            name="fk_liveness_cidr_binding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorized_target_id", "source_hostname"],
            ["authorized_target.id", "authorized_target.value"],
            name="fk_liveness_target_binding",
            ondelete="RESTRICT",
        ),
        # B1 round 2: snapshot-ownership + run/engagement composite FKs.
        ForeignKeyConstraint(
            ["authorized_cidr_id", "authorization_snapshot_id"],
            ["authorized_cidr.id", "authorized_cidr.snapshot_id"],
            name="fk_liveness_cidr_snapshot",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorized_target_id", "authorization_snapshot_id"],
            ["authorized_target.id", "authorized_target.snapshot_id"],
            name="fk_liveness_target_snapshot",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorization_snapshot_id", "scan_run_id"],
            ["authorization_snapshot.id", "authorization_snapshot.scan_run_id"],
            name="fk_liveness_snapshot_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorization_snapshot_id", "engagement_id"],
            ["authorization_snapshot.id", "authorization_snapshot.engagement_id"],
            name="fk_liveness_snapshot_engagement",
            ondelete="RESTRICT",
        ),
        Index("ix_liveness_run", "scan_run_id"),
    )

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="RESTRICT"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="RESTRICT"), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: sha256 of the canonical probe-result record (or its artifact).

    method_profile_id: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTimeUTC, nullable=False)
    observed_ip: Mapped[str] = mapped_column(String(64), nullable=False)  # canonical
    emitting_module: Mapped[str] = mapped_column(String(64), nullable=False)

    authorization_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # --- B1: exclusive FK-backed authorization reference ---
    authorized_cidr_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    authorized_target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    parent_authorized_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: set iff authorized_cidr_id set; == authorized_cidr.cidr (composite FK).
    source_hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    #: set iff authorized_target_id set; == authorized_target.value (composite FK).

    outcome: Mapped[str] = mapped_column(String(8), nullable=False, default="live")
    #: only "live" is ever stored - the row's existence IS the attestation.
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class CandidateManifest(UUIDPk, Base):
    """Immutable, content-addressed list of every address discovery will account
    for in one module run. Written and committed BEFORE the first probe. The
    manifest hash is a convenience anchor; the per-address authorization binding
    is the CandidateManifestEntry rows. CIDR-derived only (D0 has no manifest).
    Never cascade-deleted (B2)."""

    __tablename__ = "candidate_manifest"
    __table_args__ = (
        UniqueConstraint("scan_module_run_id", name="uq_manifest_per_module_run"),
        # B1 round 3: manifest-chain header keys - composite-FK targets so an
        # entry / audit row cannot chain to a manifest labelled with a different
        # snapshot or run.
        UniqueConstraint(
            "id", "authorization_snapshot_id", name="uq_manifest_id_snapshot"
        ),
        UniqueConstraint("id", "scan_run_id", name="uq_manifest_id_run"),
        # the manifest's own snapshot must belong to the manifest's own run.
        ForeignKeyConstraint(
            ["authorization_snapshot_id", "scan_run_id"],
            ["authorization_snapshot.id", "authorization_snapshot.scan_run_id"],
            name="fk_manifest_snapshot_run",
            ondelete="RESTRICT",
        ),
        Index("ix_manifest_run", "scan_run_id"),
    )

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="RESTRICT"), nullable=False
    )
    scan_module_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scan_module_run.id", ondelete="RESTRICT"),
        nullable=False,
    )
    authorization_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=False,
    )

    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: sha256 over canonical JSON of the ordered CandidateManifestEntry tuples
    #: + policy_version + snapshot_id.
    artifact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifact.id", ondelete="RESTRICT"), nullable=True
    )

    total_addresses: Mapped[int] = mapped_column(Integer, nullable=False)
    probeable_addresses: Mapped[int] = mapped_column(Integer, nullable=False)
    excluded_addresses: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    method_profile_id: Mapped[str] = mapped_column(String(32), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class CandidateManifestEntry(UUIDPk, Base):
    """One candidate address in a CIDR discovery manifest. Non-null
    ``authorized_cidr_id`` + composite FKs make every address referentially bound
    to exactly one authorization row owned by the manifest's snapshot (B1).
    ``AddressAudit`` references this entry. Immutable; never cascade-deleted."""

    __tablename__ = "candidate_manifest_entry"
    __table_args__ = (
        UniqueConstraint("manifest_id", "candidate_ip", name="uq_manifest_entry_addr"),
        # composite-FK targets for AddressAudit -> entry pinning.
        UniqueConstraint("id", "candidate_ip", name="uq_manifest_entry_id_ip"),
        UniqueConstraint(
            "id", "authorized_cidr_id", name="uq_manifest_entry_id_cidr"
        ),
        UniqueConstraint("id", "manifest_id", name="uq_manifest_entry_id_manifest"),
        # value + snapshot binding to the authorization row (both legs non-null,
        # so both always enforced - no MATCH SIMPLE skip).
        ForeignKeyConstraint(
            ["authorized_cidr_id", "parent_authorized_cidr"],
            ["authorized_cidr.id", "authorized_cidr.cidr"],
            name="fk_manifest_entry_cidr_value",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorized_cidr_id", "authorization_snapshot_id"],
            ["authorized_cidr.id", "authorized_cidr.snapshot_id"],
            name="fk_manifest_entry_cidr_snapshot",
            ondelete="RESTRICT",
        ),
        # B1 round 3: the entry's snapshot must equal its manifest's snapshot.
        ForeignKeyConstraint(
            ["manifest_id", "authorization_snapshot_id"],
            ["candidate_manifest.id", "candidate_manifest.authorization_snapshot_id"],
            name="fk_manifest_entry_manifest_snapshot",
            ondelete="RESTRICT",
        ),
        Index("ix_manifest_entry_manifest", "manifest_id"),
    )

    manifest_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("candidate_manifest.id", ondelete="RESTRICT"),
        nullable=False,
    )
    authorization_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=False,
    )
    candidate_ip: Mapped[str] = mapped_column(String(64), nullable=False)  # canonical
    authorized_cidr_id: Mapped[str] = mapped_column(String(36), nullable=False)
    parent_authorized_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    excluded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    exclusion_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class AddressAudit(UUIDPk, Base):
    """Exactly one terminal disposition per address. For a CIDR run: one per
    (manifest_id, candidate_ip), bound to its CandidateManifestEntry. For D0: one
    per (scan_run_id, candidate_ip, method_profile_id) with manifest_id and
    manifest_entry_id NULL. The UNIQUE constraints are the enforcement: a
    double-probe or double-write is a DB error, not a silent duplicate. Never
    cascade-deleted (B2)."""

    __tablename__ = "address_audit"
    __table_args__ = (
        UniqueConstraint(
            "manifest_id", "candidate_ip", name="uq_address_audit_one_per_manifest_addr"
        ),
        UniqueConstraint(
            "scan_run_id",
            "candidate_ip",
            "method_profile_id",
            name="uq_address_audit_one_per_run_addr",
        ),
        # B1: exactly one authorization reference is set.
        CheckConstraint(
            "(authorized_cidr_id IS NOT NULL) <> (authorized_target_id IS NOT NULL)",
            name="ck_address_audit_exactly_one_authz_ref",
        ),
        # B1: CIDR rows have a manifest + entry + parent_authorized_cidr; D0 rows
        # have a source_hostname and no manifest/entry.
        CheckConstraint(
            "(authorized_cidr_id IS NULL) OR "
            "(manifest_id IS NOT NULL AND manifest_entry_id IS NOT NULL "
            " AND parent_authorized_cidr IS NOT NULL AND source_hostname IS NULL)",
            name="ck_address_audit_cidr_shape",
        ),
        CheckConstraint(
            "(authorized_target_id IS NULL) OR "
            "(manifest_id IS NULL AND manifest_entry_id IS NULL "
            " AND source_hostname IS NOT NULL AND parent_authorized_cidr IS NULL)",
            name="ck_address_audit_target_shape",
        ),
        # B1: value composite FKs.
        ForeignKeyConstraint(
            ["authorized_cidr_id", "parent_authorized_cidr"],
            ["authorized_cidr.id", "authorized_cidr.cidr"],
            name="fk_address_audit_cidr_binding",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorized_target_id", "source_hostname"],
            ["authorized_target.id", "authorized_target.value"],
            name="fk_address_audit_target_binding",
            ondelete="RESTRICT",
        ),
        # B1 round 2: snapshot ownership + run/engagement binding.
        ForeignKeyConstraint(
            ["authorized_cidr_id", "authorization_snapshot_id"],
            ["authorized_cidr.id", "authorized_cidr.snapshot_id"],
            name="fk_address_audit_cidr_snapshot",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorized_target_id", "authorization_snapshot_id"],
            ["authorized_target.id", "authorized_target.snapshot_id"],
            name="fk_address_audit_target_snapshot",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorization_snapshot_id", "scan_run_id"],
            ["authorization_snapshot.id", "authorization_snapshot.scan_run_id"],
            name="fk_address_audit_snapshot_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["authorization_snapshot_id", "engagement_id"],
            ["authorization_snapshot.id", "authorization_snapshot.engagement_id"],
            name="fk_address_audit_snapshot_engagement",
            ondelete="RESTRICT",
        ),
        # B1 round 2: a CIDR audit row's ip + authorization must match its
        # manifest entry (skipped for D0 where manifest_entry_id IS NULL).
        ForeignKeyConstraint(
            ["manifest_entry_id", "candidate_ip"],
            ["candidate_manifest_entry.id", "candidate_manifest_entry.candidate_ip"],
            name="fk_address_audit_entry_ip",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["manifest_entry_id", "authorized_cidr_id"],
            [
                "candidate_manifest_entry.id",
                "candidate_manifest_entry.authorized_cidr_id",
            ],
            name="fk_address_audit_entry_cidr",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["manifest_entry_id", "manifest_id"],
            ["candidate_manifest_entry.id", "candidate_manifest_entry.manifest_id"],
            name="fk_address_audit_entry_manifest",
            ondelete="RESTRICT",
        ),
        # B1 round 3: a CIDR audit row's manifest must carry the same snapshot
        # and run as the audit row itself (skipped for D0 - manifest_id IS NULL).
        ForeignKeyConstraint(
            ["manifest_id", "authorization_snapshot_id"],
            ["candidate_manifest.id", "candidate_manifest.authorization_snapshot_id"],
            name="fk_address_audit_manifest_snapshot",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["manifest_id", "scan_run_id"],
            ["candidate_manifest.id", "candidate_manifest.scan_run_id"],
            name="fk_address_audit_manifest_run",
            ondelete="RESTRICT",
        ),
        Index("ix_address_audit_run", "scan_run_id"),
        Index("ix_address_audit_manifest", "manifest_id"),
    )

    manifest_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("candidate_manifest.id", ondelete="RESTRICT"),
        nullable=True,
    )  # NULL only for a D0 target row
    manifest_entry_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("candidate_manifest_entry.id", ondelete="RESTRICT"),
        nullable=True,
    )  # non-null for a CIDR row, NULL for a D0 target row
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="RESTRICT"), nullable=False
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="RESTRICT"), nullable=False
    )

    candidate_ip: Mapped[str] = mapped_column(String(64), nullable=False)  # canonical
    authorization_snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # --- B1: exclusive FK-backed authorization reference ---
    authorized_cidr_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    authorized_target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    parent_authorized_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)

    permit_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    #: NULL when the address was excluded pre-permit.

    method_profile_id: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)

    outcome: Mapped[AddressOutcome] = mapped_column(
        enum_col(AddressOutcome), nullable=False
    )
    liveness_attestation_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("liveness_attestation.id", ondelete="RESTRICT"),
        nullable=True,
    )
    evidence_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=True
    )
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)  # redacted-safe
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    #: CIDR: f"{manifest_hash}:{candidate_ip}"
    #: D0:   f"{snapshot_id}:{authorized_target_id}:{candidate_ip}"
    #: resume looks this up before re-probing.

    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )


class AuditRetentionExport(UUIDPk, Base):
    """Append-only proof that an engagement's active-scan audit trail was
    exported to an immutable bundle before any forensic row was purged.
    Deliberately has NO FK to engagement / scan_run - it and its bundle outlive
    the deletion. No update or delete path anywhere (mirrors AuditLogEntry)."""

    __tablename__ = "audit_retention_export"
    __table_args__ = (
        # the declared SHA must equal the referenced RetentionArtifact's SHA.
        ForeignKeyConstraint(
            ["bundle_artifact_id", "bundle_artifact_sha256"],
            ["retention_artifact.id", "retention_artifact.sha256"],
            name="fk_retention_export_bundle",
            ondelete="RESTRICT",
        ),
        Index("ix_audit_retention_engagement", "engagement_id"),
    )

    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False)  # plain, no FK
    exported_by_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    exported_at: Mapped[datetime] = mapped_column(DateTimeUTC, nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)

    bundle_artifact_id: Mapped[str] = mapped_column(String(36), nullable=False)
    #: non-null RESTRICT FK -> retention_artifact.id (the bundle blob is
    #: guaranteed to exist and outlive the engagement, B2 round 2).
    bundle_artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: == retention_artifact.sha256 (composite FK).

    snapshot_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_count: Mapped[int] = mapped_column(Integer, nullable=False)
    address_audit_count: Mapped[int] = mapped_column(Integer, nullable=False)
    attestation_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_hashes: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    #: flat list of every preserved manifest_hash - queryable without the blob.

    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )
