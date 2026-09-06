"""active-scan authorization boundary (P0-1 / G0)

snapshot / authorized_cidr / authorized_target / amendment / retention_artifact /
liveness_attestation / candidate_manifest / candidate_manifest_entry /
address_audit / audit_retention_export  (+ evidence.liveness_attestation_id)

Every FK toward an engagement / run / snapshot / manifest / evidence / artifact
is ondelete=RESTRICT (B2): a plain DELETE FROM engagement raises while any
active-scan row exists. Composite FKs pin the denormalised authorization value,
the snapshot owner, and the manifest -> entry -> audit chain to one (snapshot,
run) pair (B1). No write path uses these tables until the G2 resolver wires in.

Revision ID: d4e2a1c7b930
Revises: c1a7e5d2f9b0
Create Date: 2026-09-06
"""

from alembic import op
import sqlalchemy as sa

revision = "d4e2a1c7b930"
down_revision = "c1a7e5d2f9b0"
branch_labels = None
depends_on = None


_ADDRESS_OUTCOME = sa.Enum(
    "live",
    "no_response",
    "excluded",
    "rate_limited",
    "cancelled",
    "error",
    name="addressoutcome",
    native_enum=False,
    create_constraint=False,
    length=32,
)


def upgrade() -> None:
    op.create_table(
        "authorization_snapshot",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_run_id",
            sa.String(36),
            sa.ForeignKey("scan_run.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagement.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("roe_config_hash", sa.String(64), nullable=False),
        sa.Column("scope_policy_hash", sa.String(64), nullable=False),
        sa.Column(
            "authorized_by_user_id",
            sa.String(36),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checkpoint_ack_hash", sa.String(64), nullable=False),
        sa.Column("checkpoint_payload", sa.JSON(), nullable=False),
        sa.Column("flow", sa.String(16), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "revoked_by_user_id",
            sa.String(36),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("revoked_reason", sa.String(512), nullable=True),
        sa.Column(
            "superseded_by_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "scan_run_id", name="uq_authz_snapshot_id_run"),
        sa.UniqueConstraint(
            "id", "engagement_id", name="uq_authz_snapshot_id_engagement"
        ),
    )
    op.create_index(
        "ix_authz_snapshot_run", "authorization_snapshot", ["scan_run_id"]
    )

    op.create_table(
        "authorization_amendment",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_run_id",
            sa.String(36),
            sa.ForeignKey("scan_run.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagement.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("roe_config_hash", sa.String(64), nullable=False),
        sa.Column("scope_policy_hash", sa.String(64), nullable=False),
        sa.Column("exact_targets", sa.JSON(), nullable=False),
        sa.Column("justification", sa.String(512), nullable=False),
        sa.Column(
            "authorized_by_user_id",
            sa.String(36),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checkpoint_ack_hash", sa.String(64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_authz_amendment_run", "authorization_amendment", ["scan_run_id"]
    )

    op.create_table(
        "authorized_cidr",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column("ip_version", sa.Integer(), nullable=False),
        sa.Column("address_count", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column(
            "amendment_id",
            sa.String(36),
            sa.ForeignKey("authorization_amendment.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("snapshot_id", "cidr", name="uq_authorized_cidr"),
        sa.UniqueConstraint("id", "cidr", name="uq_authorized_cidr_id_value"),
        sa.UniqueConstraint(
            "id", "snapshot_id", name="uq_authorized_cidr_id_snapshot"
        ),
    )
    op.create_index(
        "ix_authorized_cidr_snapshot", "authorized_cidr", ["snapshot_id"]
    )

    op.create_table(
        "authorized_target",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("value", sa.String(253), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column(
            "amendment_id",
            sa.String(36),
            sa.ForeignKey("authorization_amendment.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "snapshot_id", "target_type", "value", name="uq_authorized_target"
        ),
        sa.UniqueConstraint("id", "value", name="uq_authorized_target_id_value"),
        sa.UniqueConstraint(
            "id", "snapshot_id", name="uq_authorized_target_id_snapshot"
        ),
        sa.CheckConstraint(
            "target_type IN ('hostname', 'ip')", name="ck_authorized_target_type"
        ),
    )
    op.create_index(
        "ix_authorized_target_snapshot", "authorized_target", ["snapshot_id"]
    )

    op.create_table(
        "retention_artifact",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("stored_path", sa.String(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("sha256", name="uq_retention_artifact_sha"),
        sa.UniqueConstraint("id", "sha256", name="uq_retention_artifact_id_sha"),
    )

    op.create_table(
        "liveness_attestation",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_run_id",
            sa.String(36),
            sa.ForeignKey("scan_run.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagement.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.String(36),
            sa.ForeignKey("evidence.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("method_profile_id", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_ip", sa.String(64), nullable=False),
        sa.Column("emitting_module", sa.String(64), nullable=False),
        sa.Column(
            "authorization_snapshot_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("authorized_cidr_id", sa.String(36), nullable=True),
        sa.Column("authorized_target_id", sa.String(36), nullable=True),
        sa.Column("parent_authorized_cidr", sa.String(64), nullable=True),
        sa.Column("source_hostname", sa.String(253), nullable=True),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "scan_run_id",
            "observed_ip",
            "method_profile_id",
            name="uq_liveness_run_ip_method",
        ),
        sa.CheckConstraint(
            "(authorized_cidr_id IS NOT NULL) <> (authorized_target_id IS NOT NULL)",
            name="ck_liveness_exactly_one_authz_ref",
        ),
        sa.CheckConstraint(
            "(authorized_cidr_id IS NULL) OR "
            "(parent_authorized_cidr IS NOT NULL AND source_hostname IS NULL)",
            name="ck_liveness_cidr_shape",
        ),
        sa.CheckConstraint(
            "(authorized_target_id IS NULL) OR "
            "(source_hostname IS NOT NULL AND parent_authorized_cidr IS NULL)",
            name="ck_liveness_target_shape",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_cidr_id", "parent_authorized_cidr"],
            ["authorized_cidr.id", "authorized_cidr.cidr"],
            name="fk_liveness_cidr_binding",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_target_id", "source_hostname"],
            ["authorized_target.id", "authorized_target.value"],
            name="fk_liveness_target_binding",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_cidr_id", "authorization_snapshot_id"],
            ["authorized_cidr.id", "authorized_cidr.snapshot_id"],
            name="fk_liveness_cidr_snapshot",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_target_id", "authorization_snapshot_id"],
            ["authorized_target.id", "authorized_target.snapshot_id"],
            name="fk_liveness_target_snapshot",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorization_snapshot_id", "scan_run_id"],
            ["authorization_snapshot.id", "authorization_snapshot.scan_run_id"],
            name="fk_liveness_snapshot_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorization_snapshot_id", "engagement_id"],
            ["authorization_snapshot.id", "authorization_snapshot.engagement_id"],
            name="fk_liveness_snapshot_engagement",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_liveness_run", "liveness_attestation", ["scan_run_id"])

    op.create_table(
        "candidate_manifest",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "scan_run_id",
            sa.String(36),
            sa.ForeignKey("scan_run.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "scan_module_run_id",
            sa.String(36),
            sa.ForeignKey("scan_module_run.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "authorization_snapshot_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column(
            "artifact_id",
            sa.String(36),
            sa.ForeignKey("artifact.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("total_addresses", sa.Integer(), nullable=False),
        sa.Column("probeable_addresses", sa.Integer(), nullable=False),
        sa.Column("excluded_addresses", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("method_profile_id", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "scan_module_run_id", name="uq_manifest_per_module_run"
        ),
        sa.UniqueConstraint(
            "id", "authorization_snapshot_id", name="uq_manifest_id_snapshot"
        ),
        sa.UniqueConstraint("id", "scan_run_id", name="uq_manifest_id_run"),
        sa.ForeignKeyConstraint(
            ["authorization_snapshot_id", "scan_run_id"],
            ["authorization_snapshot.id", "authorization_snapshot.scan_run_id"],
            name="fk_manifest_snapshot_run",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_manifest_run", "candidate_manifest", ["scan_run_id"])

    op.create_table(
        "candidate_manifest_entry",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "manifest_id",
            sa.String(36),
            sa.ForeignKey("candidate_manifest.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "authorization_snapshot_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("candidate_ip", sa.String(64), nullable=False),
        sa.Column("authorized_cidr_id", sa.String(36), nullable=False),
        sa.Column("parent_authorized_cidr", sa.String(64), nullable=False),
        sa.Column("excluded", sa.Boolean(), nullable=False),
        sa.Column("exclusion_reason", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "manifest_id", "candidate_ip", name="uq_manifest_entry_addr"
        ),
        sa.UniqueConstraint("id", "candidate_ip", name="uq_manifest_entry_id_ip"),
        sa.UniqueConstraint(
            "id", "authorized_cidr_id", name="uq_manifest_entry_id_cidr"
        ),
        sa.UniqueConstraint(
            "id", "manifest_id", name="uq_manifest_entry_id_manifest"
        ),
        sa.ForeignKeyConstraint(
            ["authorized_cidr_id", "parent_authorized_cidr"],
            ["authorized_cidr.id", "authorized_cidr.cidr"],
            name="fk_manifest_entry_cidr_value",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_cidr_id", "authorization_snapshot_id"],
            ["authorized_cidr.id", "authorized_cidr.snapshot_id"],
            name="fk_manifest_entry_cidr_snapshot",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id", "authorization_snapshot_id"],
            [
                "candidate_manifest.id",
                "candidate_manifest.authorization_snapshot_id",
            ],
            name="fk_manifest_entry_manifest_snapshot",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_manifest_entry_manifest", "candidate_manifest_entry", ["manifest_id"]
    )

    op.create_table(
        "address_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "manifest_id",
            sa.String(36),
            sa.ForeignKey("candidate_manifest.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "manifest_entry_id",
            sa.String(36),
            sa.ForeignKey("candidate_manifest_entry.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "scan_run_id",
            sa.String(36),
            sa.ForeignKey("scan_run.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagement.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("candidate_ip", sa.String(64), nullable=False),
        sa.Column(
            "authorization_snapshot_id",
            sa.String(36),
            sa.ForeignKey("authorization_snapshot.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("authorized_cidr_id", sa.String(36), nullable=True),
        sa.Column("authorized_target_id", sa.String(36), nullable=True),
        sa.Column("parent_authorized_cidr", sa.String(64), nullable=True),
        sa.Column("source_hostname", sa.String(253), nullable=True),
        sa.Column("permit_id", sa.String(36), nullable=True),
        sa.Column("method_profile_id", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", _ADDRESS_OUTCOME, nullable=False),
        sa.Column(
            "liveness_attestation_id",
            sa.String(36),
            sa.ForeignKey("liveness_attestation.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "evidence_id",
            sa.String(36),
            sa.ForeignKey("evidence.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("detail", sa.String(512), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "manifest_id",
            "candidate_ip",
            name="uq_address_audit_one_per_manifest_addr",
        ),
        sa.UniqueConstraint(
            "scan_run_id",
            "candidate_ip",
            "method_profile_id",
            name="uq_address_audit_one_per_run_addr",
        ),
        sa.CheckConstraint(
            "(authorized_cidr_id IS NOT NULL) <> (authorized_target_id IS NOT NULL)",
            name="ck_address_audit_exactly_one_authz_ref",
        ),
        sa.CheckConstraint(
            "(authorized_cidr_id IS NULL) OR "
            "(manifest_id IS NOT NULL AND manifest_entry_id IS NOT NULL "
            " AND parent_authorized_cidr IS NOT NULL AND source_hostname IS NULL)",
            name="ck_address_audit_cidr_shape",
        ),
        sa.CheckConstraint(
            "(authorized_target_id IS NULL) OR "
            "(manifest_id IS NULL AND manifest_entry_id IS NULL "
            " AND source_hostname IS NOT NULL AND parent_authorized_cidr IS NULL)",
            name="ck_address_audit_target_shape",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_cidr_id", "parent_authorized_cidr"],
            ["authorized_cidr.id", "authorized_cidr.cidr"],
            name="fk_address_audit_cidr_binding",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_target_id", "source_hostname"],
            ["authorized_target.id", "authorized_target.value"],
            name="fk_address_audit_target_binding",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_cidr_id", "authorization_snapshot_id"],
            ["authorized_cidr.id", "authorized_cidr.snapshot_id"],
            name="fk_address_audit_cidr_snapshot",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorized_target_id", "authorization_snapshot_id"],
            ["authorized_target.id", "authorized_target.snapshot_id"],
            name="fk_address_audit_target_snapshot",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorization_snapshot_id", "scan_run_id"],
            ["authorization_snapshot.id", "authorization_snapshot.scan_run_id"],
            name="fk_address_audit_snapshot_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorization_snapshot_id", "engagement_id"],
            ["authorization_snapshot.id", "authorization_snapshot.engagement_id"],
            name="fk_address_audit_snapshot_engagement",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_entry_id", "candidate_ip"],
            [
                "candidate_manifest_entry.id",
                "candidate_manifest_entry.candidate_ip",
            ],
            name="fk_address_audit_entry_ip",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_entry_id", "authorized_cidr_id"],
            [
                "candidate_manifest_entry.id",
                "candidate_manifest_entry.authorized_cidr_id",
            ],
            name="fk_address_audit_entry_cidr",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_entry_id", "manifest_id"],
            [
                "candidate_manifest_entry.id",
                "candidate_manifest_entry.manifest_id",
            ],
            name="fk_address_audit_entry_manifest",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id", "authorization_snapshot_id"],
            [
                "candidate_manifest.id",
                "candidate_manifest.authorization_snapshot_id",
            ],
            name="fk_address_audit_manifest_snapshot",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id", "scan_run_id"],
            ["candidate_manifest.id", "candidate_manifest.scan_run_id"],
            name="fk_address_audit_manifest_run",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_address_audit_run", "address_audit", ["scan_run_id"])
    op.create_index(
        "ix_address_audit_manifest", "address_audit", ["manifest_id"]
    )

    op.create_table(
        "audit_retention_export",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("engagement_id", sa.String(36), nullable=False),  # no FK, by design
        sa.Column(
            "exported_by_user_id",
            sa.String(36),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("exported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("bundle_artifact_id", sa.String(36), nullable=False),
        sa.Column("bundle_artifact_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_count", sa.Integer(), nullable=False),
        sa.Column("manifest_count", sa.Integer(), nullable=False),
        sa.Column("address_audit_count", sa.Integer(), nullable=False),
        sa.Column("attestation_count", sa.Integer(), nullable=False),
        sa.Column("manifest_hashes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["bundle_artifact_id", "bundle_artifact_sha256"],
            ["retention_artifact.id", "retention_artifact.sha256"],
            name="fk_retention_export_bundle",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_audit_retention_engagement",
        "audit_retention_export",
        ["engagement_id"],
    )

    # Optional, non-forensic back-link (Security G0: "not forensic authority").
    # Added as a plain nullable column - a DB-level FK on an existing core table
    # would force a full SQLite table rebuild of `evidence` for no integrity gain
    # (the forensic direction, address_audit -> liveness_attestation, keeps its
    # RESTRICT FK). A future Postgres migration may add the FK.
    op.add_column(
        "evidence",
        sa.Column("liveness_attestation_id", sa.String(36), nullable=True),
    )


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch_op:
        batch_op.drop_column("liveness_attestation_id")
    op.drop_table("audit_retention_export")
    op.drop_table("address_audit")
    op.drop_table("candidate_manifest_entry")
    op.drop_table("candidate_manifest")
    op.drop_table("liveness_attestation")
    op.drop_table("retention_artifact")
    op.drop_table("authorized_target")
    op.drop_table("authorized_cidr")
    op.drop_table("authorization_amendment")
    op.drop_table("authorization_snapshot")
