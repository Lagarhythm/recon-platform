from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, UUIDPk, utcnow
from recon.models.enums import FindingPolarity, enum_col


class Evidence(UUIDPk, Base):
    """The single write target for every recon module.

    Evidence names a *subject* (e.g. subdomain "api.acme.com"). The Correlation
    Engine later attaches it to an Asset by populating ``asset_id``. Until then
    evidence is unattached but never lost.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_engagement_subject", "engagement_id", "subject_type", "subject_value"),
        Index("ix_evidence_asset", "asset_id"),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("asset.id", ondelete="SET NULL"), nullable=True
    )

    source_module: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="SET NULL"), nullable=True
    )
    # Optional back-link to the liveness attestation this evidence proves (P0-1).
    # Not forensic authority - the attestation row is - so this is a plain
    # nullable column, no DB FK (avoids a full SQLite rebuild of `evidence`; the
    # forensic direction address_audit -> liveness_attestation keeps its FK).
    liveness_attestation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # What this evidence is about, before correlation resolves it to an Asset.
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_value: Mapped[str] = mapped_column(String(1024), nullable=False)

    # PRD gap / Section 7.2: absence of a control is itself a finding.
    polarity: Mapped[FindingPolarity] = mapped_column(
        enum_col(FindingPolarity), default=FindingPolarity.PRESENT, nullable=False
    )
    # Resilience NFR: a module failure is recorded as evidence, not a crash.
    is_error: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    request_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )
