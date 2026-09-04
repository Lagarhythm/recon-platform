from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, UUIDPk, utcnow
from recon.models.enums import ScopeStatus, enum_col


class AuditLogEntry(UUIDPk, Base):
    """The tool's legal / dispute-resolution record.

    Append-only from the application's perspective: there is no service method
    or UI path that updates or deletes a row here.
    """

    __tablename__ = "audit_log_entry"
    __table_args__ = (
        Index("ix_audit_engagement_ts", "engagement_id", "timestamp"),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="SET NULL"), nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(1024), nullable=False)

    in_scope_status: Mapped[ScopeStatus] = mapped_column(
        enum_col(ScopeStatus), nullable=False
    )
    override_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Cryptographically pins "what scope was authorized when this request went
    # out" for post-engagement disputes.
    roe_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    request_detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # PRD gap: capture the response side too, so the log is a real forensic record.
    response_meta: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    note: Mapped[str | None] = mapped_column(String(512), nullable=True)
