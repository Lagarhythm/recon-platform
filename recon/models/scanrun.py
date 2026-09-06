from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, TimestampMixin, UUIDPk
from recon.models.enums import (
    ModulePhase,
    ModuleRunStatus,
    ScanRunStatus,
    SkipReason,
    enum_col,
)


class ScanRun(UUIDPk, TimestampMixin, Base):
    __tablename__ = "scan_run"

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Scope is pinned for the lifetime of the run - if the operator edits the
    # RoE mid-engagement, in-flight runs keep the scope they started with.
    roe_config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    roe_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    modules_requested: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    # Section 7.4: module-level resumability - a resumed run skips these.
    modules_completed: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    # Operator opted in to hitting flagged/excluded targets for this run.
    allow_out_of_scope: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    status: Mapped[ScanRunStatus] = mapped_column(
        enum_col(ScanRunStatus), default=ScanRunStatus.RUNNING, nullable=False
    )
    # Section 7.1: after all passive modules finish, a run with active modules
    # stops here until the operator reviews "what we know" and signs off.
    active_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    current_phase: Mapped[ModulePhase | None] = mapped_column(
        enum_col(ModulePhase), nullable=True
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanModuleRun(UUIDPk, Base):
    """Per-module execution record within a ScanRun - drives the live UI and
    the resumability logic."""

    __tablename__ = "scan_module_run"

    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False, index=True
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)
    phase: Mapped[ModulePhase] = mapped_column(enum_col(ModulePhase), nullable=False)
    status: Mapped[ModuleRunStatus] = mapped_column(
        enum_col(ModuleRunStatus), default=ModuleRunStatus.PENDING, nullable=False
    )
    # Only meaningful when ``status is SKIPPED``. Separates a benign resumed run
    # from a "module had no input" outcome the release gate must not treat as a
    # clean scan.
    skip_reason: Mapped[SkipReason | None] = mapped_column(
        enum_col(SkipReason), nullable=True
    )
    order_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    evidence_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Safe, operator-facing coverage caveats emitted by the module (for
    # example, configured source exclusions).  This is deliberately separate
    # from error text so a skipped check cannot be rendered as a clean empty
    # result and so reports never need to infer coverage from log prose.
    coverage_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    started_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
