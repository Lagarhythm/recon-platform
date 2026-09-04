from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, TimestampMixin, UUIDPk
from recon.models.enums import EngagementStatus, enum_col


class Engagement(UUIDPk, TimestampMixin, Base):
    """A fully isolated client/project. Every other table is scoped by engagement_id."""

    __tablename__ = "engagement"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    client_name: Mapped[str] = mapped_column(String(200), nullable=False)

    # The RoE config as originally supplied (source of truth for the operator)
    # plus its parsed form and a canonical hash used to pin scope on every
    # audit-log entry and scan run.
    roe_config_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    roe_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    roe_config_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    authorized_window_start: Mapped[datetime | None] = mapped_column(
        DateTimeUTC, nullable=True
    )
    authorized_window_end: Mapped[datetime | None] = mapped_column(
        DateTimeUTC, nullable=True
    )

    status: Mapped[EngagementStatus] = mapped_column(
        enum_col(EngagementStatus), default=EngagementStatus.ACTIVE, nullable=False
    )

    # PRD gap #1: sending recon data to a remote LLM endpoint is opt-in per
    # engagement and defaults OFF. Some RoEs forbid third-party data sharing.
    llm_analysis_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
