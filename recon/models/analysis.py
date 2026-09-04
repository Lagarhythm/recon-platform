from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, TimestampMixin, UUIDPk


class Analysis(UUIDPk, TimestampMixin, Base):
    """One LLM Analyst pass over an engagement's Asset Graph. Read-only output -
    the LLM never acts, it only prioritises."""

    __tablename__ = "analysis"

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="SET NULL"), nullable=True
    )
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_count: Mapped[int] = mapped_column(default=0, nullable=False)

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    priorities: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    next_steps: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    usage: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
