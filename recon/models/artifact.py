from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, UUIDPk, utcnow


class Artifact(UUIDPk, Base):
    """A blob the scan captured, content-addressed on disk so large raw outputs
    (screenshots, captured HTTP bodies, nmap XML, git clone logs) never bloat
    the ``Evidence.raw_data`` JSON (PRD Section 9: artifact storage bounds).

    ``path`` is relative to ``data/artifacts/``; the bytes live on disk under
    ``data/artifacts/<engagement_id>/<sha256>``. The row is the manifest entry.
    """

    __tablename__ = "artifact"
    __table_args__ = (
        Index("ix_artifact_engagement", "engagement_id"),
        Index("ix_artifact_asset", "asset_id"),
        # the same bytes can be referenced by many rows, but one engagement
        # stores each payload exactly once
        Index("ix_artifact_eng_sha", "engagement_id", "sha256"),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    #: nullable until the correlator attaches it to the asset that produced it
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("asset.id", ondelete="SET NULL"), nullable=True
    )
    #: what kind of blob this is - drives the report/replay rendering
    kind: Mapped[str] = mapped_column(String(32), nullable=False)

    #: path relative to data/artifacts/ - "<engagement_id>/<sha256>"
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTimeUTC, default=utcnow, nullable=False)
