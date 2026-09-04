from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, UUIDPk, utcnow


class AssetSnapshot(UUIDPk, Base):
    """A point-in-time picture of an engagement's Asset Graph, written once per
    completed scan run.

    ``signature_set`` is a sorted list of stable asset signatures
    (e.g. ``"service:1.2.3.4:443:nginx/1.24"``, ``"subdomain:api.acme.com"``).
    ``scan_diff`` (Wave 2) diffs two snapshots' signature sets to produce the
    ''Since last scan'' view. Schema-only in Wave 0; nothing writes it yet.
    """

    __tablename__ = "asset_snapshot"
    __table_args__ = (
        Index("ix_asset_snapshot_engagement", "engagement_id"),
        Index("ix_asset_snapshot_scan_run", "scan_run_id"),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )

    taken_at: Mapped[datetime] = mapped_column(DateTimeUTC, default=utcnow, nullable=False)

    #: sorted stable asset signatures - the diff baseline
    signature_set: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    #: counts by asset type (``{"subdomain": 42, "service": 7, ...}``)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ScanDelta(UUIDPk, Base):
    """The materialized result of ``scan_diff`` (PRD Section 11.10) - what
    changed vs. ``base_snapshot_id``, for the UI/report and the analyst
    payload. ``base_snapshot_id`` is nullable: the first completed run for an
    engagement has no prior snapshot, so ``scan_diff`` only writes the
    baseline and there is nothing to diff yet.
    """

    __tablename__ = "scan_delta"
    __table_args__ = (
        Index("ix_scan_delta_engagement", "engagement_id"),
        Index("ix_scan_delta_scan_run", "scan_run_id"),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    scan_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_run.id", ondelete="CASCADE"), nullable=False
    )
    base_snapshot_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("asset_snapshot.id", ondelete="SET NULL"), nullable=True
    )

    computed_at: Mapped[datetime] = mapped_column(DateTimeUTC, default=utcnow, nullable=False)

    #: sorted list of added signatures
    added: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    #: sorted list of removed signatures
    removed: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    #: list of {"signature": ..., "was": ..., "now": ...}
    changed: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
