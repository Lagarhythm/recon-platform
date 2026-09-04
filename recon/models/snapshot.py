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
