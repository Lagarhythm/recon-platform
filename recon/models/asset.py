from __future__ import annotations

from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, UUIDPk, utcnow
from recon.models.enums import (
    AssetType,
    InterestLevel,
    RelationshipType,
    ScopeStatus,
    enum_col,
)


class Asset(UUIDPk, Base):
    """The deliverable. Only the Correlation Engine writes here - modules write Evidence."""

    __tablename__ = "asset"
    __table_args__ = (
        UniqueConstraint("engagement_id", "type", "value", name="uq_asset_identity"),
        Index("ix_asset_engagement_type", "engagement_id", "type"),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[AssetType] = mapped_column(enum_col(AssetType), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)

    # "How sure are we this asset exists" - derived from independent-source count.
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    # "Should the analyst care" - orthogonal to confidence.
    interest_level: Mapped[InterestLevel] = mapped_column(
        enum_col(InterestLevel), default=InterestLevel.INFORMATIONAL, nullable=False
    )
    in_scope_status: Mapped[ScopeStatus] = mapped_column(
        enum_col(ScopeStatus), default=ScopeStatus.FLAGGED, nullable=False
    )

    first_seen: Mapped[datetime] = mapped_column(DateTimeUTC, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTimeUTC, default=utcnow)


class AssetRelationship(UUIDPk, Base):
    __tablename__ = "asset_relationship"
    __table_args__ = (
        UniqueConstraint(
            "source_asset_id", "target_asset_id", "relationship_type", name="uq_relationship"
        ),
    )

    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="CASCADE"), nullable=False
    )
    source_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[RelationshipType] = mapped_column(
        enum_col(RelationshipType), nullable=False
    )
