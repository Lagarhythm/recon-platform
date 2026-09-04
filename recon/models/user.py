from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, TimestampMixin, UUIDPk


class User(UUIDPk, TimestampMixin, Base):
    __tablename__ = "user"

    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)

    # Single-operator app state: which engagement the dashboard is focused on.
    active_engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagement.id", ondelete="SET NULL"), nullable=True
    )


class Session(UUIDPk, TimestampMixin, Base):
    __tablename__ = "session"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # We store only a hash of the bearer token, never the token itself.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    last_activity: Mapped[datetime] = mapped_column(DateTimeUTC, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTimeUTC, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
