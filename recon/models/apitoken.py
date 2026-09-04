from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, TimestampMixin, UUIDPk


class ApiToken(UUIDPk, TimestampMixin, Base):
    """A bearer credential for the CLI / REST client (PRD Section 8.4).

    Only a SHA-256 hash of the token is stored, never the token itself - a DB
    read yields no usable credential, the same posture as ``Session``. The raw
    token is shown exactly once, at creation.
    """

    __tablename__ = "api_token"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None
