"""Declarative base and common column helpers."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DateTimeUTC(TypeDecorator):
    """Timezone-aware UTC datetime that survives a round trip through SQLite.

    SQLite has no native tz type and SQLAlchemy hands back naive values; this
    normalises everything to aware UTC on the way in and out so comparisons
    never mix naive and aware.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """All models inherit from this."""

    # Map bare ``dict`` / ``list`` annotations to a JSON column.
    type_annotation_map: dict[Any, Any] = {
        dict[str, Any]: JSON,
        list[Any]: JSON,
    }


class UUIDPk:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTimeUTC, default=utcnow, nullable=False
    )
