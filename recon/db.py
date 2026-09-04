"""Async database engine and session plumbing.

SQLite is the default datastore (portability NFR). The schema is fully
ORM-defined so a future Postgres migration is a URL change plus an Alembic
run, not a rewrite.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from recon.config import get_settings

_settings = get_settings()

engine = create_async_engine(
    _settings.resolved_database_url,
    echo=_settings.debug,
    future=True,
)


@event.listens_for(engine.sync_engine, "connect")
def _sqlite_pragmas(dbapi_connection, _connection_record):  # noqa: ANN001
    """Enforce foreign keys and use WAL for better concurrent-read behaviour."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=15000")
    cursor.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, much faster
    cursor.close()


SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional scope for background/orchestrator code (outside a request)."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency - one session per request, rolled back on error."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
