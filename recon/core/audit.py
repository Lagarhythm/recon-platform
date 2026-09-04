"""Audit Logger.

Records every outbound request the tool makes. Append-only by construction:
this module exposes ``record`` and read helpers only - there is deliberately
no update or delete path anywhere in the codebase.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.models.audit import AuditLogEntry
from recon.models.enums import ScopeStatus


class AuditLogger:
    async def record(
        self,
        session: AsyncSession,
        *,
        engagement_id: str,
        module: str,
        target: str,
        in_scope_status: ScopeStatus,
        roe_config_hash: str,
        request_detail: dict[str, Any],
        response_meta: dict[str, Any] | None = None,
        override_used: bool = False,
        scan_run_id: str | None = None,
        note: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            engagement_id=engagement_id,
            scan_run_id=scan_run_id,
            module=module,
            target=target,
            in_scope_status=in_scope_status,
            override_used=override_used,
            roe_config_hash=roe_config_hash,
            request_detail=request_detail,
            response_meta=response_meta,
            note=note,
        )
        if timestamp is not None:
            entry.timestamp = timestamp
        session.add(entry)
        await session.flush()
        return entry

    async def list_entries(
        self,
        session: AsyncSession,
        *,
        engagement_id: str,
        module: str | None = None,
        in_scope_status: ScopeStatus | None = None,
        override_only: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> Sequence[AuditLogEntry]:
        stmt = (
            select(AuditLogEntry)
            .where(AuditLogEntry.engagement_id == engagement_id)
            .order_by(AuditLogEntry.timestamp.desc())
        )
        if module:
            stmt = stmt.where(AuditLogEntry.module == module)
        if in_scope_status is not None:
            stmt = stmt.where(AuditLogEntry.in_scope_status == in_scope_status)
        if override_only:
            stmt = stmt.where(AuditLogEntry.override_used.is_(True))
        stmt = stmt.limit(min(limit, 1000)).offset(offset)
        return (await session.execute(stmt)).scalars().all()

    async def count(self, session: AsyncSession, *, engagement_id: str) -> int:
        from sqlalchemy import func

        stmt = select(func.count()).select_from(AuditLogEntry).where(
            AuditLogEntry.engagement_id == engagement_id
        )
        return int((await session.execute(stmt)).scalar_one())


audit_logger = AuditLogger()
