"""Engagement lifecycle + scope access.

Engagements are fully isolated: every downstream query filters by
engagement_id, and switching the active engagement only changes which id the
dashboard passes in.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.roe import RoEConfig, RoEError, load_roe
from recon.core.scope import ScopeManager, lint_roe
from recon.models.engagement import Engagement
from recon.models.enums import EngagementStatus
from recon.models.user import User


class EngagementError(Exception):
    pass


class EngagementNotFound(EngagementError):
    pass


class EngagementService:
    async def create(
        self, session: AsyncSession, raw_yaml: str
    ) -> tuple[Engagement, list[str]]:
        """Create an engagement from an RoE document. Returns (engagement, advisories)."""
        config, roe_hash = load_roe(raw_yaml)
        window = config.engagement.authorized_window
        engagement = Engagement(
            name=config.engagement.name,
            client_name=config.engagement.client,
            roe_config_yaml=raw_yaml,
            roe_config=config.model_dump(mode="json"),
            roe_config_hash=roe_hash,
            authorized_window_start=window.start if window else None,
            authorized_window_end=window.end if window else None,
            status=EngagementStatus.ACTIVE,
            llm_analysis_enabled=config.llm.analysis_enabled,
        )
        session.add(engagement)
        await session.flush()
        return engagement, lint_roe(config)

    async def list(
        self, session: AsyncSession, *, include_archived: bool = True
    ) -> Sequence[Engagement]:
        stmt = select(Engagement).order_by(Engagement.created_at.desc())
        if not include_archived:
            stmt = stmt.where(Engagement.status != EngagementStatus.ARCHIVED)
        return (await session.execute(stmt)).scalars().all()

    async def get(self, session: AsyncSession, engagement_id: str) -> Engagement:
        engagement = await session.get(Engagement, engagement_id)
        if engagement is None:
            raise EngagementNotFound(engagement_id)
        return engagement

    async def get_or_none(
        self, session: AsyncSession, engagement_id: str | None
    ) -> Engagement | None:
        if not engagement_id:
            return None
        return await session.get(Engagement, engagement_id)

    async def set_status(
        self, session: AsyncSession, engagement_id: str, status: EngagementStatus
    ) -> Engagement:
        engagement = await self.get(session, engagement_id)
        engagement.status = status
        return engagement

    async def set_llm_enabled(
        self, session: AsyncSession, engagement_id: str, enabled: bool
    ) -> Engagement:
        engagement = await self.get(session, engagement_id)
        engagement.llm_analysis_enabled = enabled
        return engagement

    async def set_active(
        self, session: AsyncSession, user: User, engagement_id: str | None
    ) -> None:
        if engagement_id:
            await self.get(session, engagement_id)  # existence check
        db_user = await session.get(User, user.id)
        assert db_user is not None
        db_user.active_engagement_id = engagement_id

    async def purge(self, session: AsyncSession, engagement_id: str) -> None:
        """Hard-delete an engagement and everything scoped to it (FK cascade)."""
        engagement = await self.get(session, engagement_id)
        # Detach it from any operator's active pointer first.
        for u in (
            await session.execute(
                select(User).where(User.active_engagement_id == engagement_id)
            )
        ).scalars():
            u.active_engagement_id = None
        await session.delete(engagement)

    # --- Scope access ------------------------------------------------
    def config_of(self, engagement: Engagement) -> RoEConfig:
        try:
            return RoEConfig.model_validate(engagement.roe_config)
        except Exception as exc:  # pragma: no cover - stored config should always be valid
            raise RoEError(f"stored RoE for engagement {engagement.id} is invalid: {exc}") from exc

    def scope_manager(self, engagement: Engagement) -> ScopeManager:
        return ScopeManager(self.config_of(engagement))
