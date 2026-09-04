"""Read-model helpers for the dashboard (asset graph, scan status)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.models.asset import Asset, AssetRelationship
from recon.models.enums import AssetType, InterestLevel, ScopeStatus
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun


@dataclass
class AssetGraphStats:
    by_type: dict[str, int]
    by_interest: dict[str, int]
    by_scope: dict[str, int]
    total: int
    findings: int


class AssetQueryService:
    async def stats(self, session: AsyncSession, engagement_id: str) -> AssetGraphStats:
        rows = (
            await session.execute(
                select(Asset.type, Asset.interest_level, Asset.in_scope_status, func.count())
                .where(Asset.engagement_id == engagement_id)
                .group_by(Asset.type, Asset.interest_level, Asset.in_scope_status)
            )
        ).all()
        by_type: dict[str, int] = {}
        by_interest: dict[str, int] = {}
        by_scope: dict[str, int] = {}
        total = 0
        for atype, interest, scope, count in rows:
            tv = atype.value if hasattr(atype, "value") else str(atype)
            iv = interest.value if hasattr(interest, "value") else str(interest)
            sv = scope.value if hasattr(scope, "value") else str(scope)
            by_type[tv] = by_type.get(tv, 0) + count
            by_interest[iv] = by_interest.get(iv, 0) + count
            by_scope[sv] = by_scope.get(sv, 0) + count
            total += count
        return AssetGraphStats(
            by_type=by_type,
            by_interest=by_interest,
            by_scope=by_scope,
            total=total,
            findings=by_type.get(AssetType.FINDING.value, 0),
        )

    async def list_assets(
        self,
        session: AsyncSession,
        engagement_id: str,
        *,
        asset_type: str | None = None,
        interest: str | None = None,
        scope: str | None = None,
        min_confidence: float = 0.0,
        query: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> Sequence[Asset]:
        stmt = select(Asset).where(Asset.engagement_id == engagement_id)
        if asset_type in {t.value for t in AssetType}:
            stmt = stmt.where(Asset.type == AssetType(asset_type))
        if interest in {i.value for i in InterestLevel}:
            stmt = stmt.where(Asset.interest_level == InterestLevel(interest))
        if scope in {s.value for s in ScopeStatus}:
            stmt = stmt.where(Asset.in_scope_status == ScopeStatus(scope))
        if min_confidence > 0:
            stmt = stmt.where(Asset.confidence_score >= min_confidence)
        if query:
            stmt = stmt.where(Asset.value.ilike(f"%{query}%"))
        stmt = stmt.order_by(
            Asset.interest_level.desc(), Asset.confidence_score.desc(), Asset.value
        ).limit(min(limit, 1000)).offset(offset)
        return (await session.execute(stmt)).scalars().all()

    async def get_asset_detail(self, session: AsyncSession, asset_id: str):
        asset = await session.get(Asset, asset_id)
        if asset is None:
            return None
        evidence = (
            await session.execute(
                select(Evidence)
                .where(Evidence.asset_id == asset_id)
                .order_by(Evidence.discovered_at)
            )
        ).scalars().all()
        rels_out = (
            await session.execute(
                select(AssetRelationship, Asset)
                .join(Asset, Asset.id == AssetRelationship.target_asset_id)
                .where(AssetRelationship.source_asset_id == asset_id)
            )
        ).all()
        rels_in = (
            await session.execute(
                select(AssetRelationship, Asset)
                .join(Asset, Asset.id == AssetRelationship.source_asset_id)
                .where(AssetRelationship.target_asset_id == asset_id)
            )
        ).all()
        return {"asset": asset, "evidence": evidence, "rels_out": rels_out, "rels_in": rels_in}


class ScanQueryService:
    async def list_runs(
        self, session: AsyncSession, engagement_id: str, limit: int = 50
    ) -> Sequence[ScanRun]:
        return (
            await session.execute(
                select(ScanRun)
                .where(ScanRun.engagement_id == engagement_id)
                .order_by(ScanRun.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

    async def get_run(self, session: AsyncSession, scan_run_id: str) -> ScanRun | None:
        return await session.get(ScanRun, scan_run_id)

    async def module_rows(
        self, session: AsyncSession, scan_run_id: str
    ) -> Sequence[ScanModuleRun]:
        return (
            await session.execute(
                select(ScanModuleRun)
                .where(ScanModuleRun.scan_run_id == scan_run_id)
                .order_by(ScanModuleRun.order_index)
            )
        ).scalars().all()


asset_queries = AssetQueryService()
scan_queries = ScanQueryService()
