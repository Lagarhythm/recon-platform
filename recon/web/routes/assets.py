"""Asset Graph browser."""

from __future__ import annotations

from fastapi import APIRouter, Request

from recon.models.enums import AssetType, InterestLevel, ScopeStatus
from recon.orchestrator.queries import asset_queries
from recon.web.deps import CurrentUser, DbSession, RequiredEngagement
from recon.web.flash import flash_redirect
from recon.web.templating import render

router = APIRouter(tags=["assets"])


@router.get("/assets")
async def list_assets(
    request: Request,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
    type: str | None = None,
    interest: str | None = None,
    scope: str | None = None,
    min_confidence: float = 0.0,
    q: str | None = None,
    page: int = 1,
):
    page = max(page, 1)
    per_page = 200
    assets = await asset_queries.list_assets(
        session,
        engagement.id,
        asset_type=type,
        interest=interest,
        scope=scope,
        min_confidence=min_confidence,
        query=q,
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    stats = await asset_queries.stats(session, engagement.id)
    return render(
        request,
        "assets.html",
        {
            "current_user": user,
            "active_engagement": engagement,
            "assets": assets,
            "stats": stats,
            "filters": {
                "type": type or "",
                "interest": interest or "",
                "scope": scope or "",
                "min_confidence": min_confidence,
                "q": q or "",
            },
            "page": page,
            "per_page": per_page,
            "AssetType": AssetType,
            "InterestLevel": InterestLevel,
            "ScopeStatus": ScopeStatus,
        },
    )


@router.get("/assets/{asset_id}")
async def asset_detail(
    request: Request,
    asset_id: str,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
):
    detail = await asset_queries.get_asset_detail(session, asset_id)
    if detail is None or detail["asset"].engagement_id != engagement.id:
        return flash_redirect("/assets", "Asset not found.", "error")
    return render(
        request,
        "asset_detail.html",
        {
            "current_user": user,
            "active_engagement": engagement,
            **detail,
        },
    )
