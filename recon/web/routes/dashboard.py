"""Operator dashboard home."""

from __future__ import annotations

from fastapi import APIRouter, Request

from recon.core.audit import audit_logger
from recon.core.scope import ScopeManager
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.queries import asset_queries, scan_queries
from recon.web.deps import ActiveEngagement, CurrentUser, DbSession, EngagementsDep
from recon.web.templating import render

router = APIRouter(tags=["dashboard"])


@router.get("/")
async def home(
    request: Request,
    user: CurrentUser,
    engagement: ActiveEngagement,
    engagements: EngagementsDep,
    session: DbSession,
):
    ctx: dict = {
        "current_user": user,
        "active_engagement": engagement,
        "kill_switch": kill_switch.status(),
        "window_status": None,
        "audit_count": 0,
        "roe": None,
    }
    if engagement is not None:
        roe = engagements.config_of(engagement)
        ctx["roe"] = roe
        ctx["window_status"] = ScopeManager(roe).check_window().value
        ctx["audit_count"] = await audit_logger.count(session, engagement_id=engagement.id)
        ctx["asset_stats"] = await asset_queries.stats(session, engagement.id)
        ctx["recent_runs"] = await scan_queries.list_runs(session, engagement.id, limit=5)
        ctx["top_findings"] = await asset_queries.list_assets(
            session, engagement.id, interest="high_value", limit=10
        )
    return render(request, "dashboard.html", ctx)
