"""Read-only audit log viewer for the active engagement."""

from __future__ import annotations

from fastapi import APIRouter, Request

from recon.core.audit import audit_logger
from recon.models.enums import ScopeStatus
from recon.web.deps import CurrentUser, DbSession, RequiredEngagement
from recon.web.templating import render

router = APIRouter(tags=["audit"])


@router.get("/audit")
async def view_audit(
    request: Request,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
    module: str | None = None,
    scope: str | None = None,
    overrides: int = 0,
    page: int = 1,
):
    page = max(page, 1)
    per_page = 100
    scope_filter = None
    if scope in {s.value for s in ScopeStatus}:
        scope_filter = ScopeStatus(scope)
    entries = await audit_logger.list_entries(
        session,
        engagement_id=engagement.id,
        module=module or None,
        in_scope_status=scope_filter,
        override_only=bool(overrides),
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    total = await audit_logger.count(session, engagement_id=engagement.id)
    return render(
        request,
        "audit.html",
        {
            "current_user": user,
            "active_engagement": engagement,
            "entries": entries,
            "total": total,
            "page": page,
            "per_page": per_page,
            "module": module or "",
            "scope": scope or "",
            "overrides": bool(overrides),
            "ScopeStatus": ScopeStatus,
        },
    )
