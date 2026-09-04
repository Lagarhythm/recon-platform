"""Shared FastAPI dependencies: DB sessions, auth, active engagement."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from recon.config import get_settings
from recon.db import get_session
from recon.models.engagement import Engagement
from recon.models.user import User
from recon.orchestrator.auth import AuthService
from recon.orchestrator.engagements import EngagementService
from recon.web.csrf import CSRF_COOKIE, verify_csrf

SESSION_COOKIE = get_settings().session_cookie_name


class _Redirect(Exception):
    def __init__(self, location: str) -> None:
        self.location = location


def redirect_exception_response(exc: _Redirect) -> RedirectResponse:
    return RedirectResponse(exc.location, status_code=303)


DbSession = Annotated[AsyncSession, Depends(get_session)]


def get_auth_service() -> AuthService:
    return AuthService(idle_timeout_minutes=get_settings().session_idle_timeout_minutes)


def get_engagement_service() -> EngagementService:
    return EngagementService()


AuthDep = Annotated[AuthService, Depends(get_auth_service)]
EngagementsDep = Annotated[EngagementService, Depends(get_engagement_service)]


async def get_optional_user(
    request: Request, session: DbSession, auth: AuthDep
) -> User | None:
    token = request.cookies.get(SESSION_COOKIE, "")
    return await auth.resolve_session(session, token)


OptionalUser = Annotated["User | None", Depends(get_optional_user)]


async def require_user(user: OptionalUser) -> User:
    if user is None:
        raise _Redirect("/login")
    return user


CurrentUser = Annotated[User, Depends(require_user)]


async def get_active_engagement(
    user: CurrentUser, session: DbSession, engagements: EngagementsDep
) -> Engagement | None:
    return await engagements.get_or_none(session, user.active_engagement_id)


ActiveEngagement = Annotated["Engagement | None", Depends(get_active_engagement)]


async def require_active_engagement(engagement: ActiveEngagement) -> Engagement:
    if engagement is None:
        raise _Redirect("/engagements?need_active=1")
    return engagement


RequiredEngagement = Annotated[Engagement, Depends(require_active_engagement)]

CsrfProtected = Depends(verify_csrf)

__all__ = [
    "DbSession",
    "AuthDep",
    "EngagementsDep",
    "OptionalUser",
    "CurrentUser",
    "ActiveEngagement",
    "RequiredEngagement",
    "CsrfProtected",
    "SESSION_COOKIE",
    "CSRF_COOKIE",
    "_Redirect",
    "redirect_exception_response",
]
