"""HTTP middleware: CSRF cookie lifecycle + first-run setup gate."""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from recon.db import SessionLocal
from recon.orchestrator.auth import AuthService
from recon.web.csrf import CSRF_COOKIE
from recon.config import get_settings

_SAFE_PREFIXES = ("/static", "/health", "/favicon.ico")


class SetupGateMiddleware(BaseHTTPMiddleware):
    """Force first-run setup before anything else is reachable."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith(_SAFE_PREFIXES):
            async with SessionLocal() as session:
                needs_setup = await AuthService().needs_setup(session)
            if needs_setup and not path.startswith("/setup"):
                return RedirectResponse("/setup", status_code=303)
            if not needs_setup and path.startswith("/setup"):
                return RedirectResponse("/login", status_code=303)
        return await call_next(request)


class CsrfCookieMiddleware(BaseHTTPMiddleware):
    """Guarantee every response carries a CSRF cookie for the double-submit check."""

    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get(CSRF_COOKIE)
        minted = token is None
        if minted:
            token = secrets.token_urlsafe(32)
        request.state.csrf_token = token

        response = await call_next(request)
        if minted:
            settings = get_settings()
            response.set_cookie(
                CSRF_COOKIE,
                token,
                httponly=False,
                secure=settings.session_cookie_secure,
                samesite="strict",
                max_age=60 * 60 * 12,
            )
        # Every authenticated page is dynamic and session-scoped. Without this a
        # browser serves a stale copy after e.g. purging an engagement and being
        # redirected back to the list.
        if not request.url.path.startswith(_SAFE_PREFIXES):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
