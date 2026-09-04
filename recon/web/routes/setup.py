"""First-run setup: create the single operator account."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from recon.config import get_settings
from recon.core.security import WeakPasswordError
from recon.orchestrator.auth import AuthError
from recon.web.csrf import verify_csrf
from recon.web.deps import AuthDep, DbSession, SESSION_COOKIE
from recon.web.flash import flash
from recon.web.templating import render

router = APIRouter(tags=["setup"])


@router.get("/setup")
async def setup_form(request: Request):
    return render(request, "setup.html", {"error": None})


@router.post("/setup", dependencies=[Depends(verify_csrf)])
async def setup_submit(
    request: Request,
    session: DbSession,
    auth: AuthDep,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if password != password_confirm:
        return render(request, "setup.html", {"error": "Passwords do not match."}, status_code=400)
    try:
        user = await auth.create_initial_admin(session, username, password)
    except (WeakPasswordError, AuthError) as exc:
        return render(request, "setup.html", {"error": str(exc)}, status_code=400)

    token = await auth.start_session(
        session,
        user,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=get_settings().session_cookie_secure,
        samesite="lax",
        max_age=get_settings().session_idle_timeout_minutes * 60,
    )
    flash(resp, "Operator account created. Welcome.", "success")
    return resp
