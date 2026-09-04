"""Login / logout / account management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from recon.config import get_settings
from recon.core.security import WeakPasswordError
from recon.orchestrator.auth import AuthError
from recon.web.csrf import verify_csrf
from recon.web.deps import AuthDep, CurrentUser, DbSession, SESSION_COOKIE
from recon.web.flash import flash, flash_redirect
from recon.web.templating import render

router = APIRouter(tags=["auth"])


def _set_session_cookie(resp, token: str) -> None:  # noqa: ANN001
    s = get_settings()
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=s.session_cookie_secure,
        samesite="lax",
        max_age=s.session_idle_timeout_minutes * 60,
    )


@router.get("/login")
async def login_form(request: Request):
    return render(request, "login.html", {"error": None})


@router.post("/login", dependencies=[Depends(verify_csrf)])
async def login_submit(
    request: Request,
    session: DbSession,
    auth: AuthDep,
    username: str = Form(...),
    password: str = Form(...),
):
    user = await auth.authenticate(session, username, password)
    if user is None:
        return render(
            request, "login.html", {"error": "Invalid credentials."}, status_code=401
        )
    token = await auth.start_session(
        session,
        user,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    resp = RedirectResponse("/", status_code=303)
    _set_session_cookie(resp, token)
    flash(resp, f"Signed in as {user.username}.", "success")
    return resp


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(request: Request, session: DbSession, auth: AuthDep):
    await auth.end_session(session, request.cookies.get(SESSION_COOKIE, ""))
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    flash(resp, "Signed out.", "info")
    return resp


@router.get("/account")
async def account(request: Request, user: CurrentUser):
    return render(request, "account.html", {"error": None, "current_user": user})


@router.post("/account/password", dependencies=[Depends(verify_csrf)])
async def change_password(
    request: Request,
    session: DbSession,
    auth: AuthDep,
    user: CurrentUser,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
):
    if new_password != new_password_confirm:
        return render(
            request, "account.html",
            {"error": "New passwords do not match.", "current_user": user},
            status_code=400,
        )
    try:
        await auth.change_password(session, user, current_password, new_password)
    except (AuthError, WeakPasswordError) as exc:
        return render(
            request, "account.html", {"error": str(exc), "current_user": user}, status_code=400
        )
    # change_password revoked all sessions - issue a fresh one.
    token = await auth.start_session(
        session, user,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    resp = flash_redirect("/account", "Password changed. Other sessions were signed out.", "success")
    _set_session_cookie(resp, token)
    return resp
