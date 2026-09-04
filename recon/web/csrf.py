"""Double-submit-cookie CSRF protection for state-changing form posts.

The cookie is minted and attached by CsrfCookieMiddleware. Templates echo the
value into a hidden field; verify_csrf compares field against cookie in
constant time. SameSite=strict on the cookie is the primary defence; the
token check is defence in depth.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from recon.core.security import constant_time_equals

CSRF_COOKIE = "recon_csrf"
CSRF_FIELD = "csrf_token"


def issue_csrf(request: Request) -> str:
    return getattr(request.state, "csrf_token", "") or request.cookies.get(CSRF_COOKIE, "")


async def verify_csrf(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    form = await request.form()
    form_token = str(form.get(CSRF_FIELD, ""))
    if not cookie_token or not form_token or not constant_time_equals(cookie_token, form_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")
