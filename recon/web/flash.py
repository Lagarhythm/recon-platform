"""Minimal signed-cookie flash messages (no server-side session store needed)."""

from __future__ import annotations

from fastapi import Request, Response
from itsdangerous import BadSignature, URLSafeSerializer

from recon.config import get_settings

FLASH_COOKIE = "recon_flash"
_serializer = URLSafeSerializer(get_settings().secret_key, salt="flash")

# category is one of: info, success, warning, error


def flash(response: Response, message: str, category: str = "info") -> None:
    payload = _serializer.dumps([[category, message]])
    response.set_cookie(FLASH_COOKIE, payload, max_age=30, httponly=True, samesite="lax")


def read_flashes(request: Request) -> list[tuple[str, str]]:
    raw = request.cookies.get(FLASH_COOKIE)
    if not raw:
        return []
    try:
        data = _serializer.loads(raw)
    except BadSignature:
        return []
    return [(c, m) for c, m in data]


def flash_redirect(location: str, message: str, category: str = "info", status_code: int = 303):
    from fastapi.responses import RedirectResponse

    resp = RedirectResponse(location, status_code=status_code)
    flash(resp, message, category)
    return resp
