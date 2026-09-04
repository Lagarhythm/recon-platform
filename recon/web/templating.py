"""Jinja2 configuration and a render helper that injects common context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from recon import __version__
from recon.orchestrator.killswitch import kill_switch
from recon.web.csrf import CSRF_FIELD, issue_csrf
from recon.web.flash import FLASH_COOKIE, read_flashes

_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
):
    flashes = read_flashes(request)
    ctx: dict[str, Any] = {
        "request": request,
        "app_version": __version__,
        "csrf_token": issue_csrf(request),
        "csrf_field": CSRF_FIELD,
        "flashes": flashes,
        "kill_switch": kill_switch.status(),
        "current_user": getattr(request.state, "current_user", None),
        "active_engagement": getattr(request.state, "active_engagement", None),
    }
    if context:
        ctx.update(context)
    response = templates.TemplateResponse(
        request, template, ctx, status_code=status_code
    )
    if flashes:
        response.delete_cookie(FLASH_COOKIE)
    return response
