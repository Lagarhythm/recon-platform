"""JSON REST API for the ``recon`` CLI (``--server`` mode) and any other
programmatic client. Bearer-token auth via :class:`~recon.models.apitoken.ApiToken`.

Every endpoint is a thin wrapper over :class:`~recon.cli.client.InProcessClient`
- the exact code path the local CLI uses - so the two transports cannot drift.
Token auth is not cookie-based, so these routes are CSRF-exempt by construction.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from recon.cli.client import InProcessClient
from recon.cli.output import EXIT_AUTH, CliError
from recon.db import session_scope
from recon.models.user import User
from recon.orchestrator.tokens import TokenService

router = APIRouter(prefix="/api/v1", tags=["api"])

_CONTENT_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "html": "text/html",
    "pdf": "application/pdf",
}


async def require_token(
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    raw = authorization.split(" ", 1)[1].strip()
    async with session_scope() as session:
        user = await TokenService().authenticate(session, raw)
    if user is None:
        raise HTTPException(401, "invalid or revoked token")
    return user


TokenUser = Annotated[User, Depends(require_token)]


def _client(user: User) -> InProcessClient:
    return InProcessClient(user_id=user.id)


def _http_status(code: int) -> int:
    # Client errors from the shared InProcessClient are either an auth problem
    # (403) or a bad request (400). Scan outcome codes (2 "module failures",
    # 4 "scan failed") are never *raised* - they ride in the status payload the
    # CLI reads to compute its own exit code, on both transports.
    return 403 if code == EXIT_AUTH else 400


async def _call(coro) -> Any:  # noqa: ANN001
    try:
        return await coro
    except CliError as exc:
        raise HTTPException(_http_status(exc.exit_code), str(exc)) from exc


# --- engagements ----------------------------------------------------------
@router.get("/engagements")
async def list_engagements(
    user: TokenUser, include_archived: bool = Query(True)
) -> list[dict]:
    return await _call(_client(user).engagement_list(include_archived=include_archived))


@router.post("/engagements")
async def create_engagement(user: TokenUser, payload: dict = Body(...)) -> dict:
    roe_yaml = payload.get("roe_yaml")
    if not roe_yaml:
        raise HTTPException(400, "roe_yaml is required")
    return await _call(_client(user).engagement_create(roe_yaml, payload.get("name")))


@router.get("/engagements/{engagement_id}")
async def show_engagement(user: TokenUser, engagement_id: str) -> dict:
    return await _call(_client(user).engagement_show(engagement_id))


@router.post("/engagements/{engagement_id}/status")
async def set_engagement_status(
    user: TokenUser, engagement_id: str, payload: dict = Body(...)
) -> dict:
    status = payload.get("status")
    if not status:
        raise HTTPException(400, "status is required")
    return await _call(_client(user).engagement_set_status(engagement_id, status))


@router.post("/engagements/{engagement_id}/purge")
async def purge_engagement(
    user: TokenUser, engagement_id: str, payload: dict = Body(default={})
) -> dict:
    """Hard-delete. Requires ``confirm_name`` to match the engagement name -
    the same export-or-confirm gate the dashboard enforces (PRD Section 13
    row 4)."""
    show = await _call(_client(user).engagement_show(engagement_id))
    if (payload or {}).get("confirm_name") != show.get("name"):
        raise HTTPException(400, "confirm_name must match the engagement name")
    return await _call(_client(user).engagement_purge(engagement_id, show.get("name")))


@router.get("/engagements/{engagement_id}/report")
async def engagement_report(
    user: TokenUser,
    engagement_id: str,
    format: str = Query("html"),
    redacted: bool = Query(False),
) -> Response:
    blob = await _call(_client(user).report(engagement_id, format, redacted=redacted))
    return Response(blob, media_type=_CONTENT_TYPES.get(format, "application/octet-stream"))


@router.get("/engagements/{engagement_id}/diff")
async def engagement_diff(
    user: TokenUser, engagement_id: str, since: str | None = Query(None)
) -> dict:
    return await _call(_client(user).diff(engagement_id, since))


@router.post("/engagements/{engagement_id}/analyst")
async def engagement_analyst(user: TokenUser, engagement_id: str) -> dict:
    return await _call(_client(user).analyst_run(engagement_id))


# --- scans --------------------------------------------------------------
@router.get("/modules")
async def list_modules(user: TokenUser) -> list[dict]:
    return await _call(_client(user).available_modules())


@router.post("/scans")
async def start_scan(user: TokenUser, payload: dict = Body(...)) -> dict:
    engagement_id = payload.get("engagement_id")
    modules = payload.get("modules") or []
    if not engagement_id or not modules:
        raise HTTPException(400, "engagement_id and modules are required")
    return await _call(
        _client(user).scan_start(
            engagement_id, list(modules),
            allow_out_of_scope=bool(payload.get("allow_out_of_scope")),
            yes_active=bool(payload.get("yes_active")),
        )
    )


@router.get("/scans")
async def list_scans(user: TokenUser, engagement_id: str = Query(...)) -> list[dict]:
    return await _call(_client(user).scan_list(engagement_id))


@router.get("/scans/{run_id}")
async def scan_status(user: TokenUser, run_id: str) -> dict:
    return await _call(_client(user).scan_status(run_id))


@router.post("/scans/{run_id}/checkpoint")
async def scan_checkpoint(user: TokenUser, run_id: str) -> dict:
    return await _call(_client(user).scan_checkpoint(run_id))


@router.post("/scans/{run_id}/resume")
async def scan_resume(user: TokenUser, run_id: str) -> dict:
    return await _call(_client(user).scan_resume(run_id))


@router.post("/scans/{run_id}/cancel")
async def scan_cancel(user: TokenUser, run_id: str) -> dict:
    return await _call(_client(user).scan_cancel(run_id))


@router.get("/scans/{run_id}/events")
async def scan_events(user: TokenUser, run_id: str) -> StreamingResponse:
    """Server-sent events over the same bus the dashboard WebSocket consumes."""
    import json

    async def _gen():
        async for event in _client(user).scan_stream(run_id):
            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream")


# --- cve (Wave 2) ------------------------------------------------------
@router.get("/cve/status")
async def cve_status(user: TokenUser) -> dict:
    return await _call(_client(user).cve_status())


@router.post("/cve/refresh")
async def cve_refresh(user: TokenUser, payload: dict = Body(default={})) -> dict:
    return await _call(_client(user).cve_refresh(payload.get("source")))


# --- tokens ----------------------------------------------------------
@router.get("/tokens")
async def list_tokens(user: TokenUser) -> list[dict]:
    return await _call(_client(user).token_list())


@router.post("/tokens")
async def create_token(user: TokenUser, payload: dict = Body(...)) -> dict:
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    return await _call(_client(user).token_create(name))


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(user: TokenUser, token_id: str) -> dict:
    return await _call(_client(user).token_revoke(token_id))
