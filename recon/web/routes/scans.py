"""Scan control: start, live progress (WebSocket), checkpoint resume, cancel."""

from __future__ import annotations

import contextlib

from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse

from recon.orchestrator.events import event_bus
from recon.orchestrator.queries import scan_queries
from recon.orchestrator.scans import ScanError, scan_service
from recon.web.csrf import verify_csrf
from recon.web.deps import (
    CurrentUser,
    DbSession,
    RequiredEngagement,
    SESSION_COOKIE,
)
from recon.web.flash import flash_redirect
from recon.web.templating import render

router = APIRouter(tags=["scans"])


@router.get("/scans")
async def list_scans(
    request: Request,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
):
    runs = await scan_queries.list_runs(session, engagement.id)
    modules = await scan_service.available_modules()
    return render(
        request,
        "scans.html",
        {
            "current_user": user,
            "active_engagement": engagement,
            "runs": runs,
            "modules": modules,
        },
    )


@router.post("/scans", dependencies=[Depends(verify_csrf)])
async def start_scan(
    request: Request,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
):
    form = await request.form()
    module_names = form.getlist("modules")
    allow_oos = form.get("allow_out_of_scope") == "on"
    if not module_names:
        return flash_redirect("/scans", "Select at least one module.", "error")
    try:
        run = await scan_service.start_scan(
            session, engagement, module_names, allow_out_of_scope=allow_oos
        )
    except ScanError as exc:
        return flash_redirect("/scans", f"Could not start scan: {exc}", "error")
    return RedirectResponse(f"/scans/{run.id}", status_code=303)


@router.get("/scans/{scan_run_id}")
async def scan_detail(
    request: Request,
    scan_run_id: str,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
):
    run = await scan_queries.get_run(session, scan_run_id)
    if run is None or run.engagement_id != engagement.id:
        return flash_redirect("/scans", "Scan run not found.", "error")
    modules = await scan_queries.module_rows(session, scan_run_id)
    return render(
        request,
        "scan_detail.html",
        {
            "current_user": user,
            "active_engagement": engagement,
            "run": run,
            "module_rows": modules,
        },
    )


@router.post("/scans/{scan_run_id}/resume", dependencies=[Depends(verify_csrf)])
async def resume_scan(
    scan_run_id: str, user: CurrentUser, engagement: RequiredEngagement, session: DbSession
):
    run = await scan_queries.get_run(session, scan_run_id)
    if run is None or run.engagement_id != engagement.id:
        return flash_redirect("/scans", "Scan run not found.", "error")
    try:
        await scan_service.resume_scan(session, scan_run_id)
    except ScanError as exc:
        return flash_redirect(f"/scans/{scan_run_id}", f"Cannot resume: {exc}", "error")
    return flash_redirect(f"/scans/{scan_run_id}", "Scan resumed.", "success")


@router.post("/scans/{scan_run_id}/cancel", dependencies=[Depends(verify_csrf)])
async def cancel_scan(
    scan_run_id: str, user: CurrentUser, engagement: RequiredEngagement, session: DbSession
):
    run = await scan_queries.get_run(session, scan_run_id)
    if run is None or run.engagement_id != engagement.id:
        return flash_redirect("/scans", "Scan run not found.", "error")
    await scan_service.cancel_scan(scan_run_id)
    return flash_redirect(f"/scans/{scan_run_id}", "Cancellation requested.", "info")


@router.websocket("/scans/{scan_run_id}/ws")
async def scan_ws(websocket: WebSocket, scan_run_id: str):
    # Authenticate the socket via the session cookie.
    from recon.db import SessionLocal
    from recon.orchestrator.auth import AuthService

    token = websocket.cookies.get(SESSION_COOKIE, "")
    async with SessionLocal() as session:
        user = await AuthService().resolve_session(session, token)
        run = await scan_queries.get_run(session, scan_run_id)
    if user is None or run is None or run.engagement_id != user.active_engagement_id:
        await websocket.close(code=4401)
        return

    await websocket.accept()
    queue = event_bus.subscribe(scan_run_id)
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        event_bus.unsubscribe(scan_run_id, queue)
        with contextlib.suppress(Exception):
            await websocket.close()
