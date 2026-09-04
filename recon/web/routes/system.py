"""System controls: health check and the global kill switch."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from recon.web.csrf import verify_csrf
from recon.web.deps import CurrentUser
from recon.web.flash import flash_redirect
from recon.orchestrator.killswitch import kill_switch

router = APIRouter(tags=["system"])


@router.get("/health")
async def health():
    return {"status": "ok", "kill_switch": kill_switch.status()}


@router.post("/system/killswitch/engage", dependencies=[Depends(verify_csrf)])
async def engage_killswitch(
    request: Request,
    user: CurrentUser,
    reason: str = Form("operator emergency stop"),
):
    kill_switch.engage(reason=reason.strip() or "operator emergency stop", by_user=user.username)
    return flash_redirect(
        request.headers.get("referer", "/"),
        "GLOBAL STOP engaged. All active modules will halt.",
        "error",
    )


@router.post("/system/killswitch/reset", dependencies=[Depends(verify_csrf)])
async def reset_killswitch(request: Request, user: CurrentUser):
    kill_switch.reset(by_user=user.username)
    return flash_redirect(
        request.headers.get("referer", "/"),
        "Kill switch cleared. Scanning re-enabled.",
        "success",
    )
