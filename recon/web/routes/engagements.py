"""Engagement management: create from RoE, switch active, status, purge."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse

from recon.core.audit import audit_logger
from recon.core.roe import RoEError
from recon.core.scope import lint_roe
from recon.models.enums import EngagementStatus
from recon.orchestrator.engagements import EngagementNotFound
from recon.web.csrf import verify_csrf
from recon.web.deps import CurrentUser, DbSession, EngagementsDep
from recon.web.flash import flash, flash_redirect
from recon.web.roe_form import RoEFormError, form_to_roe_yaml
from recon.web.templating import render

router = APIRouter(tags=["engagements"])

ROTATION_CHOICES = ["round_robin", "random"]


async def _create_and_activate(request, user, engagements, session, raw_yaml: str):
    """Shared tail for both the raw-YAML and guided-form create paths."""
    engagement, warnings = await engagements.create(session, raw_yaml)
    await engagements.set_active(session, user, engagement.id)
    resp = RedirectResponse(f"/engagements/{engagement.id}", status_code=303)
    msg = f"Engagement '{engagement.name}' created and set active."
    if warnings:
        msg += f" {len(warnings)} advisory warning(s) - review below."
    flash(resp, msg, "warning" if warnings else "success")
    return resp


@router.get("/engagements")
async def list_engagements(
    request: Request,
    user: CurrentUser,
    engagements: EngagementsDep,
    session: DbSession,
    need_active: int = 0,
):
    rows = await engagements.list(session)
    active = await engagements.get_or_none(session, user.active_engagement_id)
    return render(
        request,
        "engagements.html",
        {
            "current_user": user,
            "active_engagement": active,
            "engagements": rows,
            "need_active": bool(need_active),
            "error": None,
            "EngagementStatus": EngagementStatus,
        },
    )


@router.post("/engagements", dependencies=[Depends(verify_csrf)])
async def create_engagement(
    request: Request,
    user: CurrentUser,
    engagements: EngagementsDep,
    session: DbSession,
    roe_yaml: str = Form(""),
    roe_file: UploadFile | None = File(None),
):
    raw = roe_yaml
    if roe_file is not None and roe_file.filename:
        raw = (await roe_file.read()).decode("utf-8", errors="replace")
    if not raw.strip():
        rows = await engagements.list(session)
        return render(
            request, "engagements.html",
            {"current_user": user, "engagements": rows, "error": "Provide an RoE document."},
            status_code=400,
        )
    try:
        return await _create_and_activate(request, user, engagements, session, raw)
    except RoEError as exc:
        rows = await engagements.list(session)
        return render(
            request, "engagements.html",
            {"current_user": user, "engagements": rows, "error": f"RoE rejected: {exc}"},
            status_code=400,
        )


@router.get("/engagements/new")
async def new_engagement_form(request: Request, user: CurrentUser):
    return render(
        request,
        "engagement_new.html",
        {"current_user": user, "error": None, "form": {}, "rotation_choices": ROTATION_CHOICES},
    )


@router.post("/engagements/new", dependencies=[Depends(verify_csrf)])
async def new_engagement_submit(
    request: Request,
    user: CurrentUser,
    engagements: EngagementsDep,
    session: DbSession,
):
    form = {k: v for k, v in (await request.form()).items()}
    try:
        raw_yaml = form_to_roe_yaml(form)
        return await _create_and_activate(request, user, engagements, session, raw_yaml)
    except (RoEFormError, RoEError) as exc:
        return render(
            request,
            "engagement_new.html",
            {
                "current_user": user,
                "error": str(exc),
                "form": form,
                "rotation_choices": ROTATION_CHOICES,
            },
            status_code=400,
        )


@router.get("/engagements/{engagement_id}")
async def engagement_detail(
    request: Request,
    engagement_id: str,
    user: CurrentUser,
    engagements: EngagementsDep,
    session: DbSession,
):
    try:
        engagement = await engagements.get(session, engagement_id)
    except EngagementNotFound:
        return flash_redirect("/engagements", "Engagement not found.", "error")
    roe = engagements.config_of(engagement)
    return render(
        request,
        "engagement_detail.html",
        {
            "current_user": user,
            "engagement": engagement,
            "active_engagement": await engagements.get_or_none(session, user.active_engagement_id),
            "roe": roe,
            "warnings": lint_roe(roe),
            "audit_count": await audit_logger.count(session, engagement_id=engagement.id),
            "EngagementStatus": EngagementStatus,
        },
    )


@router.post("/engagements/{engagement_id}/activate", dependencies=[Depends(verify_csrf)])
async def activate(
    engagement_id: str, user: CurrentUser, engagements: EngagementsDep, session: DbSession
):
    try:
        await engagements.set_active(session, user, engagement_id)
    except EngagementNotFound:
        return flash_redirect("/engagements", "Engagement not found.", "error")
    return flash_redirect("/", "Active engagement switched.", "success")


@router.post("/engagements/{engagement_id}/status", dependencies=[Depends(verify_csrf)])
async def set_status(
    engagement_id: str,
    engagements: EngagementsDep,
    session: DbSession,
    user: CurrentUser,
    status: str = Form(...),
):
    try:
        new_status = EngagementStatus(status)
    except ValueError:
        return flash_redirect(f"/engagements/{engagement_id}", "Unknown status.", "error")
    await engagements.set_status(session, engagement_id, new_status)
    return flash_redirect(
        f"/engagements/{engagement_id}", f"Status set to {new_status.value}.", "success"
    )


@router.post("/engagements/{engagement_id}/llm", dependencies=[Depends(verify_csrf)])
async def set_llm(
    engagement_id: str,
    engagements: EngagementsDep,
    session: DbSession,
    user: CurrentUser,
    enabled: str = Form("off"),
):
    on = enabled == "on"
    await engagements.set_llm_enabled(session, engagement_id, on)
    return flash_redirect(
        f"/engagements/{engagement_id}",
        f"Remote LLM analysis {'ENABLED - recon data will leave this host' if on else 'disabled'}.",
        "warning" if on else "info",
    )


@router.post("/engagements/{engagement_id}/purge", dependencies=[Depends(verify_csrf)])
async def purge(
    engagement_id: str,
    engagements: EngagementsDep,
    session: DbSession,
    user: CurrentUser,
    confirm_name: str = Form(...),
):
    try:
        engagement = await engagements.get(session, engagement_id)
    except EngagementNotFound:
        return flash_redirect("/engagements", "Engagement not found.", "error")
    if confirm_name.strip() != engagement.name:
        return flash_redirect(
            f"/engagements/{engagement_id}",
            "Purge aborted: typed name did not match.",
            "error",
        )
    name = engagement.name
    await engagements.purge(session, engagement_id)
    return flash_redirect("/engagements", f"Engagement '{name}' and all its data purged.", "success")
