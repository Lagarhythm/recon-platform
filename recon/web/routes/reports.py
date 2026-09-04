"""Report generation (HTML / PDF / JSON) and the LLM Analyst."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select

from recon.models.analysis import Analysis
from recon.orchestrator.analyst import AnalystError, AnalystService
from recon.reporting.collect import build_report_data
from recon.reporting.redaction import RedactionMode, redact_report
from recon.reporting.render import PdfUnavailable, render_html, render_json, render_pdf
from recon.web.csrf import verify_csrf
from recon.web.deps import CurrentUser, DbSession, RequiredEngagement
from recon.web.flash import flash_redirect
from recon.web.templating import render

router = APIRouter(tags=["reports"])


async def _latest_analysis(session, engagement_id: str) -> Analysis | None:
    return (
        await session.execute(
            select(Analysis)
            .where(Analysis.engagement_id == engagement_id)
            .order_by(Analysis.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


def _analyst_ctx(analysis: Analysis | None) -> dict | None:
    if analysis is None or analysis.error:
        return None
    return {
        "model": analysis.model,
        "summary": analysis.summary,
        "priorities": analysis.priorities,
        "next_steps": analysis.next_steps,
    }


@router.get("/reports")
async def reports_page(
    request: Request,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
):
    analysis = await _latest_analysis(session, engagement.id)
    return render(
        request,
        "reports.html",
        {
            "current_user": user,
            "active_engagement": engagement,
            "analysis": analysis,
        },
    )


@router.get("/reports/download")
async def download_report(
    request: Request,
    user: CurrentUser,
    engagement: RequiredEngagement,
    session: DbSession,
    format: str = "html",
    redact: int = 0,
):
    data = await build_report_data(session, engagement)
    mode = RedactionMode.CLIENT if redact else RedactionMode.INTERNAL
    data = redact_report(data, mode)
    if not redact:
        analysis = await _latest_analysis(session, engagement.id)
        data["analyst"] = _analyst_ctx(analysis)

    slug = engagement.name.lower().replace(" ", "-")[:40]
    tag = "client" if redact else "internal"

    if format == "json":
        return Response(
            render_json(data),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{slug}-{tag}.json"'},
        )
    if format == "pdf":
        try:
            pdf = render_pdf(data)
        except PdfUnavailable as exc:
            return flash_redirect("/reports", str(exc), "error")
        return Response(
            pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{slug}-{tag}.pdf"'},
        )
    return Response(render_html(data), media_type="text/html")


@router.post("/analyst/run", dependencies=[Depends(verify_csrf)])
async def run_analyst(
    user: CurrentUser, engagement: RequiredEngagement, session: DbSession
):
    try:
        await AnalystService().run(session, engagement)
    except AnalystError as exc:
        return flash_redirect("/reports", f"Analyst run failed: {exc}", "error")
    return flash_redirect("/reports", "Analyst assessment complete.", "success")
