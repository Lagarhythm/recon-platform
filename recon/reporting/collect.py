"""Assemble the full report data structure from the Asset Graph."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon import __version__
from recon.models.asset import Asset, AssetRelationship
from recon.models.audit import AuditLogEntry
from recon.models.engagement import Engagement
from recon.models.enums import AssetType, FindingPolarity, InterestLevel
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


async def build_report_data(session: AsyncSession, engagement: Engagement) -> dict[str, Any]:
    assets = list(
        (
            await session.execute(
                select(Asset)
                .where(Asset.engagement_id == engagement.id)
                .order_by(Asset.interest_level.desc(), Asset.type, Asset.value)
            )
        ).scalars()
    )
    asset_by_id = {a.id: a for a in assets}

    rels = list(
        (
            await session.execute(
                select(AssetRelationship).where(
                    AssetRelationship.engagement_id == engagement.id
                )
            )
        ).scalars()
    )
    evidence = list(
        (
            await session.execute(
                select(Evidence)
                .where(Evidence.engagement_id == engagement.id, Evidence.is_error.is_(False))
                .order_by(Evidence.discovered_at)
            )
        ).scalars()
    )
    ev_by_asset: dict[str, list[Evidence]] = {}
    for e in evidence:
        if e.asset_id:
            ev_by_asset.setdefault(e.asset_id, []).append(e)

    runs = list(
        (
            await session.execute(
                select(ScanRun)
                .where(ScanRun.engagement_id == engagement.id)
                .order_by(ScanRun.created_at)
            )
        ).scalars()
    )
    module_runs = list((await session.execute(select(ScanModuleRun).where(
        ScanModuleRun.engagement_id == engagement.id))).scalars())
    modules_by_run: dict[str, list[dict[str, Any]]] = {}
    for m in module_runs:
        outcome = "failed" if m.status.value == "failed" else (
            "partial" if m.error_count else ("completed-no-evidence" if m.status.value == "completed" and not m.evidence_count else m.status.value))
        modules_by_run.setdefault(m.scan_run_id, []).append({"name": m.module_name, "status": outcome,
            "reason": m.error if outcome == "skipped" else None,
            "skip_reason": m.skip_reason.value if m.skip_reason is not None else None,
            "error_count": m.error_count, "evidence_count": m.evidence_count,
            "coverage_metadata": m.coverage_metadata or {}})
    audit_total = (
        await session.execute(
            select(func.count()).select_from(AuditLogEntry).where(
                AuditLogEntry.engagement_id == engagement.id
            )
        )
    ).scalar_one()
    override_count = (
        await session.execute(
            select(func.count()).select_from(AuditLogEntry).where(
                AuditLogEntry.engagement_id == engagement.id,
                AuditLogEntry.override_used.is_(True),
            )
        )
    ).scalar_one()

    def _asset_dict(a: Asset) -> dict[str, Any]:
        return {
            "id": a.id,
            "type": a.type.value,
            "value": a.value,
            "confidence": round(a.confidence_score, 2),
            "interest": a.interest_level.value,
            "scope": a.in_scope_status.value,
            "first_seen": _iso(a.first_seen),
            "last_seen": _iso(a.last_seen),
            "evidence": [
                {
                    "id": e.id,
                    "module": e.source_module,
                    "subject_type": e.subject_type,
                    "polarity": e.polarity.value,
                    "summary": e.summary,
                    "discovered_at": _iso(e.discovered_at),
                    "raw_data": e.raw_data,
                    "request_metadata": e.request_metadata,
                }
                for e in ev_by_asset.get(a.id, [])
            ],
        }

    findings = [
        _asset_dict(a)
        for a in assets
        if a.type is AssetType.FINDING
        or a.interest_level in (InterestLevel.NOTABLE, InterestLevel.HIGH_VALUE)
    ]
    negative = [
        {"summary": e.summary, "module": e.source_module, "subject_type": e.subject_type}
        for e in evidence
        if e.polarity is FindingPolarity.ABSENT
    ]

    by_type: dict[str, int] = {}
    for a in assets:
        by_type[a.type.value] = by_type.get(a.type.value, 0) + 1

    return {
        "meta": {
            "tool_version": __version__,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "engagement": {
            "name": engagement.name,
            "client": engagement.client_name,
            "status": engagement.status.value,
            "roe_hash": engagement.roe_config_hash,
            "authorized_window": {
                "start": _iso(engagement.authorized_window_start),
                "end": _iso(engagement.authorized_window_end),
            },
            "roe_yaml": engagement.roe_config_yaml,  # redacted out for client mode
        },
        "summary": {
            "asset_count": len(assets),
            "by_type": by_type,
            "finding_count": len(findings),
            "high_value_count": sum(
                1 for a in assets if a.interest_level is InterestLevel.HIGH_VALUE
            ),
            "scan_runs": len(runs),
            "audit_entries": audit_total,
            "out_of_scope_overrides": override_count,
            "incomplete_coverage": any(m["status"] in ("failed", "partial", "skipped") for ms in modules_by_run.values() for m in ms),
        },
        "findings": findings,
        "negative_findings": negative,
        "assets": [_asset_dict(a) for a in assets],
        "relationships": [
            {
                "source": asset_by_id[r.source_asset_id].value
                if r.source_asset_id in asset_by_id else r.source_asset_id,
                "target": asset_by_id[r.target_asset_id].value
                if r.target_asset_id in asset_by_id else r.target_asset_id,
                "type": r.relationship_type.value,
            }
            for r in rels
        ],
        "scan_runs": [
            {
                "id": r.id,
                "status": r.status.value,
                "modules": r.modules_requested,
                "modules_completed": r.modules_completed,
                "started_at": _iso(r.started_at),
                "completed_at": _iso(r.completed_at),
                "module_outcomes": modules_by_run.get(r.id, []),
                "coverage_note": "Incomplete coverage: one or more modules failed, returned partial results, or were skipped; zero findings are not a clean result."
                    if any(m["status"] in ("failed", "partial", "skipped") for m in modules_by_run.get(r.id, [])) else None,
            }
            for r in runs
        ],
    }
