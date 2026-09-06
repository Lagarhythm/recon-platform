"""This-run DNS answers, ``hostname -> {canonical ip}``.

The single reader used by both D0 (``recon/orchestrator/d0.py``) and the
permit-backed ``port_scan`` path. Only the passive ``dns`` module's
``dns_record`` Evidence for the given run counts - no correlated Asset, no prior
run, nothing else may stand in for a fresh resolution (rebind / stale-answer
defence).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.netscope import NetscopeError, canonical_ip
from recon.models.evidence import Evidence

_A_RECORD_TYPES = {"A", "AAAA"}


async def run_dns_answers(
    session: AsyncSession, scan_run_id: str
) -> dict[str, set[str]]:
    rows = (
        await session.execute(
            select(Evidence).where(
                Evidence.scan_run_id == scan_run_id,
                Evidence.source_module == "dns",
                Evidence.subject_type == "dns_record",
            )
        )
    ).scalars().all()
    answers: dict[str, set[str]] = {}
    for ev in rows:
        data = ev.raw_data or {}
        if data.get("rtype") not in _A_RECORD_TYPES:
            continue
        name = str(data.get("name", "")).strip().lower().rstrip(".")
        raw_value = str(data.get("value", "")).strip()
        if not name or not raw_value:
            continue
        try:
            ip = canonical_ip(raw_value)
        except NetscopeError:
            continue
        answers.setdefault(name, set()).add(ip)
    return answers
