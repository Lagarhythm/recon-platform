"""Local CVE index refresh (PRD v2.1 §11.9, Part A) - CISA KEV + NVD API 2.0.

The ONLY outbound networking in the ``cve_correlate`` feature happens here, in
a standalone, out-of-band ``recon cve refresh`` operation - never at scan
time. This is deliberately not a ``ReconModule``: ``CVERecord`` is reference
data, not engagement-scoped, so there is no engagement/RoE/scope to gate
against and ``ctx.http`` (which requires exactly those) doesn't apply. Talks
to CISA/NVD with a bare ``httpx.AsyncClient`` instead.

No ``nvdlib`` dependency - matches this codebase's existing precedent
(``email_security`` hand-rolls SPF/DMARC parsing instead of adding
``checkdmarc``) of a minimal native fetch over a third-party wrapper library.
``httpx`` is already a direct dependency; nothing new was added for this.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.models.cve import CVEIndexMeta, CVERecord

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_PAGE_SIZE = 2000
# NVD's keyless public rate limit is 5 requests per rolling 30s window; sleep
# comfortably past 30/5=6s between requests to never trip it.
_NVD_REQUEST_INTERVAL = 6.5
#: CVSS v3.1 severity bands covering baseScore >= 7.0 (HIGH 7.0-8.9, CRITICAL
#: 9.0-10.0) - the NVD API only accepts one severity value per query, not a
#: numeric threshold, so "kev_high" makes one pass per band.
_HIGH_SEVERITIES = ("HIGH", "CRITICAL")


class CVEIndexError(RuntimeError):
    pass


async def refresh_index(
    session: AsyncSession,
    *,
    source: str = "local",
    client: httpx.AsyncClient | None = None,
) -> CVEIndexMeta:
    """Fetch CISA KEV plus NVD records and upsert into ``CVERecord``. Returns
    the updated ``CVEIndexMeta`` singleton.

    ``source`` (matches the ``recon cve refresh --source`` CLI flag and the
    ``CVEIndexMeta.source`` field, PRD §8.3):
      - ``"local"`` (default) - CISA KEV catalog union NVD records scored
        CVSS>=7 (HIGH/CRITICAL). Small, fast, covers what drives triage
        (PRD §11.9 decision C). Still a live CISA+NVD fetch, not offline -
        "local" names the resulting index size, not the network behaviour.
      - ``"nvd_api"`` - the complete NVD index, every severity. Much larger,
        many more paginated requests.

    Both fetches happen before anything is written - a failure partway
    through either one raises ``CVEIndexError`` and leaves the existing index
    untouched; the operator just re-runs ``recon cve refresh``.
    """
    if source not in ("local", "nvd_api"):
        raise CVEIndexError(f"unknown source: {source!r} (expected local|nvd_api)")

    own_client = client is None
    http = client or httpx.AsyncClient(timeout=30.0)
    try:
        kev_ids, feed_version = await _fetch_kev(http)
        severities = None if source == "nvd_api" else _HIGH_SEVERITIES
        records = await _fetch_nvd(http, severities=severities)
    finally:
        if own_client:
            await http.aclose()

    # KEV membership always wins even for a CVE the severity filter would
    # have excluded (e.g. an older CVE later re-scored below 7.0 but still on
    # the actively-exploited list) - a KEV-only hit still gets a bare record.
    known_ids = {r["cve_id"] for r in records}
    for cve_id in kev_ids - known_ids:
        records.append({
            "cve_id": cve_id, "cpe_matches": [], "references": [],
            "published": None, "last_modified": None,
            "cvss_v31_score": None, "cvss_v31_severity": None, "cvss_vector": None,
            "description": None,
        })
    for r in records:
        r["in_kev"] = r["cve_id"] in kev_ids

    for r in records:
        await session.merge(CVERecord(**r))
    await session.flush()

    meta = await session.get(CVEIndexMeta, "singleton")
    if meta is None:
        meta = CVEIndexMeta(id="singleton")
        session.add(meta)
    meta.source = source
    meta.last_refreshed = datetime.now(timezone.utc)
    meta.record_count = (
        await session.execute(select(func.count()).select_from(CVERecord))
    ).scalar_one()
    meta.feed_version = feed_version
    return meta


# --- CISA KEV -------------------------------------------------------------
async def _fetch_kev(http: httpx.AsyncClient) -> tuple[set[str], str | None]:
    try:
        resp = await http.get(_KEV_URL, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise CVEIndexError(f"CISA KEV fetch failed: {exc}") from exc
    ids = {
        v["cveID"].strip().upper()
        for v in (data.get("vulnerabilities") or [])
        if isinstance(v, dict) and v.get("cveID")
    }
    return ids, data.get("catalogVersion")


# --- NVD API 2.0 ------------------------------------------------------------
async def _fetch_nvd(
    http: httpx.AsyncClient, *, severities: tuple[str, ...] | None
) -> list[dict[str, Any]]:
    """Paginate the NVD API 2.0. One severity value per query (the API takes
    a single band, not a numeric threshold or a list) - one full paginated
    pass per requested severity, or one unfiltered pass for ``full``.
    Sleeps between every page to respect the keyless rate limit."""
    out: dict[str, dict[str, Any]] = {}
    passes: tuple[str | None, ...] = severities or (None,)
    for severity in passes:
        start_index = 0
        first = True
        while True:
            if not first:
                await asyncio.sleep(_NVD_REQUEST_INTERVAL)
            first = False
            params: dict[str, Any] = {
                "resultsPerPage": _NVD_PAGE_SIZE, "startIndex": start_index,
            }
            if severity:
                params["cvssV3Severity"] = severity
            try:
                resp = await http.get(_NVD_URL, params=params, timeout=30.0)
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise CVEIndexError(
                    f"NVD fetch failed (severity={severity!r}, startIndex={start_index}): {exc}"
                ) from exc
            items = data.get("vulnerabilities") or []
            for item in items:
                rec = _parse_nvd_cve(item.get("cve") or {})
                if rec:
                    out[rec["cve_id"]] = rec
            total = data.get("totalResults", 0)
            # Advance by what was actually returned, not the requested page
            # size - a short/empty page (server truncation, tail of results)
            # must not be misread as "still more to fetch" and loop forever.
            start_index += len(items) if items else _NVD_PAGE_SIZE
            if not items or start_index >= total:
                break
    return list(out.values())


def _parse_nvd_cve(cve: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    desc = next(
        (d.get("value") for d in (cve.get("descriptions") or []) if d.get("lang") == "en"),
        None,
    )
    refs = [
        {"url": r["url"], "source": r.get("source"), "tags": r.get("tags") or []}
        for r in (cve.get("references") or []) if r.get("url")
    ]
    score, severity, vector = _primary_cvss_v31(cve.get("metrics") or {})
    return {
        "cve_id": cve_id,
        "published": _parse_nvd_dt(cve.get("published")),
        "last_modified": _parse_nvd_dt(cve.get("lastModified")),
        "cpe_matches": _flatten_cpe_matches(cve.get("configurations") or []),
        "cvss_v31_score": score,
        "cvss_v31_severity": severity,
        "cvss_vector": vector,
        "description": desc,
        "references": refs,
    }


def _primary_cvss_v31(
    metrics: dict[str, Any],
) -> tuple[float | None, str | None, str | None]:
    entries = metrics.get("cvssMetricV31") or []
    if not entries:
        return None, None, None
    primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
    data = primary.get("cvssData") or {}
    return data.get("baseScore"), data.get("baseSeverity"), data.get("vectorString")


def _flatten_cpe_matches(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for config in configurations:
        for node in config.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                criteria = m.get("criteria")
                if not criteria:
                    continue
                # cpe:2.3:<part>:<vendor>:<product>:<version>:...
                parts = criteria.split(":")
                out.append({
                    "cpe": criteria,
                    "part": parts[2] if len(parts) > 2 else None,
                    "vendor": parts[3] if len(parts) > 3 else None,
                    "product": parts[4] if len(parts) > 4 else None,
                    "version_start": (
                        m.get("versionStartIncluding") or m.get("versionStartExcluding")
                    ),
                    "version_end": (
                        m.get("versionEndExcluding") or m.get("versionEndIncluding")
                    ),
                    "vulnerable": bool(m.get("vulnerable", True)),
                })
    return out


def _parse_nvd_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # NVD timestamps are naive UTC, e.g. "2024-01-01T00:00:00.000"
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
