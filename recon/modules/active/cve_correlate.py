"""CVE correlation (active, PRD v2.1 §11.9, Part B).

Turns the version data the tool already collects into "this version is
affected by CVE-XXXX-YYYY" findings. Never an exploit attempt - a data
cross-reference. Three sources, in the PRD's resolution order:

  1. Shodan InternetDB's ``vulns`` - already fetched by the ``internetdb``
     module (Wave 1) as ``subject_type="cve"`` evidence. Zero extra work;
     this pass just attaches the ``affects`` graph edge InternetDB's own
     comment flags as missing.
  2. The local ``CVERecord`` index (``recon cve refresh``, Part A) - CPE/
     product/version match against ``service`` evidence from ``port_scan``
     and ``internetdb``. No network call.
  3. OSV.dev (keyless) - for the small set of client-side libraries
     ``js_analyzer``/``http_analyzer`` can name confidently enough to map to
     an npm package (``tech`` evidence). The one live call in this module;
     narrowly scoped to library correlation per the spec.

``CVERecord`` is reference data, not engagement-scoped (see
``recon.models.cve``), so it's read with its own ``session_scope()`` rather
than through ``ModuleContext`` (which is engagement-bound) - the same
separation Part A's CLI code already uses.

Degradation: no local index yet, or InternetDB/OSV find nothing -> warn,
emit nothing, don't fail the run (PRD).
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select

from recon.db import session_scope
from recon.models.cve import CVERecord
from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

_OSV_URL = "https://api.osv.dev/v1/query"
_TOP_N_PER_TARGET = 5

# js_analyzer/http_analyzer name their tech fingerprints as a display name,
# e.g. "jQuery"/"React" - only map the ones confidently identifiable as an
# npm package. Anything else is skipped, not guessed.
_NPM_PACKAGE_NAMES = {
    "react": "react",
    "vue": "vue",
    "angular": "@angular/core",
    "jquery": "jquery",
    "webpack": "webpack",
}


def _cvss_interest(score: float | None, *, in_kev: bool) -> str:
    if in_kev or (score is not None and score >= 9.0):
        return "high_value"
    return "notable"


def _version_key(v: str) -> tuple[int, ...] | None:
    """A best-effort dotted-numeric sort key ('1.24.3' -> (1, 24, 3)). Not a
    full semver/CPE version comparator - no ``packaging`` dependency was
    added for this (matches the codebase's native-parser precedent). Returns
    ``None`` for anything that doesn't parse as dotted integers, which
    callers treat as "cannot determine" and match permissively rather than
    silently drop a possible hit."""
    parts = re.findall(r"\d+", v or "")
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def _version_in_range(version: str, start: str | None, end: str | None) -> bool:
    """True if ``version`` is within [start, end) - or if either bound can't
    be compared, in which case this is permissive (include, don't drop a
    possible match) rather than strict."""
    vkey = _version_key(version)
    if vkey is None:
        return True
    if start:
        skey = _version_key(start)
        if skey is not None and vkey < skey:
            return False
    if end:
        ekey = _version_key(end)
        if ekey is not None and vkey >= ekey:
            return False
    return True


def _product_matches(cpe_match: dict[str, Any], product: str) -> bool:
    cpe_product = (cpe_match.get("product") or "").replace("_", " ").lower()
    product = product.lower()
    if not cpe_product or not product:
        return False
    return cpe_product in product or product in cpe_product


@register
class CveCorrelateModule(ReconModule):
    name = "cve_correlate"
    phase = ModulePhase.ACTIVE
    depends_on = ("port_scan",)
    description = "Match service/tech versions against InternetDB vulns, the local CVE index, and OSV.dev"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        await self._link_internetdb_cves(ctx)

        index = await self._load_index()
        if not index:
            await ctx.progress(
                "cve_correlate: no local CVE index - run `recon cve refresh` "
                "first. InternetDB linking still ran; local/OSV matching skipped."
            )
        else:
            await self._match_local_index(ctx, index)

        await self._match_osv(ctx)

    # --- 1. InternetDB vulns -> affects edges ---------------------------
    async def _link_internetdb_cves(self, ctx: ModuleContext) -> None:
        cve_evs = await ctx.known_evidence("cve")
        for ev in cve_evs:
            raw = ev.raw_data or {}
            if raw.get("source") != "internetdb":
                continue  # only internetdb's own rows carry ip/ports this way
            ip = raw.get("ip")
            ports = [p for p in (raw.get("ports") or []) if p]
            if not ip or not ports:
                continue
            await ctx.add_evidence(
                subject_type="cve",
                subject_value=ev.subject_value,
                raw_data={
                    "source": "cve_correlate", "linked_from": "internetdb",
                    "ip": ip, "ports": ports,
                },
                summary=f"{ev.subject_value} affects {len(ports)} service(s) on {ip} "
                        f"(Shodan InternetDB)",
                relationships=[
                    {"type": "affects", "target_type": "service",
                     "target_value": f"{ip}:{port}"}
                    for port in ports
                ],
            )

    # --- 2. local CVERecord index ----------------------------------------
    @staticmethod
    async def _load_index() -> list[CVERecord]:
        async with session_scope() as session:
            return list((await session.execute(select(CVERecord))).scalars())

    async def _match_local_index(self, ctx: ModuleContext, index: list[CVERecord]) -> None:
        service_evs = await ctx.known_evidence("service")
        for ev in service_evs:
            raw = ev.raw_data or {}
            host = raw.get("host")
            port = raw.get("port")
            product = raw.get("product") or raw.get("name")
            version = raw.get("version")
            if not host or not port or not product:
                continue
            ctx.check_alive()
            hits = self._cpe_matches(index, product, version)
            for rec in hits[:_TOP_N_PER_TARGET]:
                await self._emit_cve(
                    ctx, rec, target=f"{host}:{port}", target_type="service",
                    context=f"{product} {version or '(unknown version)'} on {host}:{port}",
                )

    def _cpe_matches(
        self, index: list[CVERecord], product: str, version: str | None
    ) -> list[CVERecord]:
        hits = []
        for rec in index:
            for cpe_match in rec.cpe_matches or []:
                if not _product_matches(cpe_match, product):
                    continue
                if version and not _version_in_range(
                    version, cpe_match.get("version_start"), cpe_match.get("version_end")
                ):
                    continue
                hits.append(rec)
                break
        hits.sort(key=lambda r: (r.cvss_v31_score or 0.0), reverse=True)
        return hits

    # --- 3. OSV.dev for js/http tech hits --------------------------------
    async def _match_osv(self, ctx: ModuleContext) -> None:
        tech_evs = await ctx.known_evidence("tech")
        seen: set[tuple[str, str]] = set()
        for ev in tech_evs:
            raw = ev.raw_data or {}
            name = raw.get("name")
            version = raw.get("version")
            if not name or not version:
                continue
            pkg = _NPM_PACKAGE_NAMES.get(name.strip().lower())
            if not pkg or (pkg, version) in seen:
                continue
            seen.add((pkg, version))
            ctx.check_alive()
            await self._osv_lookup(ctx, ev, pkg, version)

    async def _osv_lookup(self, ctx: ModuleContext, ev, pkg: str, version: str) -> None:  # noqa: ANN001
        try:
            resp = await ctx.http.request(
                "POST", _OSV_URL, is_target=False, timeout=15.0,
                json={"package": {"name": pkg, "ecosystem": "npm"}, "version": version},
            )
        except Exception as exc:  # noqa: BLE001 - non-fatal, per-package
            await ctx.add_error(
                subject_value=f"{pkg}@{version}",
                summary=f"OSV.dev lookup failed for {pkg}@{version}: {type(exc).__name__}",
            )
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except ValueError:
            return
        vulns = data.get("vulns") or []
        target = (ev.raw_data or {}).get("url") or (ev.raw_data or {}).get("host")
        for v in vulns[:_TOP_N_PER_TARGET]:
            cve_id = next(
                (a for a in ([v.get("id")] + list(v.get("aliases") or []))
                 if a and a.startswith("CVE-")),
                None,
            )
            if not cve_id:
                continue  # OSV/GHSA-only advisory, no CVE to key on
            vector, severity_label = self._osv_severity(v)
            await ctx.add_evidence(
                subject_type="cve", subject_value=cve_id,
                raw_data={
                    "source": "cve_correlate", "matched_via": "osv.dev",
                    "package": pkg, "version": version, "osv_id": v.get("id"),
                    "cvss_vector": vector, "cvss_severity": severity_label,
                    "interest": (
                        "high_value" if severity_label == "CRITICAL" else "notable"
                    ),
                },
                summary=f"{cve_id} affects {pkg}@{version} (OSV.dev)",
                relationships=(
                    [{"type": "affects", "target_type": "url", "target_value": target}]
                    if target else None
                ),
            )

    @staticmethod
    def _osv_severity(vuln: dict[str, Any]) -> tuple[str | None, str | None]:
        """OSV gives a raw CVSS vector string, not a precomputed base score -
        deriving a numeric score from a vector means implementing the full
        CVSS v3.1 scoring formula, which this module doesn't attempt (too
        easy to get subtly wrong for a security tool, and not worth the risk
        for a "notable vs. high_value" triage bump). Uses GHSA's own
        ``database_specific.severity`` label when OSV provides one; the raw
        vector is still recorded for the analyst either way."""
        vector = next(
            (sev.get("score") for sev in vuln.get("severity") or []
             if sev.get("type") == "CVSS_V3" and sev.get("score")),
            None,
        )
        label = (vuln.get("database_specific") or {}).get("severity")
        return vector, label

    # --- shared emit helper ------------------------------------------
    async def _emit_cve(
        self, ctx: ModuleContext, rec: CVERecord, *, target: str, target_type: str, context: str
    ) -> None:
        await ctx.add_evidence(
            subject_type="cve", subject_value=rec.cve_id,
            raw_data={
                "source": "cve_correlate", "matched_via": "local_index",
                "target": target, "cvss_score": rec.cvss_v31_score,
                "cvss_severity": rec.cvss_v31_severity, "in_kev": rec.in_kev,
                "interest": _cvss_interest(rec.cvss_v31_score, in_kev=rec.in_kev),
            },
            summary=f"{rec.cve_id} ({rec.cvss_v31_severity or 'unknown'}"
                    f"{' KEV' if rec.in_kev else ''}) matches {context}",
            relationships=[
                {"type": "affects", "target_type": target_type, "target_value": target},
            ],
        )
