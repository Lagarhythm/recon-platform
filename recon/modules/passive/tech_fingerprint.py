"""Technology fingerprinting (passive, PRD v2.1 §11.8, N10).

Matches a vendored, curated Wappalyzer-style corpus against every host
``probe_http`` confirmed live: response headers, cookies, the HTML body, and
``<script src>`` references. Emits ``tech`` attributes carrying
``name``/``version``/``categories``/``cpe`` - the ``cpe`` field is what lets a
future ``cve_correlate`` pass match web-app-level tech (not just
``port_scan``/``internetdb`` service banners) against the local CVE index.

No new data model: this reuses the same ``tech`` subject_type ``probe_http``
and ``http_analyzer`` already emit ad hoc header/cookie signals under, just
with a much larger, HTML/JS-aware corpus behind it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from recon.models.enums import ModulePhase
from recon.modules._live_hosts import live_hosts
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError, ScopeViolation

_CORPUS_PATH = Path(__file__).resolve().parents[1] / "_tech_fingerprints.json"
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_MAX_BODY_BYTES = 300_000


def _load_corpus() -> list[dict]:
    try:
        data = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data.get("technologies", [])


def _script_srcs(html: str) -> list[str]:
    return _SCRIPT_SRC_RE.findall(html)


def _cookie_names(headers) -> set[str]:  # noqa: ANN001
    names = set()
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        if name:
            names.add(name)
    return names


def match_technologies(
    corpus: list[dict], *, headers, cookies: set[str], html: str
) -> list[dict]:
    """Match ``corpus`` entries against one response. Returns a list of
    ``{"name", "version", "categories", "cpe", "evidence"}`` dicts, one per
    matched technology (never more than one row per technology)."""
    srcs = _script_srcs(html)
    hits: list[dict] = []

    for tech in corpus:
        version: str | None = None
        evidence: list[str] = []

        for hname, pattern in tech.get("headers", {}).items():
            value = headers.get(hname)
            if value is None:
                continue
            if not pattern:
                evidence.append(f"header:{hname}")
                continue
            m = re.search(pattern, value, re.IGNORECASE)
            if m:
                evidence.append(f"header:{hname}")
                if m.groups() and m.group(1):
                    version = version or m.group(1)

        for cname in tech.get("cookies", {}):
            if any(c == cname or c.startswith(cname) for c in cookies):
                evidence.append(f"cookie:{cname}")

        for pattern in tech.get("html", []):
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                evidence.append("html")
                if m.groups() and m.group(1):
                    version = version or m.group(1)

        for pattern in tech.get("script", []):
            for src in srcs:
                m = re.search(pattern, src, re.IGNORECASE)
                if m:
                    evidence.append("script")
                    if m.groups() and m.group(1):
                        version = version or m.group(1)
                    break

        if not evidence:
            continue

        cpe_base = tech.get("cpe")
        cpe = f"{cpe_base}:{version or '*'}:*:*:*:*:*:*:*" if cpe_base else None
        hits.append({
            "name": tech["name"],
            "version": version,
            "categories": tech.get("categories", []),
            "cpe": cpe,
            "evidence": evidence,
        })
    return hits


@register
class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"
    phase = ModulePhase.PASSIVE
    depends_on = ("probe_http",)
    description = "Vendored Wappalyzer-style corpus match on headers/cookies/HTML/JS"
    max_runtime_seconds = 20 * 60

    async def run(self, ctx: ModuleContext) -> None:
        corpus = _load_corpus()
        if not corpus:
            await ctx.add_error(
                subject_value=str(_CORPUS_PATH),
                summary=f"tech fingerprint corpus missing or empty: {_CORPUS_PATH}",
            )
            return

        hosts = sorted(await live_hosts(ctx))
        if not hosts:
            await ctx.progress("tech_fingerprint: no probe_http-confirmed live hosts")
            return

        await ctx.progress(f"tech_fingerprint: {len(hosts)} host(s)", count=len(hosts))
        for i, host in enumerate(hosts, start=1):
            ctx.check_alive()
            await self._fingerprint_host(ctx, host, corpus)
            await ctx.progress(
                f"tech_fingerprint: {i}/{len(hosts)}", current=i, total=len(hosts)
            )

    async def _fingerprint_host(
        self, ctx: ModuleContext, host: str, corpus: list[dict]
    ) -> None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except ScopeViolation:
                return
            except ReconRequestError:
                continue

            html = ""
            ctype = (resp.headers.get("content-type") or "").lower()
            if "html" in ctype or not ctype:
                try:
                    html = resp.text[:_MAX_BODY_BYTES]
                except Exception:  # noqa: BLE001 - decode issues are non-fatal
                    html = ""

            hits = match_technologies(
                corpus,
                headers=resp.headers,
                cookies=_cookie_names(resp.headers),
                html=html,
            )
            for hit in hits:
                await ctx.add_evidence(
                    subject_type="tech",
                    subject_value=hit["name"],
                    raw_data={
                        "url": url,
                        "name": hit["name"],
                        "version": hit["version"],
                        "categories": hit["categories"],
                        "cpe": hit["cpe"],
                        "evidence": hit["evidence"],
                        "source": "tech_fingerprint",
                    },
                    summary=f"{hit['name']}"
                            + (f" {hit['version']}" if hit["version"] else "")
                            + f" on {url}",
                )
            return  # one answering scheme is enough, same precedent as probe_http
