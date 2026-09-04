"""Keyless historical/indexed URL collection (OSINT)."""

from __future__ import annotations

import json
from urllib.parse import quote, urlsplit

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import fetch_json, org_targets
from recon.modules.registry import register

_MAX_PER_SOURCE = 5_000


def _in_domain(url: str, domain: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower().strip(".")
    except ValueError:
        return False
    return host == domain or host.endswith("." + domain)


@register
class PassiveURLsModule(ReconModule):
    name = "passive_urls"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "Collect historical URLs from Wayback, Common Crawl, OTX, and urlscan"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        _, domains = org_targets(ctx)
        if not domains:
            await ctx.progress("passive_urls: no seed / in-scope domains")
            return
        for done, domain in enumerate(sorted(domains), start=1):
            ctx.check_alive()
            found: dict[str, set[str]] = {}
            for source, urls in await self._sources(ctx, domain):
                for url in urls[:_MAX_PER_SOURCE]:
                    if _in_domain(url, domain):
                        found.setdefault(url, set()).add(source)
            for url, sources in sorted(found.items()):
                await ctx.add_evidence(
                    subject_type="url", subject_value=url,
                    raw_data={"source": "passive_urls", "sources": sorted(sources),
                              "pivot": domain},
                    summary=f"indexed URL ({', '.join(sorted(sources))}): {url}",
                )
            await ctx.progress(f"passive_urls: {domain} -> {len(found)} URL(s)", current=done, total=len(domains))

    async def _sources(self, ctx: ModuleContext, domain: str) -> list[tuple[str, list[str]]]:
        results: list[tuple[str, list[str]]] = []
        cdx = await fetch_json(ctx,
            f"https://web.archive.org/cdx/search/cdx?url={quote(domain)}/*&output=json&fl=original&collapse=urlkey&limit=5000",
            subject=domain, source="Wayback", timeout=60.0)
        if isinstance(cdx, list):
            results.append(("wayback", [r[0] for r in cdx[1:] if isinstance(r, list) and r]))
        cc = await self._commoncrawl(ctx, domain)
        if isinstance(cc, list):
            results.append(("commoncrawl", [str(r.get("url")) for r in cc if isinstance(r, dict) and r.get("url")]))
        otx = await fetch_json(ctx,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/url_list?limit=5000&page=1",
            subject=domain, source="AlienVault OTX")
        if isinstance(otx, dict):
            rows = otx.get("url_list") or otx.get("url_list", {}).get("url_list", [])
            if isinstance(rows, list):
                results.append(("otx", [str(r.get("url")) for r in rows if isinstance(r, dict) and r.get("url")]))
        scan = await fetch_json(ctx,
            f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=10000",
            subject=domain, source="urlscan")
        if isinstance(scan, dict) and isinstance(scan.get("results"), list):
            results.append(("urlscan", [str(r.get("page", {}).get("url")) for r in scan["results"]
                                        if isinstance(r, dict) and isinstance(r.get("page"), dict) and r["page"].get("url")]))
        return results

    async def _commoncrawl(self, ctx: ModuleContext, domain: str) -> list[dict] | None:
        """Common Crawl emits NDJSON (not a JSON document) in production."""
        url = ("https://index.commoncrawl.org/CC-MAIN-2025-30-index?"
               f"url=*.{quote(domain)}/*&output=json")
        try:
            response = await ctx.http.request("GET", url, is_target=False, timeout=60.0)
        except Exception as exc:  # noqa: BLE001
            await ctx.add_error(subject_value=domain,
                                summary=f"Common Crawl request failed: {type(exc).__name__}",
                                raw_data={"source": "Common Crawl", "url": url, "error": str(exc)[:300]})
            return None
        if response.status_code != 200:
            await ctx.add_error(subject_value=domain,
                                summary=f"Common Crawl returned HTTP {response.status_code}",
                                raw_data={"source": "Common Crawl", "url": url, "status": response.status_code})
            return None
        try:
            parsed = response.json()
            if isinstance(parsed, list):
                return [row for row in parsed if isinstance(row, dict)]
        except (json.JSONDecodeError, ValueError):
            pass
        rows: list[dict] = []
        for line in response.text.splitlines():
            ctx.check_alive()
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        if not rows and response.text.strip():
            await ctx.add_error(subject_value=domain, summary="Common Crawl returned invalid NDJSON",
                                raw_data={"source": "Common Crawl", "url": url})
        return rows
