"""Wayback Machine (OSINT).

Pulls every URL the Internet Archive has ever crawled under a seed / in-scope
domain (the free CDX API - no key) and mines it for: subdomains that no longer
resolve, documents / dumps / config files that have since been removed, and
paths that look interesting (admin, login, api, backup, ...).
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import fetch_json, interesting_path, org_targets
from recon.modules.registry import register

_CDX = (
    "http://web.archive.org/cdx/search/cdx?url={dom}/*&output=json"
    "&collapse=urlkey&limit=5000&fl=original,timestamp,statuscode,mimetype"
)
import re as _re

# matched against whole path segments (so "/skills/dev..." does NOT hit "dev")
_INTEREST = _re.compile(
    r"(^|/)("
    r"admin|adminer|login|signin|logout|internal|intranet|staging|preprod|"
    r"backup|backups|api|apis|graphql|config|conf|configs|"
    r"secret|secrets|private|priv|upload|uploads|download|downloads|phpinfo|"
    r"wp-admin|wp-login|jenkins|gitlab|portal|dashboard|debug|"
    r"\.git|\.svn|\.env|\.htpasswd|actuator|swagger|"
    r"phpmyadmin|server-status"
    r")(/|$|\.)",
    _re.IGNORECASE,
)
# framework / build noise never worth surfacing
_NOISE = _re.compile(r"/(_next|_nuxt|__nuxt|static/chunks|node_modules|cdn-cgi)/", _re.IGNORECASE)
# a software project's own published archive (release tarballs, installers) - not
# an exposure, and there can be hundreds
_RELEASE = _re.compile(
    r"/(dist|releases?|download[s]?|builds?|packages?|artifacts?|archive)/", _re.IGNORECASE
)
_MAX_EMIT = 2000
_MAX_DOCS_PER_HOST = 40   # a real leak is in the first few; the rest is inventory noise


@register
class WaybackModule(ReconModule):
    name = "wayback"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "Internet Archive: historical URLs, dead subdomains, removed documents"
    max_runtime_seconds = 10 * 60

    async def run(self, ctx: ModuleContext) -> None:
        _, domains = org_targets(ctx)
        if not domains:
            await ctx.progress("wayback: no seed / in-scope domains in the RoE")
            return

        for i, domain in enumerate(sorted(domains), start=1):
            ctx.check_alive()
            await ctx.progress(f"wayback: {domain}", current=i - 1, total=len(domains))
            await self._domain(ctx, domain)
        await ctx.progress("wayback done", current=len(domains), total=len(domains))

    async def _domain(self, ctx: ModuleContext, domain: str) -> None:
        rows = await fetch_json(
            ctx, _CDX.format(dom=quote(domain)), subject=domain, source="Wayback",
            timeout=60.0,
        )
        if not isinstance(rows, list) or len(rows) < 2:
            if rows == []:
                await ctx.progress(f"wayback: nothing archived for {domain}")
            return

        header, *data = rows
        idx = {name: i for i, name in enumerate(header)}
        seen_hosts: set[str] = set()
        seen_docs: set[str] = set()
        host_docs: dict[str, int] = {}
        emitted = 0
        for row in data:
            if emitted >= _MAX_EMIT:
                break
            try:
                original = row[idx["original"]]
                mimetype = row[idx.get("mimetype", -1)] if "mimetype" in idx else ""
            except (IndexError, KeyError):
                continue
            parts = urlsplit(original)
            host = (parts.hostname or "").lower().strip(".")
            if not host or not (host == domain or host.endswith("." + domain)):
                continue
            if _NOISE.search(parts.path):
                continue

            # a subdomain we haven't recorded
            if host != domain and host not in seen_hosts:
                seen_hosts.add(host)
                await ctx.add_evidence(
                    subject_type="subdomain", subject_value=host,
                    raw_data={"source": "Wayback", "example_url": original},
                    summary=f"{host} - seen in the Internet Archive (historical)",
                )
                emitted += 1

            ext = interesting_path(original)
            is_doc = ext or (mimetype and mimetype.split(";")[0] in _DOC_MIMES)
            path = parts.path.lower()
            if is_doc and original not in seen_docs and not _RELEASE.search(path):
                seen_docs.add(original)
                if host_docs.get(host, 0) < _MAX_DOCS_PER_HOST:
                    host_docs[host] = host_docs.get(host, 0) + 1
                    await ctx.add_evidence(
                        subject_type="document", subject_value=original,
                        raw_data={"source": "Wayback", "type": ext or mimetype,
                                  "timestamp": _ts(row, idx), "interest": "notable"},
                        summary=f"archived document: {original} ({ext or mimetype})",
                    )
                    emitted += 1
            elif _INTEREST.search(path) and original not in seen_docs:
                seen_docs.add(original)
                await ctx.add_evidence(
                    subject_type="url", subject_value=original,
                    raw_data={"source": "Wayback", "timestamp": _ts(row, idx),
                              "interest": "notable"},
                    summary=f"archived interesting path: {original}",
                )
                emitted += 1

        await ctx.progress(
            f"wayback {domain}: {len(seen_hosts)} host(s), {len(seen_docs)} doc/url(s)"
        )


_DOC_MIMES = {
    "application/pdf", "application/zip", "application/x-gzip", "text/csv",
    "application/vnd.ms-excel", "application/msword", "application/sql",
    "application/octet-stream",
}


def _ts(row: list, idx: dict) -> str | None:
    i = idx.get("timestamp")
    return row[i] if i is not None and i < len(row) else None
