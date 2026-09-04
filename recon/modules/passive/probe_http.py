"""HTTP liveness probe (passive).

The bridge from "a name/IP was discovered" to "something actually answers HTTP
there". For every known host it probes ``https://`` then ``http://``, follows
the audited redirect chain, and records the final status, page title, ``Server``
banner and scheme.

Its ``url`` + ``service`` evidence is the **input filter** for everything
downstream - ``crawler``, ``js_analyzer``, ``screenshot``, and the active phase
all work from live URLs, not from the raw discovery list.

Distinct from ``http_analyzer`` (which digs into security-header / TLS / cookie
posture on ``/``): this one just answers "is it up, and where does it land".
"""

from __future__ import annotations

import asyncio
import re

from recon.models.enums import ModulePhase, ScopeStatus
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.passive.http_analyzer import _fingerprints
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError, ScopeViolation

_SCHEMES = ("https", "http")
_DEFAULT_PORT = {"https": 443, "http": 80}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MAX_TITLE_BYTES = 200_000  # only read this much of the body looking for <title>


def _title(body: str) -> str | None:
    m = _TITLE_RE.search(body[:_MAX_TITLE_BYTES])
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:300] or None


@register
class ProbeHTTPModule(ReconModule):
    name = "probe_http"
    phase = ModulePhase.PASSIVE
    depends_on = ("dns", "ct_subdomains")
    description = "Probe HTTP(S) liveness on every known host: status, title, redirect target, scheme"
    max_runtime_seconds = 20 * 60

    async def run(self, ctx: ModuleContext) -> None:
        hosts = sorted({
            h.strip().lower().strip(".")
            for h in await ctx.known_values("subdomain", "domain", "ip")
            if h and h.strip()
        })
        # Never probe an EXCLUDED host; FLAGGED only with an override (the HTTP
        # client enforces this too, but skipping up front avoids the audit noise).
        targets = [
            h for h in hosts
            if ctx.scope.classify(h).status is not ScopeStatus.EXCLUDED
            and not (
                ctx.scope.classify(h).status is ScopeStatus.FLAGGED
                and not ctx.allow_out_of_scope
            )
        ]
        if not targets:
            await ctx.progress("probe_http: no in-scope hosts discovered yet")
            return

        concurrency = max(1, min(20, ctx.roe.rate_limits.max_concurrent_connections))
        sem = asyncio.Semaphore(concurrency)
        await ctx.progress(
            f"probe_http: {len(targets)} host(s) x {len(_SCHEMES)} scheme(s)",
            count=len(targets),
        )

        async def _one(host: str) -> None:
            async with sem:
                ctx.check_alive()
                await self._probe_host(ctx, host)

        for start in range(0, len(targets), concurrency):
            ctx.check_alive()
            batch = targets[start : start + concurrency]
            await asyncio.gather(*(_one(h) for h in batch))
            await ctx.progress(
                f"probe_http: {min(start + concurrency, len(targets))}/{len(targets)}",
                current=min(start + concurrency, len(targets)), total=len(targets),
            )

    async def _probe_host(self, ctx: ModuleContext, host: str) -> None:
        for scheme in _SCHEMES:
            url = f"{scheme}://{host}/"
            try:
                resp = await ctx.http.get(url, follow_redirects=True)
            except ScopeViolation:
                return  # out of scope; the client already audited the block
            except ReconRequestError as exc:
                # A plain connection refusal / no-route just means nothing is
                # listening there - expected when probing a big discovery list,
                # stay quiet. A *timeout* is worth a note (slow or filtered).
                if "timeout" in str(exc).lower():
                    await ctx.add_error(
                        subject_value=url,
                        summary=f"{scheme} probe timed out for {host}",
                        raw_data={"url": url, "error": "timeout", "source": "probe_http"},
                    )
                continue  # try the other scheme

            try:
                final_url = str(resp.url)
            except RuntimeError:  # response built without a request (test doubles)
                final_url = url
            status = resp.status_code
            server = resp.headers.get("Server")
            ctype = (resp.headers.get("content-type") or "").lower()
            title = None
            if "html" in ctype or not ctype:
                try:
                    title = _title(resp.text)
                except Exception:  # noqa: BLE001 - decode/parse issues are non-fatal
                    title = None

            await ctx.add_evidence(
                subject_type="url",
                subject_value=url,
                raw_data={
                    "source": "probe_http", "scheme": scheme, "status": status,
                    "title": title, "final_url": final_url, "server": server,
                    "live": True,
                },
                summary=f"{url} -> {status}"
                        + (f" ({title})" if title else "")
                        + (f" -> {final_url}" if final_url != url else ""),
            )
            await ctx.add_evidence(
                subject_type="service",
                subject_value=f"{host}:{_DEFAULT_PORT[scheme]}",
                raw_data={
                    "source": "probe_http", "host": host,
                    "port": _DEFAULT_PORT[scheme], "proto": "tcp", "scheme": scheme,
                },
                summary=f"{host}:{_DEFAULT_PORT[scheme]} answers {scheme.upper()}",
                relationships=(
                    [{"type": "hosts", "target_type": "ip", "target_value": host}]
                    if _looks_like_ip(host) else None
                ),
            )
            if final_url != url:
                await ctx.add_evidence(
                    subject_type="redirect",
                    subject_value=url,
                    raw_data={"url": url, "location": final_url, "status": status,
                              "source": "probe_http"},
                    summary=f"{url} redirects to {final_url}",
                )
            for name, version, ev_src in _fingerprints(resp.headers):
                await ctx.add_evidence(
                    subject_type="tech",
                    subject_value=name,
                    raw_data={"url": url, "tech": name, "version": version,
                              "evidence": ev_src, "source": "probe_http"},
                    summary=f"{name}{('/' + version) if version else ''} on {url} ({ev_src})",
                )

            # https answered - the canonical live endpoint is found, don't also
            # spend a request probing http:// for the same host.
            if scheme == "https":
                return


def _looks_like_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
