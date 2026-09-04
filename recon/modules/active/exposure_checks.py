"""Exposure checks (active, PRD v2.1 §11.15, N15).

Curated unauthenticated presence checks against every in-scope web root:
``.git``/``.env``/``.svn`` metadata leaks, Spring Boot actuator endpoints,
swagger/openapi docs, admin panels, backup files, and GraphQL introspection
reachability. Detects *presence only* - it never authenticates, submits a
form, or attempts exploitation; the one non-GET request (GraphQL) sends a
read-only introspection query purely to check whether introspection is
reachable, the same "presence" signal as every other check here.

Full scope gate (``ctx.known_assets(..., in_scope_only=not ctx.allow_out_of_scope)``,
same as ``dir_fuzz``), runs post-checkpoint like every other active-phase
module. Reuses ``dir_fuzz``'s soft-404 cluster filter per host: with only
~20 curated paths per root, a handful of identical-signature responses is a
strong catch-all signal even at a much smaller cluster size than the
wordlist-scale filter uses.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from recon.models.enums import ModulePhase, ScopeStatus
from recon.modules._live_hosts import probed_hosts
from recon.modules._soft404 import filter_soft_404
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError, ScopeViolation

_MODULE_TIMEOUT = 20 * 60
_MAX_BODY_BYTES = 200_000
# curated list is small (~20 paths/host) so a much smaller cluster than
# dir_fuzz's wordlist-scale 12 already signals a catch-all handler
_SOFT404_CLUSTER = 2

_GRAPHQL_INTROSPECTION_QUERY = {"query": "query{__schema{queryType{name}}}"}


def _has_any(body: str, needles: tuple[str, ...]) -> bool:
    low = body.lower()
    return any(n.lower() in low for n in needles)


def _is_git_head(status: int, headers: httpx.Headers, body: str) -> bool:
    return status == 200 and _has_any(body, ("ref:", "refs/heads/", "refs/remotes/"))


def _is_git_config(status: int, headers: httpx.Headers, body: str) -> bool:
    return status == 200 and _has_any(body, ("[core]", "repositoryformatversion"))


def _is_env_file(status: int, headers: httpx.Headers, body: str) -> bool:
    if status != 200 or "<html" in body.lower():
        return False
    lines = [line for line in body.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return False
    kv = sum(1 for line in lines if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", line.strip()))
    return kv >= max(1, len(lines) // 2)


def _is_svn_entries(status: int, headers: httpx.Headers, body: str) -> bool:
    return status == 200 and (
        bool(re.match(r"^\d+\s*\n", body)) or "dir\n" in body
    )


def _json_containing(*needles: str) -> Callable[[int, httpx.Headers, str], bool]:
    def _check(status: int, headers: httpx.Headers, body: str) -> bool:
        if status != 200:
            return False
        ctype = (headers.get("content-type") or "").lower()
        if "json" not in ctype and not body.lstrip().startswith("{"):
            return False
        return _has_any(body, needles)

    return _check


def _is_swagger_ui(status: int, headers: httpx.Headers, body: str) -> bool:
    return status == 200 and _has_any(body, ("swagger-ui", "swagger ui", "swaggeruibundle"))


def _is_backup_file(status: int, headers: httpx.Headers, body: str) -> bool:
    if status != 200:
        return False
    ctype = (headers.get("content-type") or "").lower()
    return "html" not in ctype


def _reachable(status: int, headers: httpx.Headers, body: str) -> bool:
    return status in (200, 301, 302, 401, 403)


def _graphql_introspection(status: int, headers: httpx.Headers, body: str) -> bool:
    return status == 200 and _has_any(body, ("__schema", "querytype"))


@dataclass(frozen=True)
class _Check:
    path: str
    category: str
    interest: str
    validate: Callable[[int, httpx.Headers, str], bool]


_CHECKS: tuple[_Check, ...] = (
    _Check(".git/HEAD", "git", "high_value", _is_git_head),
    _Check(".git/config", "git", "high_value", _is_git_config),
    _Check(".env", "env", "high_value", _is_env_file),
    _Check(".svn/entries", "svn", "high_value", _is_svn_entries),
    _Check("actuator", "actuator", "high_value", _json_containing("_links", "\"contexts\"")),
    _Check("actuator/health", "actuator", "high_value", _json_containing("\"status\"")),
    _Check("actuator/env", "actuator", "high_value", _json_containing("propertysources")),
    _Check("env", "actuator", "high_value", _json_containing("propertysources")),
    _Check("swagger-ui.html", "swagger", "notable", _is_swagger_ui),
    _Check("swagger-ui/index.html", "swagger", "notable", _is_swagger_ui),
    _Check("api-docs", "swagger", "notable", _json_containing("swagger", "openapi")),
    _Check("v2/api-docs", "swagger", "notable", _json_containing("swagger")),
    _Check("v3/api-docs", "swagger", "notable", _json_containing("openapi")),
    _Check("openapi.json", "swagger", "notable", _json_containing("openapi")),
    _Check("admin", "admin_panel", "notable", _reachable),
    _Check("administrator", "admin_panel", "notable", _reachable),
    _Check("wp-admin/", "admin_panel", "notable", _reachable),
    _Check("backup.zip", "backup", "high_value", _is_backup_file),
    _Check("backup.sql", "backup", "high_value", _is_backup_file),
    _Check("backup.tar.gz", "backup", "high_value", _is_backup_file),
    _Check("www.zip", "backup", "high_value", _is_backup_file),
    _Check("dump.sql", "backup", "high_value", _is_backup_file),
    _Check("heapdump", "actuator", "high_value", _reachable),
)


@register
class ExposureChecksModule(ReconModule):
    name = "exposure_checks"
    phase = ModulePhase.ACTIVE
    depends_on = ("http_analyzer", "probe_http")
    description = (
        "Curated unauthenticated presence checks: .git/.env/.svn, actuator, "
        "swagger/openapi, admin panels, backup files, GraphQL introspection"
    )
    max_runtime_seconds = _MODULE_TIMEOUT

    async def run(self, ctx: ModuleContext) -> None:
        roots = await self._roots(ctx)
        if not roots:
            await ctx.progress("exposure_checks: no in-scope web roots")
            return

        ordered = sorted(roots)
        total = len(ordered)
        for i, root in enumerate(ordered, start=1):
            ctx.check_alive()
            await ctx.progress(f"exposure_checks: {root}", current=i - 1, total=total)
            await self._check_host(ctx, root)
        await ctx.progress(f"exposure_checks done: {total} root(s)", current=total, total=total)

    async def _roots(self, ctx: ModuleContext) -> set[str]:
        oos = ctx.allow_out_of_scope
        roots: set[str] = set()
        for url in await ctx.known_assets("url", in_scope_only=not oos):
            parts = urlsplit(url)
            if parts.scheme in ("http", "https") and parts.netloc:
                roots.add(f"{parts.scheme}://{parts.netloc}/")
        # Only guess a root for a host probe_http never assessed at all - a
        # confirmed-live host already has a url asset (covered), and a
        # probed-but-silent one is dead, same precedent as dir_fuzz._roots.
        covered = {urlsplit(r).netloc for r in roots}
        probe_checked = await probed_hosts(ctx)
        for host in await ctx.known_assets("subdomain", "domain", in_scope_only=not oos):
            if host not in covered and host not in probe_checked:
                roots.add(f"https://{host}/")
        return {
            r for r in roots if ctx.scope.classify(r).status is not ScopeStatus.EXCLUDED
        }

    async def _check_host(self, ctx: ModuleContext, root: str) -> None:
        results: list[dict] = []
        for check in _CHECKS:
            ctx.check_alive()
            url = root.rstrip("/") + "/" + check.path
            try:
                resp = await ctx.http.get(url)
            except ScopeViolation:
                return
            except ReconRequestError:
                continue
            try:
                body = resp.text[:_MAX_BODY_BYTES]
            except Exception:  # noqa: BLE001 - decode issues are non-fatal
                body = ""
            results.append({
                "check": check,
                "url": url,
                "status": resp.status_code,
                "length": len(resp.content or b""),
                "words": len(body.split()),
                "lines": body.count("\n") + 1,
                "headers": resp.headers,
                "body": body,
            })

        kept = filter_soft_404(results, cluster_threshold=_SOFT404_CLUSTER)
        for r in kept:
            check: _Check = r["check"]
            if not check.validate(r["status"], r["headers"], r["body"]):
                continue
            await ctx.add_evidence(
                subject_type="exposure",
                subject_value=r["url"],
                raw_data={
                    "url": r["url"],
                    "category": check.category,
                    "status": r["status"],
                    "interest": check.interest,
                    "source": "exposure_checks",
                },
                summary=f"{check.category}: {r['url']} -> {r['status']}",
            )

        await self._check_graphql(ctx, root)

    async def _check_graphql(self, ctx: ModuleContext, root: str) -> None:
        url = root.rstrip("/") + "/graphql"
        try:
            resp = await ctx.http.request("POST", url, json=_GRAPHQL_INTROSPECTION_QUERY)
        except ScopeViolation:
            return
        except ReconRequestError:
            return
        try:
            body = resp.text[:_MAX_BODY_BYTES]
        except Exception:  # noqa: BLE001 - decode issues are non-fatal
            body = ""
        if not _graphql_introspection(resp.status_code, resp.headers, body):
            return
        await ctx.add_evidence(
            subject_type="exposure",
            subject_value=url,
            raw_data={
                "url": url,
                "category": "graphql_introspection",
                "status": resp.status_code,
                "interest": "notable",
                "source": "exposure_checks",
            },
            summary=f"graphql_introspection: {url} answers a __schema introspection query",
        )
