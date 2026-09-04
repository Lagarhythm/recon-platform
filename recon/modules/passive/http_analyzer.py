"""HTTP Analyzer (passive).

Probes ``https://`` then ``http://`` for every host discovered so far and records
what the response headers give away: redirect chains, presence/absence of the
common security headers, disclosing headers (``Server`` / ``X-Powered-By`` /
``Via``), cookie flags, a light technology fingerprint, the ``Allow`` method
list, and - for TLS endpoints - the certificate basics. Absent controls are
emitted as negative evidence. No content is fetched beyond ``/``; anything
noisier belongs to the active phase.
"""

from __future__ import annotations

import asyncio
import ssl

from recon.models.enums import FindingPolarity, ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError, ScopeViolation

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)
_DISCLOSING_HEADERS = ("Server", "X-Powered-By", "Via")
_COOKIE_TECH = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "ASPSESSIONID": "ASP",
    "laravel_session": "Laravel",
}


def _apex_domains(patterns: list[str]) -> set[str]:
    return {p[2:] if p.startswith("*.") else p for p in patterns}


def _is_2xx_3xx(status: int) -> bool:
    return 200 <= status < 400


def _is_redirect(status: int) -> bool:
    return 300 <= status < 400


@register
class HTTPAnalyzerModule(ReconModule):
    name = "http_analyzer"
    phase = ModulePhase.PASSIVE
    depends_on = ("dns", "ct_subdomains")
    description = "Probe HTTP(S) on known hosts: redirects, security & disclosing headers, cookies, TLS, tech fingerprint"

    async def run(self, ctx: ModuleContext) -> None:
        hosts: set[str] = set()
        for value in await ctx.known_values("subdomain", "domain"):
            hosts.add(value.lower().rstrip("."))
        for host in ctx.roe.scope.in_scope.hosts:
            hosts.add(host.lower().rstrip("."))
        for domain in _apex_domains(ctx.roe.scope.in_scope.domains):
            hosts.add(domain.lower().rstrip("."))
        hosts.discard("")

        if not hosts:
            await ctx.progress("http_analyzer: no hosts to probe")
            return

        ordered = sorted(hosts)
        total = len(ordered)
        await ctx.progress(
            f"probing {total} host(s) over HTTPS/HTTP", current=0, total=total
        )
        for done, host in enumerate(ordered, start=1):
            ctx.check_alive()
            for scheme in ("https", "http"):
                await self._probe(ctx, host, scheme)
            await ctx.progress(
                f"probed {done}/{total} host(s)", current=done, total=total
            )

    # -- per host/scheme -------------------------------------------------
    async def _probe(self, ctx: ModuleContext, host: str, scheme: str) -> None:
        url = f"{scheme}://{host}/"
        try:
            resp = await ctx.http.get(url)
        except ScopeViolation as exc:
            await ctx.add_error(
                subject_value=url,
                summary=f"out-of-scope target skipped: {exc}",
                raw_data={"url": url, "reason": "scope", "detail": str(exc)},
            )
            return
        except ReconRequestError as exc:
            await ctx.add_error(
                subject_value=url,
                summary=f"HTTP request failed: {type(exc).__name__}: {exc}",
                raw_data={"url": url, "error": type(exc).__name__},
            )
            return

        status = resp.status_code
        headers = resp.headers
        location = headers.get("location")
        redirect = _is_redirect(status)

        url_raw: dict = {"status": status, "scheme": scheme}
        if redirect and location:
            url_raw["location"] = location
        await ctx.add_evidence(
            subject_type="url",
            subject_value=url,
            raw_data=url_raw,
            summary=f"{url} -> {status}",
        )

        if redirect and location:
            await ctx.add_evidence(
                subject_type="redirect",
                subject_value=url,
                raw_data={"url": url, "location": location, "status": status},
                summary=f"{url} redirects to {location}",
            )

        await self._security_headers(ctx, host, url, status, headers)
        await self._disclosing_headers(ctx, host, url, headers)
        await self._tech(ctx, url, headers)
        await self._cookies(ctx, host, url, headers)
        await self._methods(ctx, url)

        if scheme == "https":
            await self._tls(ctx, host, url)

    # -- security headers ---------------------------------------------
    async def _security_headers(
        self, ctx: ModuleContext, host: str, url: str, status: int, headers
    ) -> None:
        for name in _SECURITY_HEADERS:
            value = headers.get(name)
            if value is not None:
                await ctx.add_evidence(
                    subject_type="security_header",
                    subject_value=f"{host}:{name}",
                    raw_data={"url": url, "name": name, "value": value},
                    summary=f"{name} present on {url}",
                    polarity=FindingPolarity.PRESENT,
                )
            elif _is_2xx_3xx(status):
                await ctx.add_negative(
                    subject_type="security_header",
                    subject_value=f"{host}:{name}",
                    summary=f"{name} header missing on {url}",
                    raw_data={"url": url, "name": name},
                )

    # -- disclosing headers -----------------------------------------
    async def _disclosing_headers(
        self, ctx: ModuleContext, host: str, url: str, headers
    ) -> None:
        for name in _DISCLOSING_HEADERS:
            value = headers.get(name)
            if value is not None:
                await ctx.add_evidence(
                    subject_type="http_header",
                    subject_value=f"{host}:{name}",
                    raw_data={"url": url, "name": name, "value": value},
                    summary=f"{name}: {value}",
                )

    # -- technology fingerprint -----------------------------------
    async def _tech(self, ctx: ModuleContext, url: str, headers) -> None:
        for name, version, evidence in _fingerprints(headers):
            await ctx.add_evidence(
                subject_type="tech",
                subject_value=name,
                raw_data={"url": url, "name": name, "version": version, "evidence": evidence},
                summary=f"tech: {name}" + (f" {version}" if version else ""),
            )

    # -- cookies ---------------------------------------------------
    async def _cookies(self, ctx: ModuleContext, host: str, url: str, headers) -> None:
        for raw_cookie in headers.get_list("set-cookie"):
            parsed = _parse_cookie(raw_cookie)
            if parsed is None:
                continue
            name, secure, httponly, samesite = parsed
            await ctx.add_evidence(
                subject_type="cookie",
                subject_value=f"{host}:{name}",
                raw_data={
                    "url": url,
                    "name": name,
                    "secure": secure,
                    "httponly": httponly,
                    "samesite": samesite,
                },
                summary=f"Set-Cookie {name} (secure={secure}, httponly={httponly})",
            )
            missing = [
                flag
                for flag, present in (("Secure", secure), ("HttpOnly", httponly))
                if not present
            ]
            if missing:
                await ctx.add_negative(
                    subject_type="cookie",
                    subject_value=f"{host}:{name}",
                    summary=f"cookie {name} missing {', '.join(missing)} on {url}",
                    raw_data={"url": url, "name": name, "missing": missing},
                )

    # -- allowed methods ----------------------------------------
    async def _methods(self, ctx: ModuleContext, url: str) -> None:
        try:
            resp = await ctx.http.request("OPTIONS", url)
        except ScopeViolation as exc:
            await ctx.add_error(
                subject_value=f"OPTIONS {url}",
                summary=f"out-of-scope target skipped: {exc}",
                raw_data={"url": url, "reason": "scope"},
            )
            return
        except ReconRequestError as exc:
            await ctx.add_error(
                subject_value=f"OPTIONS {url}",
                summary=f"OPTIONS request failed: {type(exc).__name__}",
                raw_data={"url": url, "error": type(exc).__name__},
            )
            return
        allow = resp.headers.get("Allow")
        if allow:
            await ctx.add_evidence(
                subject_type="http_method",
                subject_value=url,
                raw_data={
                    "url": url,
                    "name": "Allow",
                    "value": allow,
                    "methods": [m.strip() for m in allow.split(",") if m.strip()],
                },
                summary=f"Allow: {allow}",
            )

    # -- TLS certificate basics --------------------------------
    async def _tls(self, ctx: ModuleContext, host: str, url: str) -> None:
        cert: dict = {}
        # This raw socket bypasses ctx.http - throttle it through the same
        # rate limiter / jitter so it can't exceed the RoE's request budget.
        await ctx.http.acquire_slot()
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=ssl_ctx), timeout=10.0
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                cert = (ssl_obj.getpeercert() if ssl_obj is not None else {}) or {}
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001 - best-effort teardown
                    pass
        except Exception as exc:  # noqa: BLE001 - any handshake/network failure -> error evidence
            await ctx.add_error(
                subject_value=f"tls:{host}:443",
                summary=f"TLS handshake failed: {type(exc).__name__}",
                raw_data={"host": host, "url": url, "error": type(exc).__name__},
            )
            await ctx.audit_action(
                target=f"tls:{host}:443",
                request_detail={"op": "tls_handshake"},
                response_meta={"error": type(exc).__name__},
            )
            return

        await ctx.add_evidence(
            subject_type="tls_cert",
            subject_value=f"{host}:443",
            raw_data={
                "url": url,
                "notAfter": cert.get("notAfter"),
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "subjectAltName": cert.get("subjectAltName"),
            },
            summary=f"TLS certificate for {host}",
        )
        await ctx.audit_action(
            target=f"tls:{host}:443",
            request_detail={"op": "tls_handshake"},
            response_meta={"has_cert": bool(cert), "notAfter": cert.get("notAfter")},
        )


def _fingerprints(headers) -> list[tuple[str, str | None, str]]:
    """(tech, version|None, evidence-header) tuples from disclosing headers/cookies."""
    out: list[tuple[str, str | None, str]] = []

    server = headers.get("Server")
    if server:
        name, _, version = server.split()[0].partition("/")
        if name:
            out.append((name.lower(), version or None, "Server"))

    powered = headers.get("X-Powered-By")
    if powered:
        name, _, version = powered.split()[0].partition("/")
        if name:
            out.append((name, version or None, "X-Powered-By"))

    generator = headers.get("X-Generator")
    if generator:
        name, _, version = generator.partition(" ")
        if name:
            out.append((name.strip(), version.strip() or None, "X-Generator"))

    for raw_cookie in headers.get_list("set-cookie"):
        cookie_name = raw_cookie.split("=", 1)[0].strip()
        tech = _COOKIE_TECH.get(cookie_name)
        if tech:
            out.append((tech, None, f"cookie:{cookie_name}"))

    return out


def _parse_cookie(raw_cookie: str) -> tuple[str, bool, bool, str | None] | None:
    parts = [p.strip() for p in raw_cookie.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    secure = False
    httponly = False
    samesite: str | None = None
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            secure = True
        elif key == "httponly":
            httponly = True
        elif key == "samesite":
            samesite = val.strip() or None
    return name, secure, httponly, samesite
