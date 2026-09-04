"""Subdomain takeover detection (passive, PRD v2.1 §11.5).

For every discovered host with a CNAME pointing at a third-party service,
checks whether that service target is *unclaimed* - a dangling DNS record is a
live exposure found by pure recon (never exploited): anyone who claims the
resource on the provider's side now controls content served from the client's
own subdomain.

Native path only. ``recon.takeover.engine`` also accepts ``subzy``/``nuclei`` as
documented future accelerators - neither is implemented here; if set, this
module runs its native check anyway and says so, rather than silently doing
nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import dns.asyncresolver

from recon.models.enums import ModulePhase
from recon.modules._dns_common import resolve_records
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

_FINGERPRINTS_PATH = Path(__file__).resolve().parents[1] / "_takeover_fingerprints.json"
_MAX_CNAME_DEPTH = 4


def _load_providers() -> list[dict]:
    try:
        data = json.loads(_FINGERPRINTS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data.get("providers", [])


def _match_provider(cname_target: str, providers: list[dict]) -> dict | None:
    target = cname_target.rstrip(".").lower()
    for p in providers:
        if any(target == suffix or target.endswith("." + suffix) for suffix in p["cnames"]):
            return p
    return None


async def _cname_chain(resolver, host: str, limiter, max_depth: int = _MAX_CNAME_DEPTH) -> list[str]:
    """Follow CNAME hops from ``host``. dnspython resolves one hop per query;
    this repeats until a non-CNAME answer, a cap, or nothing further resolves."""
    chain: list[str] = []
    current = host
    for _ in range(max_depth):
        records = await resolve_records(resolver, current, limiter, record_types=("CNAME",))
        if not records:
            break
        target = records[0]["value"].rstrip(".").lower()
        if target in chain or target == current:
            break  # defend against a CNAME loop
        chain.append(target)
        current = target
    return chain


@register
class SubdomainTakeoverModule(ReconModule):
    name = "subdomain_takeover"
    phase = ModulePhase.PASSIVE
    depends_on = ("dns", "passive_subdomains")
    description = "Detect dangling CNAMEs pointing at unclaimed third-party services"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        providers = _load_providers()
        if not providers:
            await ctx.add_error(
                subject_value=str(_FINGERPRINTS_PATH),
                summary=f"takeover fingerprint set missing or empty: {_FINGERPRINTS_PATH}",
            )
            return

        engine = ctx.roe.recon.takeover.engine.value
        if engine != "native":
            await ctx.progress(
                f"subdomain_takeover: recon.takeover.engine={engine!r} is not implemented "
                "yet (documented future accelerator) - running the native check instead"
            )

        hosts = sorted({
            h.strip().lower().strip(".")
            for h in await ctx.known_values("subdomain", "domain")
            if h and h.strip()
        })
        targets = ctx.scoped_targets(hosts)  # EXCLUDED never checked
        if not targets:
            await ctx.progress("subdomain_takeover: no known hosts to check")
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
        resolver.timeout = 3.0
        limiter = ctx.rate_limiter

        await ctx.progress(f"subdomain_takeover: {len(targets)} host(s)", count=len(targets))
        hits = 0
        for i, host in enumerate(targets, start=1):
            ctx.check_alive()
            try:
                if await self._check_host(ctx, resolver, limiter, host, providers):
                    hits += 1
            except Exception as exc:  # noqa: BLE001 - per-host, non-fatal
                await ctx.add_error(
                    subject_value=host,
                    summary=f"subdomain_takeover check failed for {host}: {type(exc).__name__}",
                )
            await ctx.progress(
                f"subdomain_takeover: {i}/{len(targets)} ({hits} candidate(s))",
                current=i, total=len(targets),
            )

    async def _check_host(
        self, ctx: ModuleContext, resolver, limiter, host: str, providers: list[dict]
    ) -> bool:
        chain = await _cname_chain(resolver, host, limiter)
        if not chain:
            return False
        target = chain[-1]
        match = _match_provider(target, providers)
        if match is None:
            return False

        target_records = await resolve_records(
            resolver, target, limiter, record_types=("A", "AAAA")
        )
        if not target_records:
            # The CNAME target itself is dangling - the strongest signal there
            # is, regardless of whether this provider's entry sets `nxdomain`
            # (a resolving-but-unclaimed provider would still answer A/AAAA).
            await self._emit(
                ctx, host, target, match,
                evidence=f"CNAME target {target} does not resolve (dangling)",
            )
            return True
        if match["nxdomain"]:
            # This provider's unclaimed state is specifically "target doesn't
            # resolve" and it just did - not a candidate.
            return False
        if not match["fingerprints"]:
            return False

        try:
            resp = await ctx.http.get(f"https://{host}/", timeout=10.0, follow_redirects=True)
        except Exception:  # noqa: BLE001 - host unreachable is not a takeover signal
            return False
        body = resp.text[:200_000]
        hit_fp = next(
            (fp for fp in match["fingerprints"] if fp.lower() in body.lower()), None
        )
        if hit_fp is None:
            return False
        await self._emit(
            ctx, host, target, match,
            evidence=f"response body matched fingerprint {hit_fp!r} (HTTP {resp.status_code})",
        )
        return True

    async def _emit(
        self, ctx: ModuleContext, host: str, target: str, match: dict, *, evidence: str
    ) -> None:
        provider = match["provider"]
        await ctx.add_evidence(
            subject_type="takeover",
            subject_value=host,
            raw_data={
                "provider": provider, "cname_target": target,
                "evidence": evidence, "interest": "high_value",
            },
            summary=f"{host} -> {target}: possible {provider} takeover ({evidence})",
            relationships=[
                {"type": "takeover_candidate", "target_type": "organization",
                 "target_value": provider},
            ],
        )
