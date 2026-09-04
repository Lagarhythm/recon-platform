"""Subdomain brute-forcer (active).

Resolves a bundled list of common subdomain labels against every in-scope apex
domain. Active phase: this is a burst of real DNS queries against the target's
authoritative infrastructure.

Wildcard-DNS guard: before brute-forcing an apex we resolve a random label that
cannot plausibly exist. If it resolves, the zone has a wildcard record and every
brute-force "hit" would be a false positive - so we record a ``dns_wildcard``
finding and skip brute-forcing that apex entirely.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import dns.asyncresolver

from recon.models.enums import ModulePhase
from recon.modules._dns_common import is_zone as _is_zone
from recon.modules._dns_common import resolve_records as _resolve_label
from recon.modules._dns_common import wildcard_answers
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

_WORDLIST = Path(__file__).resolve().parents[2] / "data" / "wordlists" / "subdomains.txt"


def _base_domains(patterns: list[str]) -> list[str]:
    out: set[str] = set()
    for p in patterns:
        out.add(p[2:] if p.startswith("*.") else p)
    return sorted(out)


def _load_labels(path: Path = _WORDLIST) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return labels
    for line in raw.splitlines():
        label = line.strip().lower()
        if not label or label.startswith("#") or label in seen:
            continue
        seen.add(label)
        labels.append(label)
    return labels


@register
class SubdomainBruteModule(ReconModule):
    name = "subdomain_brute"
    phase = ModulePhase.ACTIVE
    depends_on = ("dns",)
    description = "Brute-force common subdomain labels against in-scope apex domains"
    requires_binary = None
    # A full brute-force against many apexes shouldn't be able to run for an
    # hour; if it does, something is wrong (slow resolver, bogus apex list).
    max_runtime_seconds = 20 * 60

    async def run(self, ctx: ModuleContext) -> None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 10.0
        resolver.timeout = 5.0

        labels = _load_labels()
        if not labels:
            await ctx.add_error(
                subject_value=str(_WORDLIST),
                summary=f"subdomain wordlist missing or empty: {_WORDLIST}",
            )
            return

        apexes: set[str] = set(_base_domains(ctx.roe.scope.in_scope.domains))
        apexes.update(
            d.lower().rstrip(".")
            for d in await ctx.known_assets(
                "domain", in_scope_only=not ctx.allow_out_of_scope
            )
        )
        apexes = set(ctx.scoped_targets(apexes))  # EXCLUDED never brute-forced
        if not apexes:
            await ctx.progress("no apex domains in scope for subdomain brute-force")
            return

        concurrency = max(1, min(20, ctx.roe.rate_limits.max_concurrent_connections))
        sem = asyncio.Semaphore(concurrency)
        # Draw from the scan-run's single shared token bucket (injected into the
        # context) so these DNS queries share the RoE budget with every HTTP
        # request instead of spending it independently.
        limiter = ctx.rate_limiter

        # Only brute-force names that are actually DNS zones. A host from an
        # /etc/hosts-style RoE entry (e.g. "homer.lan") has no SOA - brute-forcing
        # it is thousands of pointless lookups that can each hit the resolver
        # timeout.
        zones = []
        for a in sorted(apexes):
            if await _is_zone(resolver, a, limiter):
                zones.append(a)
        skipped = sorted(apexes - set(zones))
        if skipped:
            await ctx.progress(
                f"skipping {len(skipped)} non-zone apex(es): {', '.join(skipped[:5])}"
            )
        if not zones:
            await ctx.progress("no brute-forceable DNS zones in scope")
            return
        apexes = set(zones)

        await ctx.progress(
            f"subdomain brute: {len(labels)} labels x {len(apexes)} apex(es)",
            count=len(labels) * len(apexes),
        )
        for apex in sorted(apexes):
            ctx.check_alive()
            await self._brute_apex(ctx, resolver, apex, labels, sem, concurrency, limiter)

    async def _brute_apex(  # noqa: ANN001, PLR0913
        self, ctx: ModuleContext, resolver, apex: str, labels, sem, concurrency, limiter
    ) -> None:
        wildcard = await wildcard_answers(resolver, apex, limiter)
        if wildcard:
            await ctx.add_evidence(
                subject_type="dns_wildcard",
                subject_value=apex,
                raw_data={"apex": apex, "interest": "notable",
                          "wildcard_answers": sorted(wildcard)},
                summary=(
                    f"wildcard DNS detected for {apex}; brute-force results "
                    "unreliable, brute-force skipped"
                ),
            )
            await ctx.audit_action(
                target=f"dns-brute:{apex}",
                request_detail={"labels": 0, "skipped": "wildcard"},
                response_meta={"hits": 0},
            )
            return

        hits = 0
        total = len(labels)
        for start in range(0, total, concurrency):
            ctx.check_alive()
            batch = labels[start : start + concurrency]
            await ctx.progress(
                f"brute {apex}: {min(start, total)}/{total} labels",
                current=min(start, total), total=total,
            )

            async def _one(label: str) -> tuple[str, list[dict]]:
                async with sem:
                    fqdn = f"{label}.{apex}"
                    return fqdn, await _resolve_label(resolver, fqdn, limiter)

            results = await asyncio.gather(*(_one(lbl) for lbl in batch))
            for fqdn, records in results:
                if not records:
                    continue
                hits += 1
                await ctx.add_evidence(
                    subject_type="subdomain",
                    subject_value=fqdn,
                    raw_data={
                        "parent": apex,
                        "source": "brute",
                        "resolved": [r["value"] for r in records],
                    },
                    summary=f"brute-forced subdomain {fqdn}",
                )
                for rec in records:
                    await ctx.add_evidence(
                        subject_type="dns_record",
                        subject_value=fqdn,
                        raw_data=rec,
                        summary=f"{fqdn} {rec['rtype']} {rec['value']}",
                    )

        await ctx.audit_action(
            target=f"dns-brute:{apex}",
            request_detail={"labels": len(labels)},
            response_meta={"hits": hits},
        )
        await ctx.progress(f"subdomain brute {apex}: {hits} hit(s)")
