"""Recursive passive subdomain enumeration (passive, PRD v2.1 §11.3).

Feeds the subdomains found so far back into a fast subset of the
``passive_subdomains`` sources as *deeper* seeds - ``dev.acme.com`` becomes a
query for ``*.dev.acme.com`` - for ``recon.recursion.max_rounds`` extra rounds.
Names in the deeper zone that no top-level query would ever surface.

Honey flagged this as possibly an orchestrator run-loop rather than a module.
It is a clean bounded loop that only re-uses the source adapters, needs no
orchestrator change, and dedupes against ``known_values`` each round - so it
lives as a module. If that stops being true, revisit.
"""

from __future__ import annotations

import asyncio

from recon.models.enums import ModulePhase
from recon.modules.osint._passive_sources import ALL_SOURCES
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

# Only the fast JSON sources recurse - a full fan-out per discovered name is too
# expensive, and CT/aggregator DBs give the best deeper-zone coverage.
_RECURSE_SOURCE_NAMES = ("crtsh", "certspotter", "anubis", "otx")
_MAX_SEEDS_PER_ROUND = 60
_MAX_NEW_TOTAL = 3_000


@register
class SubdomainRecurseModule(ReconModule):
    name = "subdomain_recurse"
    phase = ModulePhase.PASSIVE
    depends_on = ("passive_subdomains",)
    description = "Re-query a fast subset of passive sources against newly-found subdomains"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        rounds = int(ctx.roe.recon.recursion.max_rounds)
        if rounds <= 0:
            await ctx.progress("subdomain_recurse: recursion disabled (max_rounds=0)")
            return
        per_source_timeout = float(ctx.roe.recon.passive_sources.per_source_timeout_seconds)

        disabled = set(ctx.roe.recon.passive_sources.disable)
        sources = [
            s for s in ALL_SOURCES
            if s.name in _RECURSE_SOURCE_NAMES and s.name not in disabled
        ]
        if not sources:
            await ctx.progress("subdomain_recurse: every recursion source disabled")
            return

        apexes = {
            p[2:] if p.startswith("*.") else p
            for p in ctx.roe.scope.in_scope.domains
        }
        known = {
            n.strip().lower().strip(".")
            for n in await ctx.known_values("subdomain", "domain")
            if n and n.strip()
        }
        # only recurse on real subdomains (has a label below its apex)
        frontier = sorted(
            n for n in known
            if n not in apexes and any(n.endswith("." + a) and n != a for a in apexes)
        )
        seen = set(known)
        new_total = 0

        for rnd in range(1, rounds + 1):
            if not frontier or new_total >= _MAX_NEW_TOTAL:
                break
            ctx.check_alive()
            batch = frontier[:_MAX_SEEDS_PER_ROUND]
            await ctx.progress(
                f"subdomain_recurse: round {rnd}/{rounds}, {len(batch)} seed(s)",
                current=rnd, total=rounds,
            )
            next_frontier: set[str] = set()

            for seed in batch:
                ctx.check_alive()
                for src in sources:
                    ctx.check_alive()
                    try:
                        hits = await asyncio.wait_for(
                            src.fetch(ctx, seed), timeout=per_source_timeout
                        )
                    except Exception as exc:  # noqa: BLE001 - per-source, non-fatal
                        await ctx.add_error(
                            subject_value=src.name,
                            summary=f"{src.name} failed for {seed} (round {rnd}): "
                                    f"{type(exc).__name__}",
                            raw_data={"source": src.name, "pivot": seed, "round": rnd},
                        )
                        continue
                    for hit in hits:
                        name = hit.name
                        if name in seen or not name.endswith("." + seed):
                            continue  # must be strictly deeper than the seed
                        seen.add(name)
                        next_frontier.add(name)
                        new_total += 1
                        await ctx.add_evidence(
                            subject_type="subdomain",
                            subject_value=name,
                            raw_data={"source": src.name, "method": "recursion",
                                      "round": rnd, "pivot": seed},
                            summary=f"{name} - round {rnd} recursion via {src.name} on {seed}",
                        )
                        for ip in hit.resolved:
                            await ctx.add_evidence(
                                subject_type="dns_record", subject_value=name,
                                raw_data={"name": name,
                                          "rtype": "AAAA" if ":" in ip else "A",
                                          "value": ip, "source": src.name},
                                summary=f"{name} {ip} (recursion)",
                            )
                        if new_total >= _MAX_NEW_TOTAL:
                            break

            frontier = sorted(next_frontier)

        await ctx.progress(f"subdomain_recurse: {new_total} new name(s) over {rounds} round(s)")
