"""Multi-source passive subdomain aggregation (OSINT, PRD v2.1 §11.1).

Replaces the crt.sh-only reliance with a fan-out over ~8 keyless public sources
(CT logs, passive-DNS DBs, the Wayback index, aggregator DBs). Each source is an
adapter in ``_passive_sources.py``; this module runs the enabled ones per
in-scope / seed domain, wrapped in a per-source timeout and try/except.

Per-source failure policy (CONTRACT principle 10): a dead source records an
``error`` and the run continues; the module only *fails* if **zero** sources
answered for **every** domain. A quota / 429 signal is a *degraded* outcome, not
a crash.

Each name is emitted once per source that saw it, tagged
``raw_data["source"] = "<adapter>"`` - the correlation engine's source-diversity
``_confidence()`` fix turns "seen in crt.sh + OTX + Wayback" into rising
confidence. ``ct_subdomains`` stays in place; the two dedupe fine.
"""

from __future__ import annotations

import asyncio
import time

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import org_targets
from recon.modules.osint._passive_sources import SourceDegraded, select_sources
from recon.modules.registry import register

# Defensive ceiling on how many names one source may contribute for one domain -
# guards against a mis-parsed scrape or a runaway archive query. A real domain
# with more subdomains than this from a single source is vanishingly rare.
_MAX_HITS_PER_SOURCE = 10_000


@register
class PassiveSubdomainsModule(ReconModule):
    name = "passive_subdomains"
    phase = ModulePhase.OSINT
    depends_on = ("ct_org", "wayback")
    description = "Aggregate subdomains from ~8 keyless passive sources (CT, passive-DNS, archives)"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        _, domains = org_targets(ctx)
        known = {
            d.strip().lower().strip(".")
            for d in await ctx.known_values("domain")
            if d and d.strip()
        }
        targets = sorted({*domains, *known})
        if not targets:
            await ctx.progress("passive_subdomains: no in-scope / seed domains in the RoE")
            return

        cfg = ctx.roe.recon.passive_sources
        sources = select_sources(set(cfg.disable), set(cfg.enable))
        if not sources:
            await ctx.progress("passive_subdomains: every source disabled by config")
            return

        await ctx.progress(
            f"passive_subdomains: {len(sources)} source(s) x {len(targets)} domain(s)",
            count=len(sources) * len(targets),
        )

        deadline = time.monotonic() + float(cfg.total_budget_seconds)
        any_answered = False
        budget_hit = False

        for domain in targets:
            ctx.check_alive()
            # name -> {"sources": set, "resolved": set}
            found: dict[str, dict] = {}
            answered_here = 0

            for src in sources:
                ctx.check_alive()
                if time.monotonic() >= deadline:
                    budget_hit = True
                    break
                try:
                    hits = await asyncio.wait_for(
                        src.fetch(ctx, domain),
                        timeout=float(cfg.per_source_timeout_seconds),
                    )
                except asyncio.TimeoutError:
                    await ctx.add_error(
                        subject_value=src.name,
                        summary=f"{src.name} timed out for {domain} "
                                f"({cfg.per_source_timeout_seconds:.0f}s)",
                        raw_data={"source": src.name, "pivot": domain, "reason": "timeout"},
                    )
                    continue
                except SourceDegraded as exc:
                    await ctx.add_error(
                        subject_value=src.name,
                        summary=f"{src.name} degraded for {domain}: {exc}",
                        raw_data={"source": src.name, "pivot": domain, "reason": "degraded"},
                    )
                    continue
                except Exception as exc:  # noqa: BLE001 - any adapter failure is non-fatal
                    await ctx.add_error(
                        subject_value=src.name,
                        summary=f"{src.name} failed for {domain}: {type(exc).__name__}",
                        raw_data={"source": src.name, "pivot": domain,
                                  "error": str(exc)[:300]},
                    )
                    continue

                answered_here += 1
                any_answered = True
                if len(hits) > _MAX_HITS_PER_SOURCE:
                    await ctx.add_error(
                        subject_value=src.name,
                        summary=f"{src.name} returned {len(hits)} names for {domain} - "
                                f"capped at {_MAX_HITS_PER_SOURCE}",
                        raw_data={"source": src.name, "pivot": domain, "reason": "capped"},
                    )
                    hits = hits[:_MAX_HITS_PER_SOURCE]
                for hit in hits:
                    rec = found.setdefault(hit.name, {"sources": set(), "resolved": set()})
                    rec["sources"].add(src.name)
                    rec["resolved"].update(hit.resolved)

            await self._emit(ctx, domain, found)
            await ctx.progress(
                f"passive_subdomains: {domain} -> {len(found)} name(s) "
                f"from {answered_here}/{len(sources)} source(s)"
            )

        if budget_hit:
            await ctx.progress(
                f"passive_subdomains: {cfg.total_budget_seconds:.0f}s budget reached; "
                "remaining source calls skipped"
            )
        if not any_answered:
            raise RuntimeError(
                "passive_subdomains: every source failed for every domain "
                "(0 answered) - see the per-source error rows"
            )

    async def _emit(self, ctx: ModuleContext, pivot: str, found: dict[str, dict]) -> None:
        for name in sorted(found):
            ctx.check_alive()
            rec = found[name]
            sources = sorted(rec["sources"])
            resolved = sorted(rec["resolved"])
            stype = "domain" if name == pivot else "subdomain"
            # one evidence row per source that saw the name, so the
            # source-diversity confidence model actually counts them
            for src in sources:
                await ctx.add_evidence(
                    subject_type=stype,
                    subject_value=name,
                    raw_data={"source": src, "pivot": pivot, "also_seen_by": sources},
                    summary=f"{name} - passive source {src}",
                )
            for ip in resolved:
                await ctx.add_evidence(
                    subject_type="dns_record",
                    subject_value=name,
                    raw_data={"name": name, "rtype": "AAAA" if ":" in ip else "A",
                              "value": ip, "source": ",".join(sources)},
                    summary=f"{name} {ip} (passive)",
                )
