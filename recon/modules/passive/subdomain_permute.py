"""Subdomain permutation (passive, PRD v2.1 §11.4).

Generates likely name variants of the subdomains found so far - ``api`` →
``api-dev`` / ``dev-api`` / ``api2`` / ``api.staging`` etc. - and resolves each
one. Finds names that are in no public dataset and no static wordlist (the
altdns / dnsgen technique), so it only pays off once ``passive_subdomains`` has
seeded a set of real names to mutate.

Wildcard zones are filtered via ``_dns_common.wildcard_answers``: a candidate
that resolves *only* to the apex's wildcard address set is discarded, so a
``*.example.com`` record can't flood the graph with junk ``subdomain`` assets.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver

from recon.models.enums import ModulePhase
from recon.modules._dns_common import resolve_records, wildcard_answers
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

# environment / stage words to splice onto an existing label
_WORDS = (
    "dev", "test", "testing", "stage", "staging", "preprod", "prod", "uat", "qa",
    "demo", "beta", "alpha", "sandbox", "internal", "int", "corp", "admin",
    "api", "api2", "app", "apps", "web", "www", "portal", "dashboard", "console",
    "auth", "sso", "login", "secure", "vpn", "gw", "gateway", "proxy",
    "new", "old", "legacy", "v1", "v2", "v3", "next", "edge", "cdn", "static",
    "assets", "media", "img", "files", "download", "backup", "db", "sql",
    "git", "gitlab", "jenkins", "ci", "build", "docker", "k8s", "cluster",
    "mail", "smtp", "mx", "ns", "monitoring", "grafana", "kibana", "status",
    "eu", "us", "uk", "de", "apac", "east", "west", "north", "south",
)
_MAX_BASES = 400           # cap how many known names we bother mutating
_RESOLVE_CONCURRENCY = 20


def _labels(name: str, apex: str) -> tuple[list[str], str]:
    """(sub-labels, apex) - the labels left of the registrable apex."""
    if name == apex:
        return [], apex
    if name.endswith("." + apex):
        return name[: -len(apex) - 1].split("."), apex
    parts = name.split(".")
    return parts[:-2], ".".join(parts[-2:])


def permutations(name: str, apex: str, words: tuple[str, ...] = _WORDS) -> set[str]:
    """dnsgen-style variants of one FQDN under its apex."""
    subs, apex = _labels(name, apex)
    if not subs:
        # mutate the apex itself: word.apex
        return {f"{w}.{apex}" for w in words}

    out: set[str] = set()
    head, rest = subs[0], subs[1:]
    tail = ".".join([*rest, apex])

    for w in words:
        out.add(f"{w}.{head}.{tail}")           # new leftmost label
        out.add(f"{head}.{w}.{tail}")           # word one level down
        out.add(f"{w}-{head}.{tail}")           # dash-prefixed
        out.add(f"{head}-{w}.{tail}")           # dash-suffixed

    # dash <-> dot swaps and number bumps within the leftmost label
    if "-" in head:
        out.add(f"{head.replace('-', '.')}.{tail}")
        out.add(f"{head.replace('-', '')}.{tail}")
    for i, ch in enumerate(head):
        if ch.isdigit():
            for delta in (1, -1, 2):
                n = int(ch) + delta
                if 0 <= n <= 9:
                    out.add(f"{head[:i]}{n}{head[i + 1:]}.{tail}")
            break
    else:
        for suffix in ("1", "2", "01", "02", "-1", "-2"):
            out.add(f"{head}{suffix}.{tail}")

    out.discard(name)
    return out


@register
class SubdomainPermuteModule(ReconModule):
    name = "subdomain_permute"
    phase = ModulePhase.PASSIVE
    depends_on = ("passive_subdomains", "dns")
    description = "Resolve dnsgen-style permutations of known subdomains (altdns technique)"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        apexes = sorted({
            p[2:] if p.startswith("*.") else p
            for p in ctx.roe.scope.in_scope.domains
        })
        if not apexes:
            await ctx.progress("subdomain_permute: no in-scope apex domains")
            return
        known = {
            n.strip().lower().strip(".")
            for n in await ctx.known_values("subdomain", "domain")
            if n and n.strip()
        }
        bases = sorted(n for n in known if n not in apexes)[:_MAX_BASES]
        if not bases:
            await ctx.progress("subdomain_permute: no discovered subdomains to mutate yet")
            return

        cap = int(ctx.roe.recon.permutation.max_candidates)
        wordlist = self._load_wordlist(ctx)

        # candidate -> (origin name, its apex)
        candidates: dict[str, tuple[str, str]] = {}
        for name in bases:
            apex = next((a for a in apexes if name == a or name.endswith("." + a)), None)
            if apex is None:
                continue
            for cand in permutations(name, apex, wordlist):
                if cand not in known and cand not in candidates:
                    candidates[cand] = (name, apex)
                    if len(candidates) >= cap:
                        break
            if len(candidates) >= cap:
                break

        if not candidates:
            await ctx.progress("subdomain_permute: no new candidates generated")
            return
        await ctx.progress(
            f"subdomain_permute: resolving {len(candidates)} candidate(s)",
            count=len(candidates),
        )

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 8.0
        resolver.timeout = 4.0
        limiter = ctx.rate_limiter

        # wildcard answer sets per apex, computed once
        wildcards: dict[str, set[str]] = {}
        for apex in sorted({a for _, a in candidates.values()}):
            ctx.check_alive()
            wildcards[apex] = await wildcard_answers(resolver, apex, limiter)

        sem = asyncio.Semaphore(_RESOLVE_CONCURRENCY)
        hits = 0
        items = list(candidates.items())
        for start in range(0, len(items), _RESOLVE_CONCURRENCY):
            ctx.check_alive()
            batch = items[start : start + _RESOLVE_CONCURRENCY]

            async def _one(cand: str, origin: str, apex: str) -> None:
                nonlocal hits
                async with sem:
                    records = await resolve_records(resolver, cand, limiter)
                if not records:
                    return
                values = {r["value"] for r in records}
                wc = wildcards.get(apex, set())
                if wc and values and values <= wc:
                    return  # resolves only to the wildcard target - junk
                hits += 1
                await ctx.add_evidence(
                    subject_type="subdomain",
                    subject_value=cand,
                    raw_data={"method": "permutation", "base": origin,
                              "source": "permutation", "resolved": sorted(values)},
                    summary=f"{cand} - permutation of {origin}",
                    relationships=[{"type": "alias_of", "target_type": "subdomain",
                                    "target_value": origin}],
                )
                for rec in records:
                    await ctx.add_evidence(
                        subject_type="dns_record", subject_value=cand,
                        raw_data=rec, summary=f"{cand} {rec['rtype']} {rec['value']}",
                    )

            await asyncio.gather(*(_one(c, o, a) for c, (o, a) in batch))
            await ctx.progress(
                f"subdomain_permute: {min(start + _RESOLVE_CONCURRENCY, len(items))}"
                f"/{len(items)} ({hits} live)",
                current=min(start + _RESOLVE_CONCURRENCY, len(items)), total=len(items),
            )

        await ctx.progress(f"subdomain_permute: {hits} live permutation(s)")

    @staticmethod
    def _load_wordlist(ctx: ModuleContext) -> tuple[str, ...]:
        path = ctx.roe.recon.permutation.wordlist
        if not path:
            return _WORDS
        try:
            with open(path, encoding="utf-8") as fh:
                extra = tuple(
                    ln.strip().lower() for ln in fh
                    if ln.strip() and not ln.startswith("#")
                )
            return tuple(dict.fromkeys((*_WORDS, *extra)))
        except OSError:
            return _WORDS
