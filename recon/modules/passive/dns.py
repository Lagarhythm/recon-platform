"""DNS Engine (passive).

Enumerates A/AAAA/CNAME/MX/NS/TXT/SOA/CAA for in-scope apex domains and every
subdomain discovered so far, and records the *absence* of DNSSEC as negative
evidence. Zone-transfer (AXFR) attempts are noisy and belong to the active
phase - not here.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

# Record types worth asking for on any name vs. only on a zone apex. Asking a
# plain host for NS/SOA/CAA is just extra queries - and on a resolver that is
# slow to answer (or slow to NXDOMAIN a bogus TLD like ``.lan``) that adds up
# fast.
_HOST_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT")
_APEX_ONLY_TYPES = ("MX", "NS", "SOA", "CAA")


def _base_domains(patterns: list[str]) -> list[str]:
    out: set[str] = set()
    for p in patterns:
        out.add(p[2:] if p.startswith("*.") else p)
    return sorted(out)


@register
class DNSModule(ReconModule):
    name = "dns"
    phase = ModulePhase.PASSIVE
    description = "Resolve A/AAAA/CNAME/MX/NS/TXT/SOA/CAA; flag missing DNSSEC"

    async def run(self, ctx: ModuleContext) -> None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
        resolver.timeout = 3.0

        apexes = set(_base_domains(ctx.roe.scope.in_scope.domains))
        names: set[str] = set(apexes)
        names.update(h.lower().rstrip(".") for h in ctx.roe.scope.in_scope.hosts)
        for v in await ctx.known_values("subdomain", "domain"):
            names.add(v.lower().rstrip("."))

        if not names:
            await ctx.progress("no domains in scope to resolve")
            return

        total = len(names)
        self._timeouts = 0
        self._answered = False
        await ctx.progress(f"resolving {total} name(s)", current=0, total=total)
        for done, name in enumerate(sorted(names), start=1):
            ctx.check_alive()
            # Circuit breaker: if the first several queries all time out and
            # nothing has answered, the resolver is unreachable - bail rather
            # than grind through every name x every record type.
            if self._timeouts >= 8 and not self._answered:
                await ctx.add_error(
                    subject_value="resolver",
                    summary=(
                        f"{self._timeouts} DNS queries timed out with no answer - "
                        "resolver unreachable or the in-scope names aren't real DNS "
                        "names; skipping the rest of DNS enumeration"
                    ),
                )
                await ctx.progress("DNS: bailing early - queries are timing out")
                return
            rtypes = _HOST_RECORD_TYPES + (_APEX_ONLY_TYPES if name in apexes else ())
            await self._resolve_name(ctx, resolver, name, rtypes)
            await ctx.progress(
                f"resolved {done}/{total} name(s)", current=done, total=total
            )

    async def _resolve_name(self, ctx: ModuleContext, resolver, name: str, rtypes) -> None:  # noqa: ANN001
        any_record = False
        for rtype in rtypes:
            ctx.check_alive()
            try:
                answer = await resolver.resolve(name, rtype, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                self._answered = True  # the resolver is alive, this name just doesn't exist
                await ctx.audit_action(
                    target=f"dns:{name}/{rtype}",
                    request_detail={"query": name, "rtype": rtype},
                    response_meta={"result": "NXDOMAIN"},
                )
                return
            except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException) as exc:
                if isinstance(exc, dns.exception.Timeout):
                    self._timeouts += 1
                await ctx.add_error(
                    subject_value=f"{name}/{rtype}",
                    summary=f"DNS {rtype} query failed: {type(exc).__name__}",
                )
                continue

            self._answered = True
            await ctx.audit_action(
                target=f"dns:{name}/{rtype}",
                request_detail={"query": name, "rtype": rtype},
                response_meta={"rrset": bool(answer.rrset), "count": len(answer.rrset or [])},
            )
            if not answer.rrset:
                continue

            for rdata in answer.rrset:
                any_record = True
                value = rdata.to_text()
                await ctx.add_evidence(
                    subject_type="dns_record",
                    subject_value=name,
                    raw_data={
                        "name": name,
                        "rtype": rtype,
                        "value": value,
                        "ttl": answer.rrset.ttl,
                    },
                    summary=f"{name} {rtype} {value}",
                )

        if any_record:
            await self._check_dnssec(ctx, resolver, name)

    async def _check_dnssec(self, ctx: ModuleContext, resolver, name: str) -> None:  # noqa: ANN001
        try:
            answer = await resolver.resolve(name, "DNSKEY", raise_on_no_answer=False)
        except dns.exception.DNSException:
            return
        await ctx.audit_action(
            target=f"dns:{name}/DNSKEY",
            request_detail={"query": name, "rtype": "DNSKEY"},
            response_meta={"present": bool(answer.rrset)},
        )
        if not answer.rrset:
            await ctx.add_negative(
                subject_type="dnssec",
                subject_value=name,
                summary=f"DNSSEC not configured for {name} (no DNSKEY record)",
            )
