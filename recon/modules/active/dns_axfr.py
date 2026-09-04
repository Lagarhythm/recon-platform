"""DNS Zone Transfer probe (active).

Asks every authoritative nameserver of each in-scope apex domain for a full
zone transfer (AXFR). A server that answers is a serious misconfiguration: it
hands an attacker the entire internal DNS namespace in one request. The healthy
case is a refusal, so a refusal is recorded as *negative* evidence (the control
was checked and found working) rather than a loud error.

This module deliberately lives in the active phase - an AXFR attempt is an
unmistakable, logged interaction with the target's infrastructure.
"""

from __future__ import annotations

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.zone

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

_XFR_TIMEOUT = 15.0
# Cap on dns_record rows emitted per transferred zone - a hostile/poisoned
# nameserver of an in-scope domain shouldn't be able to flood Evidence.
_MAX_ZONE_RECORDS = 1000


def _base_domains(patterns: list[str]) -> list[str]:
    out: set[str] = set()
    for p in patterns:
        out.add(p[2:] if p.startswith("*.") else p)
    return sorted(out)


def _records_from_zone(zone, domain: str) -> list[dict]:  # noqa: ANN001
    """Normalise a ``dns.zone.Zone`` into the same record shape ``dns.py`` emits."""
    origin = getattr(zone, "origin", None)
    out: list[dict] = []
    for name, ttl, rdata in zone.iterate_rdatas():
        try:
            fqdn = name.derelativize(origin).to_text(omit_final_dot=True) if origin else str(name)
        except Exception:  # noqa: BLE001 - be forgiving about odd names
            fqdn = str(name)
        rdtype = getattr(rdata, "rdtype", None)
        try:
            rtype = dns.rdatatype.to_text(rdtype) if rdtype is not None else "UNKNOWN"
        except Exception:  # noqa: BLE001
            rtype = str(rdtype)
        out.append(
            {
                "name": fqdn or domain,
                "rtype": rtype,
                "value": rdata.to_text(),
                "ttl": int(ttl),
            }
        )
    return out


async def _zone_transfer(ns_addr: str, domain: str, timeout: float) -> list[dict]:
    """Attempt an AXFR against ``ns_addr`` for ``domain``. Raises on failure."""
    xfr = getattr(dns.asyncquery, "xfr", None)
    if xfr is not None:  # test seam / older dnspython
        zone = dns.zone.from_xfr(xfr(ns_addr, domain, timeout=timeout, lifetime=timeout))
    else:
        zone = dns.zone.Zone(dns.name.from_text(domain))
        await dns.asyncquery.inbound_xfr(ns_addr, zone, timeout=timeout, lifetime=timeout)
    return _records_from_zone(zone, domain)


@register
class DNSZoneTransferModule(ReconModule):
    name = "dns_axfr"
    phase = ModulePhase.ACTIVE
    depends_on = ("dns",)
    description = "Attempt AXFR zone transfer against each apex domain's nameservers"
    requires_binary = None

    async def run(self, ctx: ModuleContext) -> None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 10.0
        resolver.timeout = 5.0

        domains: set[str] = set(_base_domains(ctx.roe.scope.in_scope.domains))
        domains.update(
            d.lower().rstrip(".")
            for d in await ctx.known_assets(
                "domain", in_scope_only=not ctx.allow_out_of_scope
            )
        )
        # EXCLUDED domains are never probed, even under an override.
        domains = set(ctx.scoped_targets(domains))
        if not domains:
            await ctx.progress("no apex domains in scope for AXFR")
            return

        await ctx.progress(f"AXFR probe on {len(domains)} domain(s)", count=len(domains))
        for domain in sorted(domains):
            ctx.check_alive()
            await self._probe_domain(ctx, resolver, domain)

    async def _nameservers(self, ctx: ModuleContext, resolver, domain: str) -> list[str]:  # noqa: ANN001
        try:
            answer = await resolver.resolve(domain, "NS", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return []
        except (dns.exception.DNSException,) as exc:
            await ctx.add_error(
                subject_value=f"{domain}/NS",
                summary=f"could not resolve NS for {domain}: {type(exc).__name__}",
            )
            return []
        rrset = getattr(answer, "rrset", None)
        if not rrset:
            return []
        return sorted({rd.to_text().rstrip(".") for rd in rrset})

    async def _ns_addresses(self, resolver, ns: str) -> list[str]:  # noqa: ANN001
        addrs: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(ns, rtype, raise_on_no_answer=False)
            except dns.exception.DNSException:
                continue
            rrset = getattr(answer, "rrset", None)
            if rrset:
                addrs.extend(rd.to_text() for rd in rrset)
        return addrs or [ns]

    async def _probe_domain(self, ctx: ModuleContext, resolver, domain: str) -> None:  # noqa: ANN001
        nameservers = await self._nameservers(ctx, resolver, domain)
        if not nameservers:
            await ctx.progress(f"no NS records for {domain}; skipping AXFR")
            return

        any_success = False
        refused: list[str] = []
        for ns in nameservers:
            ctx.check_alive()
            addresses = await self._ns_addresses(resolver, ns)
            transferred: list[dict] | None = None
            last_error = ""
            for addr in addresses:
                ctx.check_alive()
                try:
                    transferred = await _zone_transfer(addr, domain, _XFR_TIMEOUT)
                    break
                except Exception as exc:  # noqa: BLE001 - refused/timeout/etc. all expected
                    last_error = f"{type(exc).__name__}: {exc}"[:300]
                    transferred = None

            success = transferred is not None
            await ctx.audit_action(
                target=f"axfr:{domain}@{ns}",
                request_detail={"op": "AXFR", "ns": ns},
                response_meta={
                    "success": success,
                    "records": len(transferred) if transferred else 0,
                },
            )

            if not success:
                refused.append(ns)
                await ctx.progress(f"AXFR refused by {ns} for {domain}: {last_error}")
                continue

            any_success = True
            n = len(transferred)
            truncated = n > _MAX_ZONE_RECORDS
            await ctx.add_evidence(
                subject_type="dns_axfr",
                subject_value=domain,
                raw_data={
                    "nameserver": ns,
                    "record_count": n,
                    "records_emitted": min(n, _MAX_ZONE_RECORDS),
                    "truncated": truncated,
                    "interest": "high_value",
                },
                summary=(
                    f"AXFR zone transfer allowed from {ns} for {domain}"
                    + (f" ({n} records, first {_MAX_ZONE_RECORDS} recorded)" if truncated else "")
                ),
            )
            for rec in transferred[:_MAX_ZONE_RECORDS]:
                await ctx.add_evidence(
                    subject_type="dns_record",
                    subject_value=rec["name"],
                    raw_data=rec,
                    summary=f"{rec['name']} {rec['rtype']} {rec['value']} (via AXFR {ns})",
                )

        if not any_success and refused:
            await ctx.add_negative(
                subject_type="dns_axfr",
                subject_value=domain,
                summary=(
                    f"AXFR correctly refused by all {len(refused)} nameserver(s) "
                    f"for {domain} ({', '.join(refused)})"
                ),
                raw_data={"nameservers": refused},
            )
