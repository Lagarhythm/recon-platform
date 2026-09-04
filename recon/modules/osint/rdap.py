"""RDAP / WHOIS lookups (OSINT).

For each seed / in-scope domain: registrant organisation, registrar, key dates
(registration / last-changed / expiration), status flags, nameservers - from the
public RDAP system (rdap.org bootstraps to the authoritative server). Then
resolves the domain and reverse-looks-up the hosting netblock + owner.
"""

from __future__ import annotations

from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import fetch_json, org_targets
from recon.modules.registry import register

# status values worth surfacing as a finding
_NOTABLE_STATUS = {
    "client hold", "server hold", "pending delete", "pending transfer",
    "redemption period", "inactive",
}


def _vcard_field(entity: dict, field: str) -> str | None:
    vca = entity.get("vcardArray")
    if not isinstance(vca, list) or len(vca) < 2:
        return None
    for item in vca[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return str(item[3]) if item[3] else None
    return None


def _entity_org(entity: dict) -> str | None:
    return _vcard_field(entity, "org") or _vcard_field(entity, "fn")


@register
class RDAPModule(ReconModule):
    name = "rdap"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "RDAP/WHOIS: registrant org, dates, status, nameservers + reverse-IP netblock"
    max_runtime_seconds = 8 * 60

    async def run(self, ctx: ModuleContext) -> None:
        _, domains = org_targets(ctx)
        if not domains:
            await ctx.progress("rdap: no seed / in-scope domains in the RoE")
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 6.0
        seen_netblocks: set[str] = set()

        for i, domain in enumerate(sorted(domains), start=1):
            ctx.check_alive()
            await ctx.progress(f"rdap: {domain}", current=i, total=len(domains))
            await self._domain(ctx, domain)
            for ip in await self._resolve(resolver, domain):
                ctx.check_alive()
                await self._ip(ctx, ip, domain, seen_netblocks)

    async def _domain(self, ctx: ModuleContext, domain: str) -> None:
        # rdap.org bootstraps to the authoritative RDAP server, which for some
        # TLDs (.org via PIR) is slow - give it room.
        data = await fetch_json(
            ctx, f"https://rdap.org/domain/{domain}", subject=domain, source="RDAP",
            timeout=45.0, ok_statuses=(200,),
        )
        if not isinstance(data, dict):
            return

        entities = data.get("entities") or []
        registrant = next((e for e in entities if "registrant" in (e.get("roles") or [])), None)
        registrar = next((e for e in entities if "registrar" in (e.get("roles") or [])), None)
        reg_org = _entity_org(registrant) if registrant else None
        registrar_name = _entity_org(registrar) if registrar else None

        events = {e.get("eventAction"): e.get("eventDate")
                  for e in (data.get("events") or []) if e.get("eventAction")}
        statuses = [str(s).lower() for s in (data.get("status") or [])]
        nameservers = sorted(
            (ns.get("ldhName") or "").lower().strip(".")
            for ns in (data.get("nameservers") or []) if ns.get("ldhName")
        )

        await ctx.add_evidence(
            subject_type="domain",
            subject_value=domain,
            raw_data={
                "source": "RDAP", "registrant_org": reg_org, "registrar": registrar_name,
                "registration": events.get("registration"),
                "last_changed": events.get("last changed") or events.get("last update of RDAP database"),
                "expiration": events.get("expiration"),
                "status": statuses, "nameservers": nameservers,
            },
            summary=(
                f"{domain}: registrar {registrar_name or '?'}"
                + (f", registrant {reg_org}" if reg_org else "")
            ),
        )
        if reg_org:
            await ctx.add_evidence(
                subject_type="organization", subject_value=reg_org,
                raw_data={"source": "RDAP registrant", "domain": domain},
                summary=f"{reg_org} - registrant of {domain}",
                relationships=[{"type": "owns", "target_type": "domain",
                                "target_value": domain}],
            )

        notable = [s for s in statuses if s in _NOTABLE_STATUS]
        expiring = _within_days(events.get("expiration"), 30)
        if notable or expiring:
            bits = []
            if notable:
                bits.append("status " + ", ".join(notable))
            if expiring:
                bits.append(f"expires {events.get('expiration', '')[:10]}")
            await ctx.add_evidence(
                subject_type="domain_status", subject_value=domain,
                raw_data={"source": "RDAP", "status": statuses,
                          "expiration": events.get("expiration"), "interest": "notable"},
                summary=f"{domain}: " + "; ".join(bits),
            )

    async def _ip(
        self, ctx: ModuleContext, ip: str, domain: str, seen: set[str]
    ) -> None:
        data = await fetch_json(
            ctx, f"https://rdap.org/ip/{ip}", subject=ip, source="RDAP-IP", timeout=20.0,
        )
        if not isinstance(data, dict):
            return
        cidr = _cidr_of(data)
        if not cidr or cidr in seen:
            return
        seen.add(cidr)
        entities = data.get("entities") or []
        host_org = next(
            (_entity_org(e) for e in entities
             if {"registrant", "administrative"} & set(e.get("roles") or []) and _entity_org(e)),
            data.get("name"),
        )
        await ctx.add_evidence(
            subject_type="netblock", subject_value=cidr,
            raw_data={"source": "RDAP-IP", "resolved_from": domain, "ip": ip,
                      "net_name": data.get("name"), "host_org": host_org},
            summary=f"{cidr} ({data.get('name') or '?'}) hosts {domain} @ {ip}"
                    + (f" - {host_org}" if host_org else ""),
        )
        if host_org:
            await ctx.add_evidence(
                subject_type="organization", subject_value=str(host_org),
                raw_data={"source": "RDAP-IP", "netblock": cidr},
                summary=f"{host_org} - operates netblock {cidr}",
                relationships=[{"type": "owns", "target_type": "netblock",
                                "target_value": cidr}],
            )

    @staticmethod
    async def _resolve(resolver, domain: str) -> list[str]:  # noqa: ANN001
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                ans = await resolver.resolve(domain, rtype, raise_on_no_answer=False)
            except dns.exception.DNSException:
                continue
            for rd in (ans.rrset or []):
                out.append(rd.to_text())
        return out[:4]


def _cidr_of(data: dict) -> str | None:
    for c in data.get("cidr0_cidrs") or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if pfx and length is not None:
            return f"{pfx}/{length}"
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        try:
            import ipaddress
            nets = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)))
            return str(nets[0]) if nets else None
        except (ValueError, TypeError):
            return None
    return None


def _within_days(iso: str | None, days: int) -> bool:
    if not iso:
        return False
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return timedelta_days(dt) <= days
    except ValueError:
        return False


def timedelta_days(dt: datetime) -> float:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).total_seconds() / 86400
