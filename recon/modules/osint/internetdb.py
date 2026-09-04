"""Shodan InternetDB (OSINT).

``https://internetdb.shodan.io/<ipv4>`` is completely keyless - no account, no
token. One GET per in-scope resolved IPv4 returns the open ports, CPEs,
hostnames, tags and **known CVEs** that Shodan already computed from its own
periodic internet-wide scan. **Zero packets reach the target** - this is a
lookup against Shodan's dataset, audited as a third-party ``n/a`` call.

Feeds ``cve_correlate`` (Wave 2) for free via the ``service`` + ``cve``
evidence it emits.
"""

from __future__ import annotations

import ipaddress

from recon.models.enums import ModulePhase, ScopeStatus
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register

_URL = "https://internetdb.shodan.io/{ip}"
_SOURCE = "internetdb"


@register
class InternetDBModule(ReconModule):
    name = "internetdb"
    phase = ModulePhase.OSINT
    depends_on = ("dns",)
    description = "Shodan InternetDB: keyless open ports / CPEs / CVEs per resolved IP"
    max_runtime_seconds = 10 * 60

    async def run(self, ctx: ModuleContext) -> None:
        candidates = sorted({
            ip.strip() for ip in await ctx.known_values("ip") if ip and ip.strip()
        })
        # IPv4-only endpoint; never look up an EXCLUDED address.
        targets = [
            ip for ip in candidates
            if _is_ipv4(ip)
            and ctx.scope.classify(ip).status is not ScopeStatus.EXCLUDED
        ]
        if not targets:
            await ctx.progress("internetdb: no in-scope IPv4 addresses resolved yet")
            return

        await ctx.progress(
            f"internetdb: {len(targets)} IPv4 address(es)", count=len(targets)
        )
        for i, ip in enumerate(targets, start=1):
            ctx.check_alive()
            await ctx.progress(f"internetdb: {ip}", current=i, total=len(targets))
            await self._lookup(ctx, ip)

    async def _lookup(self, ctx: ModuleContext, ip: str) -> None:
        url = _URL.format(ip=ip)
        try:
            resp = await ctx.http.request(
                "GET", url, is_target=False, timeout=20.0, follow_redirects=True
            )
        except Exception as exc:  # noqa: BLE001 - network/timeout/protocol, all non-fatal
            await ctx.add_error(
                subject_value=ip,
                summary=f"internetdb request failed: {type(exc).__name__}",
                raw_data={"source": _SOURCE, "url": url, "error": str(exc)[:300]},
            )
            return

        if resp.status_code == 404:
            # Shodan has nothing on this IP - expected, not an error.
            return
        if resp.status_code != 200:
            await ctx.add_error(
                subject_value=ip,
                summary=f"internetdb returned HTTP {resp.status_code}",
                raw_data={"source": _SOURCE, "url": url, "status": resp.status_code},
            )
            return
        try:
            data = resp.json()
        except ValueError:
            await ctx.add_error(
                subject_value=ip,
                summary="internetdb returned invalid JSON",
                raw_data={"source": _SOURCE, "url": url},
            )
            return
        if not isinstance(data, dict):
            return

        ports = [p for p in (data.get("ports") or []) if isinstance(p, int)]
        cpes = [str(c) for c in (data.get("cpes") or []) if c]
        hostnames = sorted({
            h.strip().lower().strip(".") for h in (data.get("hostnames") or [])
            if isinstance(h, str) and h.strip()
        })
        tags = [str(t) for t in (data.get("tags") or []) if t]
        vulns = sorted({
            v.strip().upper() for v in (data.get("vulns") or [])
            if isinstance(v, str) and v.strip().upper().startswith("CVE-")
        })

        for port in sorted(ports):
            await ctx.add_evidence(
                subject_type="service",
                subject_value=f"{ip}:{port}",
                raw_data={
                    "source": _SOURCE, "host": ip, "port": port, "proto": "tcp",
                    "cpe": cpes, "tags": tags,
                },
                summary=f"{ip}:{port} open (Shodan InternetDB)",
                relationships=[{"type": "hosts", "target_type": "ip", "target_value": ip}],
            )

        for host in hostnames:
            stype = "subdomain" if host.count(".") >= 2 else "domain"
            await ctx.add_evidence(
                subject_type=stype,
                subject_value=host,
                raw_data={"source": _SOURCE, "ip": ip},
                summary=f"{host} - PTR/hostname for {ip} (Shodan InternetDB)",
                relationships=[{"type": "resolves_to", "target_type": "ip",
                                "target_value": ip}],
            )

        for cve in vulns:
            # No `affects` graph edge yet - that relationship type + proper
            # finding<->service linkage is cve_correlate's job (Wave 2). The
            # ip / ports / cpes in raw_data carry the association meanwhile.
            await ctx.add_evidence(
                subject_type="cve",
                subject_value=cve,
                raw_data={
                    "source": _SOURCE, "ip": ip, "ports": sorted(ports),
                    "cpes": cpes, "interest": "notable",
                },
                summary=f"{cve} on {ip} (Shodan InternetDB known-vuln list)",
            )

        if ports or vulns:
            await ctx.progress(
                f"internetdb {ip}: {len(ports)} port(s), {len(vulns)} CVE(s)"
            )


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False
