"""Port / Service Scanner (active) - wraps nmap.

Scans only in-scope IPs and hostnames (or flagged/excluded ones too when the
run was started with an out-of-scope override). Maps the RoE request rate onto
nmap's ``--max-rate`` so the scan can't exceed the engagement's agreed volume.
SYN scan is used only when the process has the privilege for it, otherwise a
TCP connect scan.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import xml.etree.ElementTree as ET

from recon.models.enums import ModulePhase, ScopeStatus
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.external import find_binary, run_command

_HOST_TIMEOUT = "5m"
_MODULE_TIMEOUT = 45 * 60

_HOSTNAME_RE = re.compile(
    r"^(?![-.])[A-Za-z0-9_.-]{1,253}(?<![-.])$"
)


def _is_safe_target(t: str) -> bool:
    """Reject anything that isn't a plain single IP or hostname - stops a
    crafted asset value ('-oN /etc/x', '--script ...') becoming an nmap
    argument, and stops an over-broad CIDR ('0.0.0.0/0') from being scanned.
    Asset values are always single hosts, so a network of more than /24 (v4) /
    /120 (v6) is refused."""
    t = t.strip()
    if not t or t.startswith("-"):
        return False
    try:
        net = ipaddress.ip_network(t, strict=False)
        if net.version == 4:
            return net.prefixlen >= 24
        return net.prefixlen >= 120
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(t))


async def _dedupe_by_ip(targets: set[str]) -> set[str]:
    """Collapse hostnames that resolve to the same address to one target.

    A homelab RoE often lists several names for one box (homer.lan, jellyfin.lan,
    ...); scanning each is N x the same 1000-port sweep against one host, and
    with a low RoE rate cap that is the difference between one minute and ten.
    A literal IP always wins over a hostname for the same address.
    """
    async def _resolve(name: str) -> str | None:
        try:
            ipaddress.ip_address(name)
            return name
        except ValueError:
            pass
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                name, None, proto=socket.IPPROTO_TCP
            )
            return infos[0][4][0] if infos else None
        except (socket.gaierror, OSError, IndexError):
            return None

    by_ip: dict[str, str] = {}
    unresolved: set[str] = set()
    for name in sorted(targets):
        ip = await _resolve(name)
        if ip is None:
            unresolved.add(name)
            continue
        cur = by_ip.get(ip)
        # prefer a literal IP target; otherwise keep the first name seen
        if cur is None or (cur != ip and name == ip):
            by_ip[ip] = name
    return set(by_ip.values()) | unresolved


def _can_syn_scan() -> bool:
    if os.name != "posix":
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover
        return False


@register
class PortScanModule(ReconModule):
    name = "port_scan"
    phase = ModulePhase.ACTIVE
    depends_on = ("dns",)
    description = "nmap: TCP port + service/version detection on in-scope hosts"
    requires_binary = "nmap"

    async def run(self, ctx: ModuleContext) -> None:
        nmap = find_binary("nmap")
        if not nmap:
            await ctx.add_error(
                subject_value="nmap",
                summary="nmap not found on PATH - port_scan skipped",
                raw_data={"module": "port_scan"},
            )
            return

        targets = await self._targets(ctx)
        if not targets:
            await ctx.progress("no in-scope hosts to port-scan")
            return

        ctx.check_alive()
        scan_type = "-sS" if _can_syn_scan() else "-sT"
        max_rate = max(1, int(round(ctx.roe.rate_limits.max_requests_per_second)))
        argv = [
            nmap, "-oX", "-", scan_type, "-sV", "--top-ports", "1000",
            "-Pn",
            # -n: skip reverse DNS. Targets are already resolved, and PTR
            # lookups for a homelab / CGNAT range just stall on the resolver.
            # -T4: don't sit on filtered ports for minutes. Volume is still
            # capped by --max-rate from the RoE, so this only tightens probe
            # timeouts / retries, not the request rate.
            "-n", "-T4", "--version-intensity", "5",
            "--host-timeout", _HOST_TIMEOUT,
            "--max-rate", str(max_rate),
            *sorted(targets),
        ]
        await ctx.progress(
            f"nmap {scan_type} on {len(targets)} host(s) at max-rate {max_rate}",
        )
        await ctx.audit_action(
            target=f"nmap:{len(targets)} hosts",
            request_detail={"argv": argv},
            response_meta=None,
            in_scope_status=(
                ScopeStatus.IN_SCOPE if not ctx.allow_out_of_scope else ScopeStatus.FLAGGED
            ),
            override_used=ctx.allow_out_of_scope,
        )

        result = await run_command(argv, timeout=_MODULE_TIMEOUT)
        if result.timed_out:
            await ctx.add_error(
                subject_value="nmap",
                summary=f"nmap timed out after {_MODULE_TIMEOUT}s",
                raw_data={"argv": argv},
            )
            return
        if result.returncode != 0 and not result.stdout.strip():
            await ctx.add_error(
                subject_value="nmap",
                summary=f"nmap exited {result.returncode}",
                raw_data={"stderr": result.stderr[:2000]},
            )
            return

        await self._parse(ctx, result.stdout)

    async def _targets(self, ctx: ModuleContext) -> set[str]:
        oos = ctx.allow_out_of_scope
        out: set[str] = set()
        out.update(await ctx.known_assets("ip", in_scope_only=not oos))
        out.update(await ctx.known_assets("subdomain", "domain", in_scope_only=not oos))
        safe = {
            t for t in out
            if _is_safe_target(t)
            and ctx.scope.classify(t).status is not ScopeStatus.EXCLUDED
        }
        return await _dedupe_by_ip(safe)

    async def _parse(self, ctx: ModuleContext, xml_text: str) -> None:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            await ctx.add_error(
                subject_value="nmap", summary=f"could not parse nmap XML: {exc}",
                raw_data={},
            )
            return

        for host_el in root.findall("host"):
            ctx.check_alive()
            addr = None
            for a in host_el.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
                    break
            hostnames = [h.get("name") for h in host_el.findall("hostnames/hostname") if h.get("name")]
            display_host = hostnames[0] if hostnames else addr
            if not display_host:
                continue

            status_el = host_el.find("status")
            if status_el is not None and status_el.get("state") == "up":
                if addr:
                    await ctx.add_evidence(
                        subject_type="ip", subject_value=addr,
                        raw_data={"nmap_state": "up", "hostnames": hostnames},
                        summary=f"{display_host} is up",
                    )
                for hn in hostnames:
                    await ctx.add_evidence(
                        subject_type="subdomain" if hn.count(".") >= 2 else "domain",
                        subject_value=hn,
                        raw_data={"nmap_state": "up", "resolved_ip": addr},
                        summary=f"{hn} is up ({addr})" if addr else f"{hn} is up",
                    )

            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = port_el.get("portid")
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc = svc_el.attrib if svc_el is not None else {}
                banner = svc.get("product", "")
                if svc.get("version"):
                    banner = f"{banner} {svc['version']}".strip()
                await ctx.add_evidence(
                    subject_type="service",
                    subject_value=f"{addr or display_host}:{portid}",
                    raw_data={
                        "host": addr or display_host,
                        "port": int(portid) if portid else None,
                        "proto": proto,
                        "name": svc.get("name"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "extrainfo": svc.get("extrainfo"),
                        "banner": banner or None,
                        "cpe": [c.text for c in svc_el.findall("cpe")] if svc_el is not None else [],
                    },
                    summary=(
                        f"{addr or display_host}:{portid}/{proto} "
                        f"{svc.get('name', 'unknown')} {banner}".strip()
                    ),
                    relationships=(
                        [{"type": "hosts", "target_type": "ip", "target_value": addr}]
                        if addr else None
                    ),
                )
