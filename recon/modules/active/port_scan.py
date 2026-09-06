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
import socket
import xml.etree.ElementTree as ET

from recon.models.enums import ModulePhase, ScopeStatus, SkipReason
from recon.modules._targets import is_safe_target as _is_safe_target
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.external import find_binary, run_command

_HOST_TIMEOUT = "5m"
_MODULE_TIMEOUT = 45 * 60

# ``_is_safe_target`` is re-exported from ``recon.modules._targets`` (the shared
# safe-form helper ``resolve_targets`` applies centrally). Kept as a name here
# for the adversarial regression tests that import it from this module.


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
            await ctx.mark_no_input(SkipReason.MISSING_BINARY)
            return

        # Same-run target handoff (P0-2): resolve_targets reads THIS run's
        # Evidence directly, so a dependency (dns) that ran earlier in the same
        # invocation is visible without waiting for end-of-run correlation.
        # include_prior_assets keeps the pre-P0-2 behaviour of also scanning the
        # engagement's already-correlated in-scope assets. Scope + safe-form
        # filtering happen centrally in resolve_targets; the EXCLUDED /
        # unsafe-form checks below are kept only as defence in depth.
        resolution = await ctx.resolve_targets(
            "ip", "hostname", include_prior_assets=True
        )
        await ctx.record_target_accounting(resolution)
        targets = await _dedupe_by_ip(
            {
                c.value
                for c in resolution.eligible
                if _is_safe_target(c.value)
                and ctx.scope.classify(c.value).status is not ScopeStatus.EXCLUDED
            }
        )
        if not targets:
            await ctx.progress("no eligible hosts to port-scan")
            await ctx.mark_no_input(SkipReason.ZERO_ELIGIBLE_TARGETS)
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
