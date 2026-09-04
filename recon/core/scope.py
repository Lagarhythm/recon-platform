"""Scope Manager.

Scope safety is a first-class requirement. This module answers two questions
for any target, and both answers are advisory to the caller - enforcement
policy (flag vs. block vs. require-override) lives in the orchestrator, not
here.

  1. classify(target) -> IN_SCOPE | FLAGGED | EXCLUDED
  2. check_window(now)  -> WITHIN | BEFORE | AFTER | NO_WINDOW

Default posture: anything not provably in-scope is FLAGGED, never silently
treated as in-scope.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from recon.core.roe import RoEConfig
from recon.models.enums import ScopeStatus, WindowStatus


@dataclass(frozen=True)
class ScopeDecision:
    status: ScopeStatus
    target: str
    host: str
    reason: str

    @property
    def is_in_scope(self) -> bool:
        return self.status is ScopeStatus.IN_SCOPE


def extract_host(target: str) -> str:
    """Reduce any target form (URL, host:port, bare host/IP, IPv6) to a host."""
    t = target.strip()
    if "://" in t:
        t = urlsplit(t).netloc or urlsplit(t).path
    # strip userinfo
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    # bracketed IPv6, optionally with port
    if t.startswith("["):
        return t[1 : t.index("]")].lower()
    # host:port - only treat trailing :NNNN as a port, leave bare IPv6 alone
    if t.count(":") == 1:
        left, right = t.split(":")
        if right.isdigit():
            t = left
    # strip path, then the DNS root label(s) and case - so "mail.example.com."
    # and "mail.example.com" classify identically and can't dodge an exclusion.
    t = t.split("/")[0]
    return t.strip().rstrip(".").lower()


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _host_matches_pattern(host: str, pattern: str) -> bool:
    host = host.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base)
    return host == pattern


def _ip_in_any(ip: ipaddress._BaseAddress, cidrs: list[str]) -> str | None:
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr)
        if ip.version == net.version and ip in net:
            return cidr
    return None


class ScopeManager:
    def __init__(self, roe: RoEConfig) -> None:
        self.roe = roe

    def classify(self, target: str, resolved_ips: list[str] | None = None) -> ScopeDecision:
        host = extract_host(target)
        ip = _as_ip(host)
        candidates = [ip] if ip is not None else []
        for rip in resolved_ips or []:
            parsed = _as_ip(rip)
            if parsed is not None:
                candidates.append(parsed)

        excl = self.roe.scope.excluded
        insc = self.roe.scope.in_scope

        # --- Exclusions win outright ------------------------------------
        if ip is None:
            if host in excl.hosts:
                return ScopeDecision(ScopeStatus.EXCLUDED, target, host,
                                     f"host {host} is explicitly excluded")
            for pat in excl.domains:
                if _host_matches_pattern(host, pat):
                    return ScopeDecision(ScopeStatus.EXCLUDED, target, host,
                                         f"host matches excluded domain pattern {pat}")
        for cand in candidates:
            hit = _ip_in_any(cand, excl.cidrs)
            if hit:
                return ScopeDecision(ScopeStatus.EXCLUDED, target, host,
                                     f"{cand} falls in excluded CIDR {hit}")

        # --- Positive in-scope match ----------------------------------
        if ip is None:
            if host in insc.hosts:
                return ScopeDecision(ScopeStatus.IN_SCOPE, target, host,
                                     f"host {host} explicitly in scope")
            for pat in insc.domains:
                if _host_matches_pattern(host, pat):
                    return ScopeDecision(ScopeStatus.IN_SCOPE, target, host,
                                         f"host matches in-scope domain pattern {pat}")
        for cand in candidates:
            hit = _ip_in_any(cand, insc.cidrs)
            if hit:
                return ScopeDecision(ScopeStatus.IN_SCOPE, target, host,
                                     f"{cand} falls in in-scope CIDR {hit}")

        return ScopeDecision(
            ScopeStatus.FLAGGED, target, host,
            "target does not match any in-scope domain, host, or CIDR",
        )

    def check_window(self, now: datetime | None = None) -> WindowStatus:
        window = self.roe.engagement.authorized_window
        if window is None:
            return WindowStatus.NO_WINDOW
        now = now or datetime.now(timezone.utc)
        if now < window.start:
            return WindowStatus.BEFORE
        if now > window.end:
            return WindowStatus.AFTER
        return WindowStatus.WITHIN


def lint_roe(roe: RoEConfig) -> list[str]:
    """Non-fatal advisories surfaced to the operator at engagement creation."""
    warnings: list[str] = []
    insc = roe.scope.in_scope
    for domain in insc.domains:
        if not domain.startswith("*.") and f"*.{domain}" not in insc.domains:
            warnings.append(
                f"in_scope domain '{domain}' has no matching '*.{domain}' entry - "
                f"subdomains of {domain} will be FLAGGED, not in-scope. Add the wildcard "
                f"if subdomains are authorised."
            )
    if roe.engagement.authorized_window is None:
        warnings.append("no authorized_window set - time-window checks will be skipped.")
    elif roe.engagement.authorized_window.enforce.value == "hard":
        warnings.append(
            "authorized_window.enforce is 'hard' - this is PARSED but a hard "
            "time-window block is not wired into the scan gate yet (later wave). "
            "Out-of-window activity is currently WARNED, not blocked."
        )
    if not roe.evasion.user_agents:
        warnings.append("no user_agents listed - active modules will use a single default UA.")
    if roe.osint.enabled:
        seeds = set(roe.osint.seed_domains)
        unscoped = sorted(seeds - set(insc.domains))
        if unscoped:
            warnings.append(
                f"osint.seed_domains {unscoped} are pivot points only - OSINT will "
                f"enrich them but passive/active modules will not touch them unless "
                f"they are also listed under scope.in_scope.domains."
            )
    if roe.llm.analysis_enabled:
        warnings.append(
            "llm.analysis_enabled is TRUE - correlated recon data for this engagement "
            "will be sent to the configured remote LLM endpoint. Confirm the RoE permits "
            "third-party data processing."
        )
    return warnings
