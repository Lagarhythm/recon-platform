"""Blast-radius policy bundle for the P0-1 active-scan surface (G0 Section 2.6).

Not a DB table - a versioned in-code constant. ``BOOTSTRAP_POLICY.version`` is
pinned into every :class:`~recon.models.authz.AuthorizationSnapshot` at
active-checkpoint acknowledgement and re-checked at permit mint and again at
dispatch, so editing this module cannot silently loosen an in-flight run: the
run keeps the version it was authorized under and a mismatch fails closed.

Security gate (G0): for P0-1 the only approved method profile is
``dns_connect_bind_v1``. CIDR discovery profiles are DISABLED - their
rate/concurrency numbers are deliberately absent and the resolver refuses to
mint a permit for any method not in :attr:`ActiveScanPolicy.method_allowlist`.
"""

from __future__ import annotations

from dataclasses import dataclass

from recon.models.authz import DNS_CONNECT_BIND_V1

__all__ = ["BOOTSTRAP_POLICY", "DNS_CONNECT_BIND_V1", "ActiveScanPolicy", "active_policy"]


@dataclass(frozen=True)
class ActiveScanPolicy:
    """Immutable per-version limits. Compared by ``version`` on the boundary."""

    version: str
    method_allowlist: frozenset[str]
    max_addresses_per_run: int
    max_aggregate_cidr_addresses: int
    per_method_rate: dict[str, float]
    per_method_concurrency: dict[str, int]
    per_method_ports: dict[str, tuple[int, ...]]
    probe_timeout_seconds: float
    max_retries: int
    total_time_budget_seconds: float
    #: wall-clock ceiling for a permit whose operation shells out (port_scan ->
    #: nmap). The connect-time bind uses ``probe_timeout_seconds``; a full
    #: service sweep needs minutes, not the 2s D0 connect budget.
    subprocess_timeout_seconds: float = 300.0
    min_ipv4_prefix: int = 24
    min_ipv6_prefix: int = 120
    reject_overlapping_cidrs: bool = True

    def allows_method(self, method_profile_id: str) -> bool:
        return method_profile_id in self.method_allowlist

    def rate_for(self, method_profile_id: str) -> float:
        try:
            return self.per_method_rate[method_profile_id]
        except KeyError:
            raise KeyError(
                f"no per-method rate configured for {method_profile_id!r} in "
                f"policy {self.version!r}"
            ) from None

    def concurrency_for(self, method_profile_id: str) -> int:
        try:
            return self.per_method_concurrency[method_profile_id]
        except KeyError:
            raise KeyError(
                f"no per-method concurrency configured for {method_profile_id!r} "
                f"in policy {self.version!r}"
            ) from None

    def ports_for(self, method_profile_id: str) -> tuple[int, ...]:
        try:
            return self.per_method_ports[method_profile_id]
        except KeyError:
            raise KeyError(
                f"no port set configured for {method_profile_id!r} in policy "
                f"{self.version!r}"
            ) from None


# Conservative bootstrap values, approved by Security as a bootstrap for
# ``dns_connect_bind_v1`` only (G0 security review, "Initial policy values").
#
# NOTE (PROPOSED, needs Security sign-off): the security gate specifies "exactly
# one approved TCP port per authorized hostname" but never fixes the number.
# 443 is chosen as the least-intrusive, most-likely-listening connect-only
# liveness port. Change here if Security nominates a different single port.
BOOTSTRAP_POLICY = ActiveScanPolicy(
    version="p1",
    method_allowlist=frozenset({DNS_CONNECT_BIND_V1}),  # CIDR profiles DISABLED
    max_addresses_per_run=16,
    max_aggregate_cidr_addresses=256,
    per_method_rate={DNS_CONNECT_BIND_V1: 2.0},
    per_method_concurrency={DNS_CONNECT_BIND_V1: 2},
    per_method_ports={DNS_CONNECT_BIND_V1: (443,)},
    probe_timeout_seconds=2.0,
    max_retries=0,
    total_time_budget_seconds=30.0,
    min_ipv4_prefix=24,
    min_ipv6_prefix=120,
    reject_overlapping_cidrs=True,
)

_POLICIES: dict[str, ActiveScanPolicy] = {BOOTSTRAP_POLICY.version: BOOTSTRAP_POLICY}


def active_policy(version: str | None = None) -> ActiveScanPolicy:
    """Return the policy bundle for ``version`` (default: the current bootstrap).

    A run pins its version at authorization; the boundary looks it back up here
    so a superseded run is still evaluated against the rules it agreed to.
    """
    if version is None:
        return BOOTSTRAP_POLICY
    try:
        return _POLICIES[version]
    except KeyError:
        raise KeyError(f"unknown ActiveScanPolicy version {version!r}") from None
