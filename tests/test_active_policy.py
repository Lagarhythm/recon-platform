"""BOOTSTRAP_POLICY carries exactly the Security-approved D0 bootstrap numbers
and nothing that would authorize CIDR traffic (G0 Section 2.6)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from recon.core.active_policy import BOOTSTRAP_POLICY, active_policy
from recon.models.authz import DNS_CONNECT_BIND_V1


def test_only_dns_connect_bind_is_allowlisted() -> None:
    assert BOOTSTRAP_POLICY.method_allowlist == frozenset({DNS_CONNECT_BIND_V1})
    assert not BOOTSTRAP_POLICY.allows_method("cidr_syn_v1")
    assert BOOTSTRAP_POLICY.allows_method(DNS_CONNECT_BIND_V1)


def test_bootstrap_numbers_match_the_security_gate() -> None:
    assert BOOTSTRAP_POLICY.version == "p1"
    assert BOOTSTRAP_POLICY.max_addresses_per_run == 16
    assert BOOTSTRAP_POLICY.max_aggregate_cidr_addresses == 256
    assert BOOTSTRAP_POLICY.rate_for(DNS_CONNECT_BIND_V1) == 2.0
    assert BOOTSTRAP_POLICY.concurrency_for(DNS_CONNECT_BIND_V1) == 2
    assert BOOTSTRAP_POLICY.probe_timeout_seconds == 2.0
    assert BOOTSTRAP_POLICY.max_retries == 0
    assert BOOTSTRAP_POLICY.total_time_budget_seconds == 30.0
    assert BOOTSTRAP_POLICY.min_ipv4_prefix == 24
    assert BOOTSTRAP_POLICY.min_ipv6_prefix == 120
    assert BOOTSTRAP_POLICY.reject_overlapping_cidrs is True


def test_d0_has_exactly_one_approved_port() -> None:
    ports = BOOTSTRAP_POLICY.ports_for(DNS_CONNECT_BIND_V1)
    assert isinstance(ports, tuple) and len(ports) == 1


def test_policy_is_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        BOOTSTRAP_POLICY.version = "p2"  # type: ignore[misc]


def test_active_policy_lookup() -> None:
    assert active_policy() is BOOTSTRAP_POLICY
    assert active_policy("p1") is BOOTSTRAP_POLICY
    with pytest.raises(KeyError):
        active_policy("nope")


def test_missing_per_method_config_raises_not_defaults() -> None:
    with pytest.raises(KeyError):
        BOOTSTRAP_POLICY.rate_for("cidr_syn_v1")
    with pytest.raises(KeyError):
        BOOTSTRAP_POLICY.ports_for("cidr_syn_v1")
