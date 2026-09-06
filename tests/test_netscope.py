"""The single IP/CIDR canonicaliser on the active-scan boundary (G0)."""

from __future__ import annotations

import pytest

from recon.core.netscope import (
    NetscopeError,
    canonical_cidr,
    canonical_ip,
    contains,
    overlaps,
    parse_ip,
)


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "203.0.113.5:443",
        "203.0.113.5/32",
        "010.0.0.1",  # leading zero - ambiguous, rejected by ipaddress
        " 203.0.113.5",
        "203.0.113.5 ",
        "fe80::1%eth0",  # zone id
        "",
        "not-an-ip",
        "http://203.0.113.5",
    ],
)
def test_parse_ip_rejects_non_canonical_forms(value: str) -> None:
    with pytest.raises(NetscopeError):
        parse_ip(value)


def test_parse_ip_rejects_non_str() -> None:
    with pytest.raises(NetscopeError):
        parse_ip(203)  # type: ignore[arg-type]


def test_canonical_ip_roundtrips_v4_and_v6() -> None:
    assert canonical_ip("203.0.113.5") == "203.0.113.5"
    assert canonical_ip("2001:db8::1") == "2001:db8::1"
    # compressed / expanded forms normalise to the same string
    assert canonical_ip("2001:0db8:0000::0001") == "2001:db8::1"


def test_canonical_cidr_rejects_host_bits_set() -> None:
    with pytest.raises(NetscopeError):
        canonical_cidr("10.0.0.1/24")
    assert canonical_cidr("10.0.0.0/24") == "10.0.0.0/24"


def test_contains_is_family_aware() -> None:
    assert contains("203.0.113.0/24", "203.0.113.9")
    assert not contains("203.0.113.0/24", "203.0.114.9")
    # v4 address vs v6 network -> not contained, no crash
    assert not contains("2001:db8::/32", "203.0.113.9")


def test_contains_rejects_a_bad_operand() -> None:
    with pytest.raises(NetscopeError):
        contains("203.0.113.0/24", "example.com")


def test_overlaps() -> None:
    assert overlaps("10.0.0.0/8", "10.1.2.0/24")
    assert not overlaps("10.0.0.0/24", "10.0.1.0/24")
    assert not overlaps("10.0.0.0/24", "2001:db8::/64")
