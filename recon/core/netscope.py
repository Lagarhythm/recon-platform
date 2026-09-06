"""Single canonicaliser for IP addresses and CIDR networks on the active-scan
authorization boundary (P0-1 / G0).

Security invariant: exactly one component decides what a host address is, what a
network is, and when one contains the other. The permit resolver and the active
executor both route every address / network decision through here, so an
attacker cannot smuggle a non-canonical form (leading zeros, an IPv6 zone id, a
``host:port``, a URL, embedded host bits) past one check that another check would
have rejected.

Every function raises :class:`NetscopeError` (a ``ValueError``) rather than
returning a sentinel, so a caller cannot accidentally treat a parse failure as
"allowed".
"""

from __future__ import annotations

import ipaddress

_Address = ipaddress.IPv4Address | ipaddress.IPv6Address
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class NetscopeError(ValueError):
    """A value is not a canonical single IP address or CIDR network."""


def parse_ip(value: str) -> _Address:
    """Parse ``value`` as exactly one canonical IP address.

    Rejects surrounding whitespace, an IPv6 zone id, anything with a prefix
    length, and every form ``ipaddress`` itself rejects (leading zeros,
    ``host:port``, hostnames, URLs).
    """
    if not isinstance(value, str):
        raise NetscopeError(f"expected a str address, got {type(value).__name__}")
    if value.strip() != value:
        raise NetscopeError(f"address {value!r} has surrounding whitespace")
    if not value:
        raise NetscopeError("empty address")
    if "%" in value:
        raise NetscopeError(f"address {value!r} carries an IPv6 zone id")
    if "/" in value:
        raise NetscopeError(f"address {value!r} looks like a network, not a host")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise NetscopeError(f"{value!r} is not a canonical IP address: {exc}") from exc


def canonical_ip(value: str) -> str:
    """Return the canonical string form of a single IP address."""
    return str(parse_ip(value))


def parse_cidr(value: str) -> _Network:
    """Parse ``value`` as a canonical CIDR network.

    ``strict=True`` rejects a network whose host bits are set (``10.0.0.1/24``),
    which is the "non-canonical" form the resolver must refuse before expansion.
    """
    if not isinstance(value, str):
        raise NetscopeError(f"expected a str network, got {type(value).__name__}")
    if value.strip() != value:
        raise NetscopeError(f"network {value!r} has surrounding whitespace")
    if not value:
        raise NetscopeError("empty network")
    if "%" in value:
        raise NetscopeError(f"network {value!r} carries an IPv6 zone id")
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise NetscopeError(
            f"{value!r} is not a canonical CIDR network: {exc}"
        ) from exc


def canonical_cidr(value: str) -> str:
    """Return the canonical string form of a CIDR network."""
    return str(parse_cidr(value))


def contains(cidr: str, ip: str) -> bool:
    """True iff canonical ``ip`` falls inside canonical ``cidr`` (same family)."""
    net = parse_cidr(cidr)
    addr = parse_ip(ip)
    return addr.version == net.version and addr in net


def overlaps(cidr_a: str, cidr_b: str) -> bool:
    """True iff the two canonical networks share any address (same family)."""
    a = parse_cidr(cidr_a)
    b = parse_cidr(cidr_b)
    return a.version == b.version and a.overlaps(b)
