"""Shared DNS helpers for the subdomain modules.

``subdomain_brute`` (active) and ``subdomain_permute`` (passive, Wave 1) both
resolve candidate names and both must guard against wildcard DNS - a zone that
answers *every* label makes every "hit" a false positive. Keeping the logic
here means one implementation and one place to fix it.

Every query is gated through the caller's shared rate limiter (the scan-run
token bucket) so these modules never exceed the RoE request rate.
"""

from __future__ import annotations

import secrets

import dns.exception
import dns.resolver

# A/AAAA/CNAME is enough to decide "does this name exist"; the brute module
# also stores the records, so it passes the full tuple.
DEFAULT_RECORD_TYPES = ("A", "AAAA", "CNAME")


async def resolve_records(
    resolver,  # noqa: ANN001 - dns.asyncresolver.Resolver
    fqdn: str,
    limiter=None,  # noqa: ANN001
    record_types: tuple[str, ...] = DEFAULT_RECORD_TYPES,
) -> list[dict]:
    """Return ``dns_record`` dicts for ``fqdn``, or ``[]`` if it does not resolve.

    ``NXDOMAIN`` on any type short-circuits to ``[]`` (the name is gone); other
    DNS exceptions on a single type are skipped so a partial answer still counts.
    """
    found: list[dict] = []
    for rtype in record_types:
        if limiter is not None:
            await limiter.acquire()
        try:
            answer = await resolver.resolve(fqdn, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.DNSException:
            continue
        rrset = getattr(answer, "rrset", None)
        if not rrset:
            continue
        for rd in rrset:
            found.append(
                {
                    "name": fqdn,
                    "rtype": rtype,
                    "value": rd.to_text(),
                    "ttl": getattr(rrset, "ttl", None),
                }
            )
    return found


async def is_zone(resolver, name: str, limiter=None) -> bool:  # noqa: ANN001
    """True if ``name`` looks like a real DNS zone (answers SOA or NS)."""
    for rtype in ("SOA", "NS"):
        if limiter is not None:
            await limiter.acquire()
        try:
            answer = await resolver.resolve(name, rtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
            continue
        if getattr(answer, "rrset", None):
            return True
    return False


async def wildcard_answers(
    resolver, apex: str, limiter=None, probes: int = 2  # noqa: ANN001
) -> set[str]:
    """Resolved values for random labels that cannot plausibly exist under
    ``apex``. Non-empty => the zone has a wildcard record.

    Returns the *set of answers* (not just a bool) so a caller can also filter
    out real candidates that merely collide with the wildcard target. Two
    probes by default so a round-robin wildcard doesn't slip through on a
    single unlucky query.
    """
    answers: set[str] = set()
    for _ in range(max(1, probes)):
        probe = f"{secrets.token_hex(6)}.{apex}"
        for rec in await resolve_records(resolver, probe, limiter):
            answers.add(rec["value"])
    return answers


async def has_wildcard(resolver, apex: str, limiter=None) -> bool:  # noqa: ANN001
    return bool(await wildcard_answers(resolver, apex, limiter))
