"""Shared DNS helpers (recon/modules/_dns_common.py) - resolver is mocked."""

from __future__ import annotations

import dns.resolver
import pytest

from recon.modules._dns_common import (
    has_wildcard,
    is_zone,
    resolve_records,
    wildcard_answers,
)


class _Rdata:
    def __init__(self, text: str) -> None:
        self._t = text

    def to_text(self) -> str:
        return self._t


class _RRset(list):
    ttl = 99


class _Answer:
    def __init__(self, records):  # noqa: ANN001
        self.rrset = _RRset(_Rdata(r) for r in records) if records else None


class _Resolver:
    def __init__(self, table=None, default=None, raise_exc=None):  # noqa: ANN001
        self._table = table or {}
        self._default = default
        self._raise = raise_exc

    async def resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
        if self._raise is not None:
            raise self._raise("boom")
        return _Answer(self._table.get((str(name).rstrip("."), rtype), self._default))


class _CountingLimiter:
    def __init__(self) -> None:
        self.acquired = 0

    async def acquire(self) -> None:
        self.acquired += 1


@pytest.mark.asyncio
async def test_resolve_records_returns_dicts():
    r = _Resolver({("api.example.com", "A"): ["203.0.113.5"]})
    recs = await resolve_records(r, "api.example.com")
    assert recs == [{"name": "api.example.com", "rtype": "A", "value": "203.0.113.5", "ttl": 99}]


@pytest.mark.asyncio
async def test_resolve_records_nxdomain_short_circuits():
    r = _Resolver(raise_exc=dns.resolver.NXDOMAIN)
    assert await resolve_records(r, "nope.example.com") == []


@pytest.mark.asyncio
async def test_resolve_records_gates_every_query_through_the_limiter():
    r = _Resolver(default=None)
    lim = _CountingLimiter()
    await resolve_records(r, "x.example.com", lim)
    assert lim.acquired == 3  # A, AAAA, CNAME


@pytest.mark.asyncio
async def test_wildcard_answers_detects_and_returns_the_set():
    r = _Resolver(default=["203.0.113.99"])  # everything resolves
    answers = await wildcard_answers(r, "example.com")
    assert answers == {"203.0.113.99"}
    assert await has_wildcard(r, "example.com") is True


@pytest.mark.asyncio
async def test_no_wildcard_when_random_labels_dont_resolve():
    r = _Resolver(default=None)
    assert await wildcard_answers(r, "example.com") == set()
    assert await has_wildcard(r, "example.com") is False


@pytest.mark.asyncio
async def test_is_zone_true_on_soa():
    r = _Resolver({("example.com", "SOA"): ["ns1. hostmaster. 1 2 3 4 5"]})
    assert await is_zone(r, "example.com") is True
    assert await is_zone(r, "homer.lan") is False
