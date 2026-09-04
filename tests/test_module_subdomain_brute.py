"""subdomain_brute module - resolver is mocked; no real DNS."""

from __future__ import annotations

import dns.resolver
import pytest

from recon.modules.active import subdomain_brute
from recon.modules.active.subdomain_brute import SubdomainBruteModule, _load_labels
from tests.harness import evidence_for, module_harness


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._t = text

    def to_text(self) -> str:
        return self._t


class _FakeRRset(list):
    ttl = 120


class _FakeAnswer:
    def __init__(self, records):  # noqa: ANN001
        self.rrset = _FakeRRset(_FakeRdata(r) for r in records) if records else None


class _FakeResolver:
    lifetime = 0.0
    timeout = 0.0

    def __init__(self, table=None, default=None, raise_exc=None):  # noqa: ANN001
        self._table = table or {}
        self._default = default
        self._raise = raise_exc

    async def resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
        if self._raise is not None:
            raise self._raise()
        key = (str(name).rstrip("."), rtype)
        return _FakeAnswer(self._table.get(key, self._default))


def test_wordlist_bundled_and_sane():
    labels = _load_labels()
    assert len(labels) >= 100
    assert "www" in labels and "vpn" in labels
    assert len(labels) == len(set(labels))


@pytest.mark.asyncio
async def test_brute_hit_emits_subdomain_and_records(engagement_id, monkeypatch):
    monkeypatch.setattr(subdomain_brute, "_load_labels", lambda *a, **k: ["www", "mail", "ftp"])
    table = {
        ("example.com", "SOA"): ["ns1.example.com. hostmaster.example.com. 1 2 3 4 5"],
        ("www.example.com", "A"): ["203.0.113.20"],
    }
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver(table)
    )

    async with module_harness(engagement_id, "subdomain_brute") as ctx:
        await SubdomainBruteModule().run(ctx)

    subs = await evidence_for(engagement_id, subject_type="subdomain")
    assert [e.subject_value for e in subs] == ["www.example.com"]
    assert subs[0].raw_data["parent"] == "example.com"
    assert subs[0].raw_data["source"] == "brute"
    assert subs[0].raw_data["resolved"] == ["203.0.113.20"]

    records = await evidence_for(engagement_id, subject_type="dns_record")
    assert any(
        e.raw_data["name"] == "www.example.com" and e.raw_data["rtype"] == "A"
        for e in records
    )
    assert await evidence_for(engagement_id, subject_type="dns_wildcard") == []


@pytest.mark.asyncio
async def test_wildcard_detected_skips_brute(engagement_id, monkeypatch):
    monkeypatch.setattr(subdomain_brute, "_load_labels", lambda *a, **k: ["www", "mail"])
    # every name resolves -> wildcard
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda *a, **k: _FakeResolver(default=["203.0.113.99"]),
    )

    async with module_harness(engagement_id, "subdomain_brute") as ctx:
        await SubdomainBruteModule().run(ctx)

    wild = await evidence_for(engagement_id, subject_type="dns_wildcard")
    assert len(wild) == 1
    assert wild[0].subject_value == "example.com"
    assert await evidence_for(engagement_id, subject_type="subdomain") == []


@pytest.mark.asyncio
async def test_non_zone_apex_is_skipped_not_brute_forced(engagement_id, monkeypatch):
    # An RoE host like "homer.lan" has no SOA/NS - brute-forcing it is thousands
    # of pointless lookups. It must be skipped, not enumerated.
    monkeypatch.setattr(subdomain_brute, "_load_labels", lambda *a, **k: ["www", "mail"])
    calls: list = []

    class _Tracking(_FakeResolver):
        async def resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
            calls.append((str(name), rtype))
            return await super().resolve(name, rtype, raise_on_no_answer)

    # only SOA/NS lookups answer with nothing; example.com is not a zone here
    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda *a, **k: _Tracking())

    async with module_harness(engagement_id, "subdomain_brute") as ctx:
        await SubdomainBruteModule().run(ctx)

    assert await evidence_for(engagement_id, subject_type="subdomain") == []
    # it probed for a zone, then stopped - no per-label brute-force lookups
    assert all(t in ("SOA", "NS") for _, t in calls)


@pytest.mark.asyncio
async def test_nxdomain_labels_produce_nothing(engagement_id, monkeypatch):
    monkeypatch.setattr(subdomain_brute, "_load_labels", lambda *a, **k: ["nope1", "nope2"])
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda *a, **k: _FakeResolver(raise_exc=dns.resolver.NXDOMAIN),
    )

    async with module_harness(engagement_id, "subdomain_brute") as ctx:
        await SubdomainBruteModule().run(ctx)

    assert await evidence_for(engagement_id, subject_type="subdomain") == []
    assert await evidence_for(engagement_id, subject_type="dns_record") == []
    assert await evidence_for(engagement_id, subject_type="dns_wildcard") == []
