"""DNS module - resolver is mocked; no real queries."""

from __future__ import annotations

import pytest

from recon.modules.passive.dns import DNSModule
from tests.harness import evidence_for, module_harness


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._t = text

    def to_text(self) -> str:
        return self._t


class _FakeRRset(list):
    ttl = 300


class _FakeAnswer:
    def __init__(self, records: list[str] | None) -> None:
        self.rrset = _FakeRRset(_FakeRdata(r) for r in records) if records else None


class _FakeResolver:
    lifetime = 0.0
    timeout = 0.0

    def __init__(self, table: dict[tuple[str, str], list[str] | None]) -> None:
        self._table = table

    async def resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
        return _FakeAnswer(self._table.get((name, rtype)))


@pytest.mark.asyncio
async def test_dns_emits_records_and_missing_dnssec(engagement_id, monkeypatch):
    table = {
        ("example.com", "A"): ["203.0.113.10"],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "DNSKEY"): None,  # -> negative evidence
    }
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver(table)
    )

    async with module_harness(engagement_id, "dns") as ctx:
        await DNSModule().run(ctx)

    records = await evidence_for(engagement_id, subject_type="dns_record")
    assert any(e.raw_data["rtype"] == "A" for e in records)
    assert any(e.raw_data["rtype"] == "MX" for e in records)

    dnssec = await evidence_for(engagement_id, subject_type="dnssec")
    assert len(dnssec) == 1
    assert dnssec[0].polarity.value == "absent"


@pytest.mark.asyncio
async def test_dns_handles_nxdomain(engagement_id, monkeypatch):
    import dns.resolver

    class _NXResolver:
        lifetime = timeout = 0.0

        async def resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
            raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr("dns.asyncresolver.Resolver", lambda *a, **k: _NXResolver())
    async with module_harness(engagement_id, "dns") as ctx:
        await DNSModule().run(ctx)
    # no crash, no dns_record evidence
    assert await evidence_for(engagement_id, subject_type="dns_record") == []
