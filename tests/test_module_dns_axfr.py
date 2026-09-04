"""dns_axfr module - resolver and zone transfer are mocked; no real DNS."""

from __future__ import annotations

import dns.resolver
import dns.zone
import pytest

from recon.modules.active.dns_axfr import DNSZoneTransferModule
from tests.harness import evidence_for, module_harness

_ZONE_TEXT = """
$ORIGIN example.com.
$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300
@ IN NS ns1.example.com.
@ IN A 203.0.113.10
www IN A 203.0.113.20
internal IN A 10.0.0.5
vpn IN CNAME www.example.com.
"""


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._t = text

    def to_text(self) -> str:
        return self._t


class _FakeRRset(list):
    ttl = 300


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


@pytest.mark.asyncio
async def test_axfr_success_emits_high_value_and_records(engagement_id, monkeypatch):
    table = {
        ("example.com", "NS"): ["ns1.example.com."],
        ("ns1.example.com", "A"): ["198.51.100.53"],
    }
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver(table)
    )

    zone = dns.zone.from_text(_ZONE_TEXT, origin="example.com", relativize=True)
    monkeypatch.setattr("dns.asyncquery.xfr", lambda *a, **k: object(), raising=False)
    monkeypatch.setattr("dns.zone.from_xfr", lambda *a, **k: zone)

    async with module_harness(engagement_id, "dns_axfr") as ctx:
        await DNSZoneTransferModule().run(ctx)

    axfr = await evidence_for(engagement_id, subject_type="dns_axfr")
    assert len(axfr) == 1
    assert axfr[0].polarity.value == "present"
    assert axfr[0].raw_data["nameserver"] == "ns1.example.com"
    assert axfr[0].raw_data["interest"] == "high_value"
    assert axfr[0].raw_data["record_count"] >= 5

    records = await evidence_for(engagement_id, subject_type="dns_record")
    rtypes = {e.raw_data["rtype"] for e in records}
    assert "A" in rtypes
    assert "CNAME" in rtypes
    assert all({"name", "rtype", "value", "ttl"} <= set(e.raw_data) for e in records)


@pytest.mark.asyncio
async def test_axfr_all_refused_emits_negative(engagement_id, monkeypatch):
    table = {
        ("example.com", "NS"): ["ns1.example.com.", "ns2.example.com."],
        ("ns1.example.com", "A"): ["198.51.100.53"],
        ("ns2.example.com", "A"): ["198.51.100.54"],
    }
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver(table)
    )

    def _refuse(*a, **k):  # noqa: ANN002, ANN003
        raise ConnectionRefusedError("AXFR refused")

    monkeypatch.setattr("dns.asyncquery.xfr", _refuse, raising=False)

    async with module_harness(engagement_id, "dns_axfr") as ctx:
        await DNSZoneTransferModule().run(ctx)

    axfr = await evidence_for(engagement_id, subject_type="dns_axfr")
    assert len(axfr) == 1
    assert axfr[0].polarity.value == "absent"
    assert "refused" in (axfr[0].summary or "").lower()
    assert await evidence_for(engagement_id, subject_type="dns_record") == []


@pytest.mark.asyncio
async def test_axfr_nxdomain_does_not_crash(engagement_id, monkeypatch):
    monkeypatch.setattr(
        "dns.asyncresolver.Resolver",
        lambda *a, **k: _FakeResolver(raise_exc=dns.resolver.NXDOMAIN),
    )
    async with module_harness(engagement_id, "dns_axfr") as ctx:
        await DNSZoneTransferModule().run(ctx)
    assert await evidence_for(engagement_id, subject_type="dns_axfr") == []
    assert await evidence_for(engagement_id, subject_type="dns_record") == []
