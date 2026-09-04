"""email_security - resolver + HTTP mocked, no real network."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.passive.email_security import EmailSecurityModule, _parse_dmarc, _parse_spf
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import FakeHTTP, evidence_for, module_harness


class _FakeTxtRdata:
    """Mimics dnspython TXT rdata: `.strings` is the tuple of byte chunks."""

    def __init__(self, *chunks: str) -> None:
        self.strings = tuple(c.encode() for c in chunks)

    def to_text(self) -> str:
        return " ".join(f'"{c}"' for c in [s.decode() for s in self.strings])


class _RRset(list):
    ttl = 300


class _Answer:
    def __init__(self, records):  # noqa: ANN001
        self.rrset = _RRset(records) if records else None


class _FakeResolver:
    lifetime = timeout = 0.0

    def __init__(self, table: dict[tuple[str, str], list] | None = None) -> None:
        self._table = table or {}

    async def resolve(self, name, rtype, raise_on_no_answer=False):  # noqa: ANN001
        return _Answer(self._table.get((name.rstrip("."), rtype)))


def _txt(domain: str, *values: str) -> tuple:
    return (domain, "TXT"), [_FakeTxtRdata(v) for v in values]


async def _run(engagement_id, table, http_routes=None):
    monkeypatch_table = dict(table)
    import unittest.mock as mock

    with mock.patch("dns.asyncresolver.Resolver", lambda *a, **k: _FakeResolver(monkeypatch_table)):
        http = FakeHTTP(http_routes or {}, default_status=404)
        async with module_harness(engagement_id, "email_security", http=http) as ctx:
            await EmailSecurityModule().run(ctx)


def _findings(evs, subject_type):
    return [e for e in evs if e.subject_type == subject_type]


# --------------------------------------------------------------------------
def test_resolves_in_passive_phase_after_dns():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["email_security"])]
    assert order == ["dns", "email_security"]
    assert MODULES["email_security"].phase.value == "passive"


def test_parse_spf_counts_lookups_and_all_qualifier():
    p = _parse_spf("v=spf1 include:_spf.google.com include:sendgrid.net a mx -all")
    assert p["lookup_mechanisms"] == 4 and p["all_qualifier"] == "-"

    p = _parse_spf("v=spf1 +all")
    assert p["all_qualifier"] == "+"


def test_parse_dmarc_tags():
    p = _parse_dmarc("v=DMARC1; p=none; pct=50; rua=mailto:d@example.com")
    assert p == {"record": "v=DMARC1; p=none; pct=50; rua=mailto:d@example.com",
                 "policy": "none", "subdomain_policy": None, "pct": 50,
                 "rua": True, "ruf": False}


@pytest.mark.asyncio
async def test_missing_spf_and_dmarc_are_negative_findings(engagement_id):
    await _run(engagement_id, {})
    evs = await evidence_for(engagement_id)
    spf_neg = [e for e in evs if e.subject_type == "spf" and e.is_error is False]
    assert any(e.polarity.value == "absent" for e in spf_neg)
    dmarc_neg = [e for e in evs if e.subject_type == "dmarc"]
    assert any(e.polarity.value == "absent" for e in dmarc_neg)


@pytest.mark.asyncio
async def test_strict_spf_and_dmarc_produce_no_weak_finding(engagement_id):
    table = dict([
        _txt("example.com", "v=spf1 include:_spf.google.com -all"),
        _txt("_dmarc.example.com", "v=DMARC1; p=reject; pct=100; rua=mailto:d@example.com"),
    ])
    await _run(engagement_id, table)
    assert await evidence_for(engagement_id, subject_type="spf_weak") == []
    assert await evidence_for(engagement_id, subject_type="dmarc_weak") == []
    spf = (await evidence_for(engagement_id, subject_type="spf"))[0]
    assert spf.raw_data["all_qualifier"] == "-"
    dmarc = (await evidence_for(engagement_id, subject_type="dmarc"))[0]
    assert dmarc.raw_data["policy"] == "reject"


@pytest.mark.asyncio
async def test_permissive_spf_and_weak_dmarc_are_flagged(engagement_id):
    table = dict([
        _txt("example.com", "v=spf1 +all"),
        _txt("_dmarc.example.com", "v=DMARC1; p=none"),
    ])
    await _run(engagement_id, table)
    spf_weak = (await evidence_for(engagement_id, subject_type="spf_weak"))[0]
    assert "+all" in spf_weak.raw_data["reasons"][0]
    dmarc_weak = (await evidence_for(engagement_id, subject_type="dmarc_weak"))[0]
    reasons = " ".join(dmarc_weak.raw_data["reasons"])
    assert "p=none" in reasons and "rua" in reasons


@pytest.mark.asyncio
async def test_too_many_spf_lookups_is_flagged(engagement_id):
    mechs = " ".join(f"include:s{i}.example.net" for i in range(12))
    table = dict([_txt("example.com", f"v=spf1 {mechs} -all")])
    await _run(engagement_id, table)
    weak = (await evidence_for(engagement_id, subject_type="spf_weak"))[0]
    assert weak.raw_data["lookup_mechanisms"] == 12


@pytest.mark.asyncio
async def test_spf_record_split_across_multiple_txt_strings(engagement_id):
    # one TXT *record* whose value is split into two 255-byte-style chunks -
    # a single rdata with two `.strings` entries, not two separate records.
    table = {("example.com", "TXT"): [_FakeTxtRdata("v=spf1 ", "include:_spf.google.com -all")]}
    await _run(engagement_id, table)
    spf = (await evidence_for(engagement_id, subject_type="spf"))[0]
    assert spf.raw_data["all_qualifier"] == "-"


@pytest.mark.asyncio
async def test_dkim_selector_found_no_negative_when_absent(engagement_id):
    table = dict([_txt("google._domainkey.example.com", "v=DKIM1; k=rsa; p=ABC123")])
    await _run(engagement_id, table)
    dkim = await evidence_for(engagement_id, subject_type="dkim")
    assert len(dkim) == 1 and dkim[0].raw_data["selector"] == "google"
    # absence of the other 8 selectors never becomes a negative finding
    assert all(e.polarity.value == "present" for e in dkim)


@pytest.mark.asyncio
async def test_mta_sts_present_fetches_policy(engagement_id):
    table = dict([_txt("_mta-sts.example.com", "v=STSv1; id=1")])
    routes = {
        "mta-sts.example.com/.well-known/mta-sts.txt": httpx.Response(
            200, text="version: STSv1\nmode: enforce\nmx: mail.example.com\n",
        ),
    }
    await _run(engagement_id, table, routes)
    mta = (await evidence_for(engagement_id, subject_type="mta_sts"))[0]
    assert mta.raw_data["mode"] == "enforce" and mta.raw_data["mx"] == ["mail.example.com"]


@pytest.mark.asyncio
async def test_mta_sts_and_tls_rpt_absent_are_informational_negatives(engagement_id):
    await _run(engagement_id, {})
    mta = [e for e in await evidence_for(engagement_id, subject_type="mta_sts")]
    tls_rpt = [e for e in await evidence_for(engagement_id, subject_type="tls_rpt")]
    assert mta and mta[0].polarity.value == "absent"
    assert tls_rpt and tls_rpt[0].polarity.value == "absent"


@pytest.mark.asyncio
async def test_no_apex_domains_is_a_noop(engagement_id):
    async with module_harness(engagement_id, "email_security") as ctx:
        ctx.roe.scope.in_scope.domains = []
        await EmailSecurityModule().run(ctx)
    assert await evidence_for(engagement_id) == []
