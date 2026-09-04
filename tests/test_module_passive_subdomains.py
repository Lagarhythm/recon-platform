"""passive_subdomains multi-source aggregator - all HTTP faked."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.osint._passive_sources import (
    ALL_SOURCES,
    SourceDegraded,
    select_sources,
)
from recon.modules.osint.passive_subdomains import PassiveSubdomainsModule
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import FakeHTTP, evidence_for, module_harness

_D = "example.com"

# One representative payload per default-on adapter, each naming a DISTINCT
# subdomain so the aggregation test can tell sources apart.
_ROUTES = {
    "crt.sh/?q=%25.example.com": httpx.Response(200, json=[
        {"name_value": "crt.example.com\n*.example.com\nexample.com"},
        {"name_value": "shared.example.com"},
    ]),
    "api.certspotter.com": httpx.Response(200, json=[
        {"dns_names": ["cs.example.com", "shared.example.com"]},
    ]),
    "api.hackertarget.com/hostsearch": httpx.Response(200, text=(
        "ht.example.com,203.0.113.9\nshared.example.com,203.0.113.9\nother.net,1.1.1.1\n"
    )),
    "otx.alienvault.com": httpx.Response(200, json={
        "passive_dns": [
            {"hostname": "otx.example.com", "address": "203.0.113.10"},
            {"hostname": "shared.example.com", "address": "not-an-ip"},
        ]
    }),
    "jldc.me/anubis": httpx.Response(200, json=["anubis.example.com", "shared.example.com"]),
    "rapiddns.io/subdomain": httpx.Response(200, text="""
        <table><tr><th>host</th></tr>
        <tr><td>rd.example.com</td><td>203.0.113.11</td><td>A</td></tr>
        <tr><td>shared.example.com</td><td>-</td><td>CNAME</td></tr>
        </table>
    """),
    "web.archive.org/cdx": httpx.Response(200, json=[
        ["original"],
        ["http://wb.example.com/a"],
        ["https://shared.example.com/b?x=1"],
        ["http://evil.net/c"],
    ]),
    "api.subdomain.center": httpx.Response(200, json=["sc.example.com", "shared.example.com"]),
}


async def _run(engagement_id, routes=None, *, config=None):
    http = FakeHTTP(routes if routes is not None else _ROUTES, default_status=404)
    async with module_harness(engagement_id, "passive_subdomains", http=http) as ctx:
        if config:
            for k, v in config.items():
                setattr(ctx.roe.recon.passive_sources, k, v)
        await PassiveSubdomainsModule().run(ctx)
    return engagement_id, http


# --------------------------------------------------------------------------
def test_source_selection():
    assert [s.name for s in select_sources(set(), set())] == [
        "crtsh", "certspotter", "hackertarget", "otx",
        "anubis", "rapiddns", "wayback_cdx", "subdomain_center",
    ]
    assert "crtsh" not in [s.name for s in select_sources({"crtsh"}, set())]
    assert "commoncrawl" in [s.name for s in select_sources(set(), {"commoncrawl"})]
    # disable wins over enable
    assert "digitorus" not in [
        s.name for s in select_sources({"digitorus"}, {"digitorus"})
    ]


def test_adapter_names_are_unique_and_stable():
    names = [s.name for s in ALL_SOURCES]
    assert len(names) == len(set(names))
    assert set(names) >= {
        "crtsh", "certspotter", "hackertarget", "otx", "anubis", "rapiddns",
        "wayback_cdx", "subdomain_center", "threatminer", "commoncrawl", "digitorus",
    }


def test_resolves_in_the_osint_phase():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["passive_subdomains"])]
    assert order[-1] == "passive_subdomains"
    assert MODULES["passive_subdomains"].phase.value == "osint"


@pytest.mark.asyncio
async def test_each_source_parses_its_shape(engagement_id):
    eid, _ = await _run(engagement_id)
    names_by_source: dict[str, set[str]] = {}
    for e in await evidence_for(eid, subject_type="subdomain"):
        names_by_source.setdefault(e.raw_data["source"], set()).add(e.subject_value)
    for e in await evidence_for(eid, subject_type="domain"):
        names_by_source.setdefault(e.raw_data["source"], set()).add(e.subject_value)

    assert "crt.example.com" in names_by_source["crtsh"]
    assert "example.com" in names_by_source["crtsh"]          # apex -> domain type
    assert "cs.example.com" in names_by_source["certspotter"]
    assert "ht.example.com" in names_by_source["hackertarget"]
    assert "otx.example.com" in names_by_source["otx"]
    assert "anubis.example.com" in names_by_source["anubis"]
    assert "rd.example.com" in names_by_source["rapiddns"]
    assert "wb.example.com" in names_by_source["wayback_cdx"]
    assert "sc.example.com" in names_by_source["subdomain_center"]
    # out-of-domain names are dropped
    all_names = {n for s in names_by_source.values() for n in s}
    assert "other.net" not in all_names and "evil.net" not in all_names


@pytest.mark.asyncio
async def test_shared_name_gets_one_evidence_row_per_source(engagement_id):
    eid, _ = await _run(engagement_id)
    shared = [
        e for e in await evidence_for(eid, subject_type="subdomain")
        if e.subject_value == "shared.example.com"
    ]
    sources = {e.raw_data["source"] for e in shared}
    # every default source that listed it (all 8 in the fixture)
    assert sources == {
        "crtsh", "certspotter", "hackertarget", "otx",
        "anubis", "rapiddns", "wayback_cdx", "subdomain_center",
    }
    assert all(set(e.raw_data["also_seen_by"]) == sources for e in shared)


@pytest.mark.asyncio
async def test_resolved_ips_become_dns_record_evidence(engagement_id):
    eid, _ = await _run(engagement_id)
    recs = {
        (e.subject_value, e.raw_data["value"])
        for e in await evidence_for(eid, subject_type="dns_record")
    }
    assert ("ht.example.com", "203.0.113.9") in recs
    assert ("otx.example.com", "203.0.113.10") in recs
    # "not-an-ip" from OTX is filtered
    assert all(v != "not-an-ip" for _, v in recs)


@pytest.mark.asyncio
async def test_one_source_degraded_others_continue(engagement_id):
    routes = dict(_ROUTES)
    routes["api.hackertarget.com/hostsearch"] = httpx.Response(200, text="API count exceeded - ...")
    eid, _ = await _run(engagement_id, routes)

    errs = [e for e in await evidence_for(eid) if e.is_error]
    assert any(e.raw_data.get("reason") == "degraded" and e.subject_value == "hackertarget"
               for e in errs)
    # the other 7 still produced results
    subs = {e.raw_data["source"] for e in await evidence_for(eid, subject_type="subdomain")}
    assert "hackertarget" not in subs
    assert "crtsh" in subs and "otx" in subs


@pytest.mark.asyncio
async def test_module_fails_only_when_every_source_fails(engagement_id):
    # every route 500s
    routes = {k: httpx.Response(500, text="boom") for k in _ROUTES}
    with pytest.raises(RuntimeError, match="0 answered"):
        await _run(engagement_id, routes)


@pytest.mark.asyncio
async def test_disable_config_is_honored(engagement_id):
    eid, http = await _run(engagement_id, config={"disable": ["crtsh", "otx"]})
    called = " ".join(u for _, u in http.calls)
    assert "crt.sh" not in called and "otx.alienvault.com" not in called
    subs = {e.raw_data["source"] for e in await evidence_for(eid, subject_type="subdomain")}
    assert "crtsh" not in subs and "otx" not in subs


def test_source_degraded_is_an_exception():
    assert issubclass(SourceDegraded, Exception)
