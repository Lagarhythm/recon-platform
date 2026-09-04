"""subdomain_recurse - HTTP faked, no real network."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.passive.subdomain_recurse import SubdomainRecurseModule
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import FakeHTTP, evidence_for, module_harness


def _sub(v):
    return {"subject_type": "subdomain", "subject_value": v, "raw_data": {}}


# crt.sh JSON keyed on the query domain in the URL
def _routes(mapping: dict[str, list[str]]) -> dict:
    r: dict = {}
    for dom, names in mapping.items():
        r[f"crt.sh/?q=%25.{dom}"] = httpx.Response(
            200, json=[{"name_value": "\n".join(names)}]
        )
    return r


async def _run(engagement_id, routes, prior, *, rounds=2):
    http = FakeHTTP(routes, default_status=404)
    async with module_harness(engagement_id, "subdomain_recurse", http=http,
                              prior_evidence=prior) as ctx:
        ctx.roe.recon.recursion.max_rounds = rounds
        # only exercise crtsh - keeps the faked-route surface small
        ctx.roe.recon.passive_sources.disable = ["certspotter", "anubis", "otx"]
        await SubdomainRecurseModule().run(ctx)
    return http


# --------------------------------------------------------------------------
def test_resolves_in_passive_phase_after_passive_subdomains():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["subdomain_recurse"])]
    assert order[-1] == "subdomain_recurse"
    assert order.index("passive_subdomains") < order.index("subdomain_recurse")
    assert MODULES["subdomain_recurse"].phase.value == "passive"


@pytest.mark.asyncio
async def test_recurses_into_deeper_zones(engagement_id):
    routes = _routes({
        "dev.example.com": ["app.dev.example.com", "db.dev.example.com"],
        "app.dev.example.com": ["v2.app.dev.example.com"],
    })
    await _run(engagement_id, routes, [_sub("dev.example.com")], rounds=2)

    got = {
        e.subject_value: e.raw_data
        for e in await evidence_for(engagement_id, subject_type="subdomain")
        if e.raw_data.get("method") == "recursion"
    }
    assert "app.dev.example.com" in got and got["app.dev.example.com"]["round"] == 1
    assert "db.dev.example.com" in got
    assert "v2.app.dev.example.com" in got and got["v2.app.dev.example.com"]["round"] == 2
    assert got["v2.app.dev.example.com"]["pivot"] == "app.dev.example.com"


@pytest.mark.asyncio
async def test_max_rounds_zero_is_a_noop(engagement_id):
    http = await _run(engagement_id, _routes({"dev.example.com": ["x.dev.example.com"]}),
                      [_sub("dev.example.com")], rounds=0)
    assert http.calls == []
    assert [e for e in await evidence_for(engagement_id, subject_type="subdomain")
            if e.raw_data.get("method") == "recursion"] == []


@pytest.mark.asyncio
async def test_stops_when_frontier_is_exhausted(engagement_id):
    # round 1 finds a name, round 2's query for it returns nothing new
    routes = _routes({
        "dev.example.com": ["only.dev.example.com"],
        "only.dev.example.com": [],
    })
    await _run(engagement_id, routes, [_sub("dev.example.com")], rounds=5)
    recs = [e for e in await evidence_for(engagement_id, subject_type="subdomain")
            if e.raw_data.get("method") == "recursion"]
    assert [e.subject_value for e in recs] == ["only.dev.example.com"]


@pytest.mark.asyncio
async def test_names_not_strictly_deeper_are_ignored(engagement_id):
    # source returns a sibling / unrelated name - must not be recorded
    routes = _routes({
        "dev.example.com": ["sibling.example.com", "real.dev.example.com", "evil.net"],
    })
    await _run(engagement_id, routes, [_sub("dev.example.com")], rounds=1)
    recs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")
            if e.raw_data.get("method") == "recursion"}
    assert recs == {"real.dev.example.com"}


@pytest.mark.asyncio
async def test_per_source_failure_is_non_fatal(engagement_id):
    routes = {"crt.sh/?q=%25.dev.example.com": httpx.Response(500, text="boom")}
    await _run(engagement_id, routes, [_sub("dev.example.com")], rounds=1)
    errs = [e for e in await evidence_for(engagement_id) if e.is_error]
    assert errs and errs[0].subject_value == "crtsh"
    # module still completed (no raise)


@pytest.mark.asyncio
async def test_only_recurses_real_subdomains_not_apexes(engagement_id):
    # example.com is an apex - never used as a recursion seed
    http = await _run(engagement_id, _routes({"example.com": ["x.example.com"]}),
                      [_sub("example.com")], rounds=2)
    assert http.calls == []
