"""probe_http -> crawler / js_analyzer / dir_fuzz live-host filtering.

Once probe_http has assessed a host, the downstream modules seed from its
confirmed-live URLs instead of speculatively probing every discovered name -
and never touch a host probe_http found dead. With no probe_http evidence they
fall back to the original "try every host" behaviour.
"""

from __future__ import annotations

import pytest

from recon.modules._live_hosts import live_hosts, probed_hosts
from recon.modules.active.dir_fuzz import DirFuzzModule
from recon.modules.passive.crawler import CrawlerModule
from recon.modules.passive.js_analyzer import JSAnalyzerModule
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import FakeHTTP, module_harness


def _sub(v):
    return {"subject_type": "subdomain", "subject_value": v, "raw_data": {}}


def _liveness_ev(host, *, live):
    """A probe_http `liveness` verdict for a host."""
    return {
        "subject_type": "liveness",
        "subject_value": host,
        "raw_data": {"source": "probe_http", "host": host, "live": live},
    }


def _probe_result(host, *, live):
    """What probe_http actually emits for one host: a liveness verdict always,
    plus a `url` row when it answered."""
    rows = [_liveness_ev(host, live=live)]
    if live:
        rows.append({
            "subject_type": "url", "subject_value": f"https://{host}/",
            "raw_data": {"source": "probe_http", "live": True, "status": 200,
                         "scheme": "https"},
        })
    return rows


# --------------------------------------------------------------------------
def test_new_modules_declare_probe_http_dep_and_resolve():
    load_builtin_modules()
    for m in ("crawler", "js_analyzer", "dir_fuzz"):
        assert "probe_http" in MODULES[m].depends_on, m
    # each still resolves (probe_http is an earlier / same phase)
    for m in ("crawler", "js_analyzer", "dir_fuzz"):
        names = [x.name for x in resolve_order([m])]
        assert "probe_http" in names and names.index("probe_http") < names.index(m)


@pytest.mark.asyncio
async def test_helpers_read_probe_http_evidence(engagement_id):
    prior = [_liveness_ev("live.example.com", live=True), _liveness_ev("dead.example.com", live=False)]
    async with module_harness(engagement_id, "crawler", prior_evidence=prior) as ctx:
        assert await probed_hosts(ctx) == {"live.example.com", "dead.example.com"}
        assert await live_hosts(ctx) == {"live.example.com"}


@pytest.mark.asyncio
async def test_helpers_empty_when_probe_http_did_not_run(engagement_id):
    async with module_harness(engagement_id, "crawler",
                              prior_evidence=[_sub("a.example.com")]) as ctx:
        assert await probed_hosts(ctx) == set()
        assert await live_hosts(ctx) == set()


# --- crawler ----------------------------------------------------------
@pytest.mark.asyncio
async def test_crawler_skips_hosts_probe_http_assessed(engagement_id):
    prior = [
        _sub("dead.example.com"), _sub("live.example.com"),
        _liveness_ev("dead.example.com", live=False),
        *_probe_result("live.example.com", live=True),
    ]
    http = FakeHTTP({
        "robots.txt": __import__("httpx").Response(404),
        "sitemap.xml": __import__("httpx").Response(404),
        "https://live.example.com/": __import__("httpx").Response(
            200, html="<html><body>ok</body></html>",
            headers={"content-type": "text/html"}),
    })
    async with module_harness(engagement_id, "crawler", http=http, prior_evidence=prior) as ctx:
        await CrawlerModule().run(ctx)

    hit_hosts = {u.split("/")[2] for _, u in http.calls if u.startswith("http")}
    assert "dead.example.com" not in hit_hosts          # never guessed
    assert "live.example.com" in hit_hosts              # seeded from its url evidence


@pytest.mark.asyncio
async def test_crawler_falls_back_without_probe_http(engagement_id):
    http = FakeHTTP({"robots.txt": __import__("httpx").Response(404),
                     "sitemap.xml": __import__("httpx").Response(404)})
    async with module_harness(engagement_id, "crawler", http=http,
                              prior_evidence=[_sub("guessme.example.com")]) as ctx:
        await CrawlerModule().run(ctx)
    hit = " ".join(u for _, u in http.calls)
    assert "guessme.example.com" in hit  # host was guessed (fallback path)


# --- js_analyzer ----------------------------------------------------
@pytest.mark.asyncio
async def test_js_analyzer_drops_js_on_dead_hosts(engagement_id):
    prior = [
        {"subject_type": "url", "subject_value": "https://dead.example.com/app.js",
         "raw_data": {"source": "wayback"}},
        {"subject_type": "url", "subject_value": "https://live.example.com/app.js",
         "raw_data": {"source": "wayback"}},
        _liveness_ev("dead.example.com", live=False),
        _liveness_ev("live.example.com", live=True),
    ]
    http = FakeHTTP({
        "live.example.com/app.js": __import__("httpx").Response(
            200, text="var x=1", headers={"content-type": "application/javascript"}),
    }, default_status=404)
    async with module_harness(engagement_id, "js_analyzer", http=http, prior_evidence=prior) as ctx:
        await JSAnalyzerModule().run(ctx)

    fetched = {u for _, u in http.calls if u.endswith(".js")}
    assert "https://live.example.com/app.js" in fetched
    assert "https://dead.example.com/app.js" not in fetched


# --- dir_fuzz -----------------------------------------------------
@pytest.mark.asyncio
async def test_dir_fuzz_roots_skip_probe_http_assessed_hosts(engagement_id):
    from recon.db import session_scope
    from recon.models.asset import Asset
    from recon.models.enums import AssetType, ScopeStatus

    async with session_scope() as s:
        for host in ("dead.example.com", "unseen.example.com"):
            s.add(Asset(engagement_id=engagement_id, type=AssetType.SUBDOMAIN, value=host,
                        in_scope_status=ScopeStatus.IN_SCOPE, confidence_score=0.6))

    prior = [_liveness_ev("dead.example.com", live=False)]
    async with module_harness(engagement_id, "dir_fuzz", prior_evidence=prior) as ctx:
        roots = await DirFuzzModule()._roots(ctx)

    netlocs = {r.split("/")[2] for r in roots}
    assert "dead.example.com" not in netlocs            # probe_http said it's dead
    assert "unseen.example.com" in netlocs              # never assessed -> still guessed
