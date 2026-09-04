"""tech_fingerprint - no real network (FakeHTTP), no real corpus lookups needed
beyond the vendored JSON already bundled with the repo."""

from __future__ import annotations

import httpx
import pytest

from recon.models.enums import FindingPolarity
from recon.modules.passive.tech_fingerprint import (
    TechFingerprintModule,
    _load_corpus,
    match_technologies,
)
from tests.harness import FakeHTTP, evidence_for, module_harness


def _liveness_ev(host: str, *, live: bool) -> dict:
    return {
        "subject_type": "liveness",
        "subject_value": host,
        "raw_data": {"source": "probe_http", "host": host, "live": live},
        "polarity": FindingPolarity.PRESENT,
    }


def test_corpus_loads_and_is_nonempty():
    corpus = _load_corpus()
    assert len(corpus) > 10
    assert {"nginx", "WordPress", "jQuery"} <= {t["name"] for t in corpus}


def test_match_technologies_header_with_version():
    corpus = [{
        "name": "nginx", "categories": ["web-server"], "cpe": "cpe:2.3:a:nginx:nginx",
        "headers": {"Server": "nginx(?:/([0-9.]+))?"},
    }]
    headers = httpx.Headers({"Server": "nginx/1.25.3"})
    hits = match_technologies(corpus, headers=headers, cookies=set(), html="")
    assert len(hits) == 1
    assert hits[0]["name"] == "nginx"
    assert hits[0]["version"] == "1.25.3"
    assert hits[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"


def test_match_technologies_html_and_script_presence_only():
    corpus = [{
        "name": "WordPress", "categories": ["cms"], "cpe": "cpe:2.3:a:wordpress:wordpress",
        "html": ["wp-content/themes/"], "script": ["wp-includes/"],
    }]
    html = '<html><script src="/wp-includes/js/jquery/jquery.js"></script>wp-content/themes/foo</html>'
    hits = match_technologies(corpus, headers=httpx.Headers({}), cookies=set(), html=html)
    assert hits[0]["name"] == "WordPress"
    assert hits[0]["version"] is None
    assert "html" in hits[0]["evidence"]
    assert "script" in hits[0]["evidence"]


def test_match_technologies_cookie_prefix():
    corpus = [{
        "name": "WordPress", "categories": ["cms"], "cpe": None,
        "cookies": {"wp-settings-": ""},
    }]
    hits = match_technologies(
        corpus, headers=httpx.Headers({}), cookies={"wp-settings-1"}, html=""
    )
    assert hits and hits[0]["name"] == "WordPress"


def test_match_technologies_no_hit_when_nothing_matches():
    corpus = [{"name": "nginx", "categories": [], "cpe": None, "headers": {"Server": "nginx"}}]
    hits = match_technologies(
        corpus, headers=httpx.Headers({"Server": "Apache"}), cookies=set(), html=""
    )
    assert hits == []


def test_cpe_omitted_when_corpus_entry_has_no_cpe():
    corpus = [{"name": "Google Analytics", "categories": ["analytics"], "cpe": None,
               "html": ["google-analytics\\.com"]}]
    hits = match_technologies(
        corpus, headers=httpx.Headers({}), cookies=set(), html="www.google-analytics.com"
    )
    assert hits[0]["cpe"] is None


@pytest.mark.asyncio
async def test_module_only_fingerprints_probe_http_confirmed_live_hosts(engagement_id):
    prior = [
        _liveness_ev("dead.example.com", live=False),
        _liveness_ev("live.example.com", live=True),
    ]
    http = FakeHTTP(routes={
        "https://live.example.com/": httpx.Response(
            200, headers=[("Server", "nginx/1.25.3"), ("content-type", "text/html")],
            text="<html>hi</html>",
        ),
    })
    async with module_harness(
        engagement_id, "tech_fingerprint", http=http, prior_evidence=prior
    ) as ctx:
        await TechFingerprintModule().run(ctx)

    tech = await evidence_for(engagement_id, subject_type="tech")
    assert {e.raw_data["url"] for e in tech} == {"https://live.example.com/"}
    assert any(e.raw_data["name"] == "nginx" and e.raw_data["version"] == "1.25.3" for e in tech)
    assert all("dead.example.com" not in u for _, u in http.calls)


@pytest.mark.asyncio
async def test_module_no_live_hosts_reports_progress_and_no_evidence(engagement_id):
    async with module_harness(engagement_id, "tech_fingerprint") as ctx:
        await TechFingerprintModule().run(ctx)

    tech = await evidence_for(engagement_id, subject_type="tech")
    assert tech == []
    progresses = [d for etype, d in ctx.events if etype == "progress"]
    assert progresses  # ran and reported something rather than silently no-op'ing
