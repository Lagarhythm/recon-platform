"""Crawler module - HTTP is faked; no real network."""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

import httpx
import pytest

from recon.modules.passive.crawler import (
    MAX_PAGES,
    MAX_PAGES_PER_HOST,
    CrawlerModule,
)
from tests.harness import FakeHTTP, evidence_for, module_harness


def _html(body: str) -> httpx.Response:
    return httpx.Response(200, html=body, headers={"content-type": "text/html"})


def _seed_subdomain(value: str) -> dict:
    return {"subject_type": "subdomain", "subject_value": value, "raw_data": {}}


async def _fetched_pages(engagement_id: str) -> list:
    urls = await evidence_for(engagement_id, subject_type="url")
    return [e for e in urls if "status" in e.raw_data]


@pytest.mark.asyncio
async def test_links_followed_within_host_and_emitted(engagement_id):
    routes = {
        "robots.txt": httpx.Response(404),
        "sitemap.xml": httpx.Response(404),
        "a.example.com/page2": _html("<html><body>leaf</body></html>"),
        "a.example.com": _html(
            '<html><body><a href="/page2">next</a>'
            '<a href="https://a.example.com/page2#frag">dupe</a></body></html>'
        ),
    }
    http = FakeHTTP(routes)
    async with module_harness(
        engagement_id, "crawler", http=http,
        prior_evidence=[_seed_subdomain("a.example.com")],
    ) as ctx:
        await CrawlerModule().run(ctx)

    fetched = {e.subject_value for e in await _fetched_pages(engagement_id)}
    assert "https://a.example.com/" in fetched
    assert "https://a.example.com/page2" in fetched
    # page2 was actually requested over HTTP
    assert any(url.endswith("/page2") for _, url in http.calls)

    all_urls = {e.subject_value for e in await evidence_for(engagement_id, subject_type="url")}
    assert "https://a.example.com/page2" in all_urls


@pytest.mark.asyncio
async def test_page_and_host_caps_respected(engagement_id):
    def page(method: str, url: str) -> httpx.Response:
        host = urlsplit(url).hostname
        links = "".join(
            f'<a href="https://{host}/p{i}">{i}</a>' for i in range(500)
        )
        return _html(f"<html><body>{links}</body></html>")

    routes = {
        "robots.txt": httpx.Response(404),
        "sitemap.xml": httpx.Response(404),
        "example.com": page,
    }
    http = FakeHTTP(routes)
    seeds = [_seed_subdomain(f"h{n}.example.com") for n in range(5)]
    async with module_harness(
        engagement_id, "crawler", http=http, prior_evidence=seeds
    ) as ctx:
        await CrawlerModule().run(ctx)

    pages = await _fetched_pages(engagement_id)
    per_host = Counter(urlsplit(e.subject_value).hostname for e in pages)
    assert sum(per_host.values()) <= MAX_PAGES
    assert max(per_host.values()) <= MAX_PAGES_PER_HOST
    assert len(per_host) > 1  # crawled across multiple seed hosts


@pytest.mark.asyncio
async def test_http_only_host_is_crawled_and_meta_uses_reached_scheme(engagement_id):
    # Regression: the crawler hard-coded https:// for the root seed and for
    # robots.txt/sitemap.xml. On an HTTP-only host every one of those failed,
    # which (via the backoff) stalled the whole scan. It must fall back to
    # http:// and do robots/sitemap on the scheme that actually worked.
    from recon.net.http_client import ReconRequestError

    body = '<html><body><a href="/inner">x</a></body></html>'
    routes = {
        "https://a.example.com": ReconRequestError("ConnectError: refused"),
        "http://a.example.com/robots.txt": httpx.Response(
            200, text="Disallow: /secret", headers={"content-type": "text/plain"}
        ),
        "http://a.example.com/sitemap.xml": httpx.Response(404),
        "http://a.example.com": _html(body),
    }
    http = FakeHTTP(routes)
    async with module_harness(
        engagement_id, "crawler", http=http,
        prior_evidence=[_seed_subdomain("a.example.com")],
    ) as ctx:
        await CrawlerModule().run(ctx)

    fetched = {e.subject_value for e in await _fetched_pages(engagement_id)}
    assert "http://a.example.com/" in fetched

    called = [u for _, u in http.calls]
    assert "http://a.example.com/robots.txt" in called
    assert not any("https://a.example.com/robots" in u for u in called)

    robots = await evidence_for(engagement_id, subject_type="robots")
    assert robots and robots[0].raw_data["disallow"] == ["/secret"]


@pytest.mark.asyncio
async def test_forms_extracted_with_inputs(engagement_id):
    body = (
        '<html><body><form action="/login" method="post">'
        '<input name="user" type="text">'
        '<input name="pw" type="password">'
        '<textarea name="note"></textarea>'
        "</form></body></html>"
    )
    routes = {
        "robots.txt": httpx.Response(404),
        "sitemap.xml": httpx.Response(404),
        "a.example.com": _html(body),
    }
    async with module_harness(
        engagement_id, "crawler", http=FakeHTTP(routes),
        prior_evidence=[_seed_subdomain("a.example.com")],
    ) as ctx:
        await CrawlerModule().run(ctx)

    forms = await evidence_for(engagement_id, subject_type="form")
    assert len(forms) == 1
    form = forms[0]
    assert form.subject_value == "https://a.example.com/login"
    assert form.raw_data["method"] == "POST"
    assert form.raw_data["url"] == "https://a.example.com/"
    names = {i["name"]: i["type"] for i in form.raw_data["inputs"]}
    assert names == {"user": "text", "pw": "password", "note": "textarea"}


@pytest.mark.asyncio
async def test_script_src_emitted_as_js_file(engagement_id):
    body = '<html><head><script src="/static/app.js"></script></head><body>x</body></html>'
    routes = {
        "robots.txt": httpx.Response(404),
        "sitemap.xml": httpx.Response(404),
        "a.example.com": _html(body),
    }
    async with module_harness(
        engagement_id, "crawler", http=FakeHTTP(routes),
        prior_evidence=[_seed_subdomain("a.example.com")],
    ) as ctx:
        await CrawlerModule().run(ctx)

    js = await evidence_for(engagement_id, subject_type="js_file")
    assert len(js) == 1
    assert js[0].subject_value == "https://a.example.com/static/app.js"
    assert js[0].raw_data == {
        "url": "https://a.example.com/static/app.js",
        "discovered_on": "https://a.example.com/",
    }


@pytest.mark.asyncio
async def test_robots_disallow_becomes_notable_url(engagement_id):
    robots = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /secret\n"
        "Sitemap: https://a.example.com/sitemap.xml\n"
    )
    routes = {
        "a.example.com/robots.txt": httpx.Response(
            200, text=robots, headers={"content-type": "text/plain"}
        ),
        "sitemap.xml": httpx.Response(404),
        "a.example.com": _html("<html><body>home</body></html>"),
    }
    async with module_harness(
        engagement_id, "crawler", http=FakeHTTP(routes),
        prior_evidence=[_seed_subdomain("a.example.com")],
    ) as ctx:
        await CrawlerModule().run(ctx)

    robots_ev = await evidence_for(engagement_id, subject_type="robots")
    assert len(robots_ev) == 1
    assert robots_ev[0].raw_data["disallow"] == ["/admin/", "/secret"]
    assert robots_ev[0].raw_data["sitemaps"] == ["https://a.example.com/sitemap.xml"]

    urls = await evidence_for(engagement_id, subject_type="url")
    notable = {
        e.subject_value
        for e in urls
        if e.raw_data.get("source") == "robots" and e.raw_data.get("interest") == "notable"
    }
    assert notable == {
        "https://a.example.com/admin/",
        "https://a.example.com/secret",
    }


@pytest.mark.asyncio
async def test_offhost_link_emitted_not_crawled(engagement_id):
    body = (
        '<html><body>'
        '<a href="https://b.example.com/secret">other in-scope host</a>'
        '<a href="https://evil.com/">third party</a>'
        "</body></html>"
    )
    routes = {
        "robots.txt": httpx.Response(404),
        "sitemap.xml": httpx.Response(404),
        "a.example.com": _html(body),
    }
    http = FakeHTTP(routes)
    async with module_harness(
        engagement_id, "crawler", http=http,
        prior_evidence=[_seed_subdomain("a.example.com")],
    ) as ctx:
        await CrawlerModule().run(ctx)

    all_urls = {e.subject_value for e in await evidence_for(engagement_id, subject_type="url")}
    assert "https://b.example.com/secret" in all_urls
    assert "https://evil.com/" in all_urls

    # nothing on b.example.com or evil.com was ever requested
    assert not any("b.example.com" in url for _, url in http.calls)
    assert not any("evil.com" in url for _, url in http.calls)
