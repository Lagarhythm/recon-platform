"""probe_http liveness module - HTTP faked, no real network."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.passive.probe_http import ProbeHTTPModule, _title
from recon.net.http_client import ReconRequestError
from tests.harness import FakeHTTP, evidence_for, module_harness

_HOST = "api.example.com"          # in EXAMPLE_ROE *.example.com -> in_scope
_EXCLUDED = "mail.example.com"     # EXAMPLE_ROE excluded.hosts


def _resp(status: int, *, url: str, body: str = "", server: str | None = None) -> httpx.Response:
    headers = {"content-type": "text/html; charset=utf-8"}
    if server:
        headers["Server"] = server
    return httpx.Response(
        status, headers=headers, text=body, request=httpx.Request("GET", url)
    )


async def _run(engagement_id, routes, prior, *, allow_oos=False):
    http = FakeHTTP(routes)
    async with module_harness(engagement_id, "probe_http", http=http, prior_evidence=prior) as ctx:
        ctx.allow_out_of_scope = allow_oos
        await ProbeHTTPModule().run(ctx)
    return http


def _prior_hosts(*hosts, stype="subdomain"):
    return [{"subject_type": stype, "subject_value": h, "raw_data": {}} for h in hosts]


def test_title_parsing():
    assert _title("<html><head><TITLE>  Hello\n World </TITLE>") == "Hello World"
    assert _title("<p>no title here</p>") is None


@pytest.mark.asyncio
async def test_live_host_emits_url_and_service(engagement_id):
    routes = {
        "https://api.example.com/": _resp(
            200, url="https://api.example.com/",
            body="<title>API Root</title>", server="nginx/1.24.0",
        ),
    }
    await _run(engagement_id, routes, _prior_hosts(_HOST))

    urls = await evidence_for(engagement_id, subject_type="url")
    assert len(urls) == 1
    u = urls[0]
    assert u.subject_value == "https://api.example.com/"
    assert u.raw_data["status"] == 200
    assert u.raw_data["title"] == "API Root"
    assert u.raw_data["scheme"] == "https" and u.raw_data["live"] is True

    svcs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="service")}
    assert svcs == {"api.example.com:443"}

    tech = {e.subject_value for e in await evidence_for(engagement_id, subject_type="tech")}
    assert "nginx" in tech


@pytest.mark.asyncio
async def test_non_html_response_skips_title_parse(engagement_id):
    r = httpx.Response(
        200, headers={"content-type": "application/json"},
        text='{"a":"<title>not a title</title>"}',
        request=httpx.Request("GET", "https://api.example.com/"),
    )
    await _run(engagement_id, {"https://api.example.com/": r}, _prior_hosts(_HOST))
    u = (await evidence_for(engagement_id, subject_type="url"))[0]
    assert u.raw_data["title"] is None


@pytest.mark.asyncio
async def test_https_failure_falls_back_to_http(engagement_id):
    routes = {
        "https://api.example.com/": ReconRequestError("connection refused"),
        "http://api.example.com/": _resp(200, url="http://api.example.com/", body="<title>x</title>"),
    }
    await _run(engagement_id, routes, _prior_hosts(_HOST))
    urls = {e.subject_value for e in await evidence_for(engagement_id, subject_type="url")}
    assert urls == {"http://api.example.com/"}
    svcs = {e.subject_value for e in await evidence_for(engagement_id, subject_type="service")}
    assert svcs == {"api.example.com:80"}


@pytest.mark.asyncio
async def test_https_success_skips_http_probe(engagement_id):
    routes = {
        "https://api.example.com/": _resp(200, url="https://api.example.com/"),
        "http://api.example.com/": _resp(200, url="http://api.example.com/"),
    }
    http = await _run(engagement_id, routes, _prior_hosts(_HOST))
    assert not any(m == "GET" and u.startswith("http://") for m, u in http.calls)


@pytest.mark.asyncio
async def test_redirect_target_recorded(engagement_id):
    routes = {
        "https://api.example.com/": _resp(
            200, url="https://www.example.com/app", body="<title>App</title>"
        ),
    }
    await _run(engagement_id, routes, _prior_hosts(_HOST))
    reds = await evidence_for(engagement_id, subject_type="redirect")
    assert len(reds) == 1
    assert reds[0].raw_data["location"] == "https://www.example.com/app"
    u = (await evidence_for(engagement_id, subject_type="url"))[0]
    assert u.raw_data["final_url"] == "https://www.example.com/app"


@pytest.mark.asyncio
async def test_dead_host_produces_nothing_and_no_error_spam(engagement_id):
    routes = {
        "https://api.example.com/": ReconRequestError("no route"),
        "http://api.example.com/": ReconRequestError("no route"),
    }
    await _run(engagement_id, routes, _prior_hosts(_HOST))
    assert await evidence_for(engagement_id, subject_type="url") == []
    assert [e for e in await evidence_for(engagement_id) if e.is_error] == []


@pytest.mark.asyncio
async def test_excluded_host_is_never_probed(engagement_id):
    routes = {"https://mail.example.com/": _resp(200, url="https://mail.example.com/")}
    http = await _run(engagement_id, routes, _prior_hosts(_EXCLUDED))
    assert http.calls == []
    assert await evidence_for(engagement_id, subject_type="url") == []


@pytest.mark.asyncio
async def test_ip_service_gets_hosts_relationship(engagement_id):
    routes = {"https://203.0.113.10/": _resp(200, url="https://203.0.113.10/")}
    await _run(engagement_id, routes, _prior_hosts("203.0.113.10", stype="ip"))
    svc = (await evidence_for(engagement_id, subject_type="service"))[0]
    assert (svc.raw_data.get("relationships") or [{}])[0].get("target_value") == "203.0.113.10"
