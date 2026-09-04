"""HTTP Analyzer module - no real network (FakeHTTP + monkeypatched TLS)."""

from __future__ import annotations

import asyncio
import types

import httpx
import pytest

from recon.models.enums import FindingPolarity
from recon.modules.passive.http_analyzer import _SECURITY_HEADERS, HTTPAnalyzerModule
from recon.net.http_client import ScopeViolation
from tests.harness import FakeHTTP, evidence_for, module_harness


@pytest.fixture(autouse=True)
def _no_real_tls(monkeypatch):
    """The TLS path opens a raw socket; make it fail fast in every test."""

    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise ConnectionRefusedError("no network in tests")

    monkeypatch.setattr(asyncio, "open_connection", _boom)


def _resp(status: int, headers: list[tuple[str, str]] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers or [])


@pytest.mark.asyncio
async def test_progress_events_carry_a_live_percentage(engagement_id):
    http = FakeHTTP(routes={"https://example.com/": _resp(200, [("content-type", "text/html")])})
    async with module_harness(engagement_id, "http_analyzer", http=http) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    progresses = [d for etype, d in ctx.events if etype == "progress"]
    with_pct = [d for d in progresses if "pct" in d]
    assert with_pct, "http_analyzer should report current/total progress"
    assert all(0 <= d["pct"] <= 100 for d in with_pct)
    assert with_pct[-1]["pct"] == 100  # finishes at 100%


@pytest.mark.asyncio
async def test_missing_security_headers_emit_negative_per_header(engagement_id):
    http = FakeHTTP(routes={"https://example.com/": _resp(200, [("content-type", "text/html")])})
    async with module_harness(engagement_id, "http_analyzer", http=http) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    sec = await evidence_for(engagement_id, subject_type="security_header")
    absent = {e.raw_data["name"] for e in sec if e.polarity is FindingPolarity.ABSENT}
    assert absent == set(_SECURITY_HEADERS)
    assert all(e.raw_data["url"] == "https://example.com/" for e in sec)


@pytest.mark.asyncio
async def test_present_security_headers_emit_present_evidence(engagement_id):
    present = [
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
    ]
    http = FakeHTTP(routes={"https://example.com/": _resp(200, present)})
    async with module_harness(engagement_id, "http_analyzer", http=http) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    sec = await evidence_for(engagement_id, subject_type="security_header")
    got = {e.raw_data["name"]: e for e in sec}
    assert set(got) == set(_SECURITY_HEADERS)
    assert all(e.polarity is FindingPolarity.PRESENT for e in sec)
    assert got["X-Frame-Options"].raw_data["value"] == "DENY"


@pytest.mark.asyncio
async def test_redirect_emits_redirect_and_url_evidence(engagement_id):
    http = FakeHTTP(
        routes={"https://example.com/": _resp(301, [("location", "https://example.com/home")])}
    )
    async with module_harness(engagement_id, "http_analyzer", http=http) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    redirects = await evidence_for(engagement_id, subject_type="redirect")
    assert any(
        e.raw_data == {
            "url": "https://example.com/",
            "location": "https://example.com/home",
            "status": 301,
        }
        for e in redirects
    )
    urls = await evidence_for(engagement_id, subject_type="url")
    assert any(
        e.raw_data.get("location") == "https://example.com/home"
        and e.raw_data["status"] == 301
        and e.raw_data["scheme"] == "https"
        for e in urls
    )


@pytest.mark.asyncio
async def test_scope_violation_from_http_client_is_caught(engagement_id):
    decision = types.SimpleNamespace(
        host="blocked.example.com",
        status=types.SimpleNamespace(value="excluded"),
        reason="explicitly excluded",
    )
    http = FakeHTTP(routes={"blocked.example.com": ScopeViolation(decision)})
    async with module_harness(
        engagement_id,
        "http_analyzer",
        http=http,
        prior_evidence=[
            {
                "subject_type": "subdomain",
                "subject_value": "blocked.example.com",
                "raw_data": {},
                "polarity": FindingPolarity.PRESENT,
            }
        ],
    ) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    errors = await evidence_for(engagement_id, subject_type="error")
    scoped = [e for e in errors if e.raw_data.get("reason") == "scope"]
    assert scoped
    assert any("blocked.example.com" in e.subject_value for e in scoped)


@pytest.mark.asyncio
async def test_insecure_cookie_emits_negative(engagement_id):
    http = FakeHTTP(routes={"https://example.com/": _resp(200, [("Set-Cookie", "sid=abc123; Path=/")])})
    async with module_harness(engagement_id, "http_analyzer", http=http) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    cookies = await evidence_for(engagement_id, subject_type="cookie")
    present = [e for e in cookies if e.polarity is FindingPolarity.PRESENT]
    absent = [e for e in cookies if e.polarity is FindingPolarity.ABSENT]
    assert any(
        e.raw_data["name"] == "sid" and e.raw_data["secure"] is False and e.raw_data["httponly"] is False
        for e in present
    )
    assert any(set(e.raw_data["missing"]) == {"Secure", "HttpOnly"} for e in absent)


@pytest.mark.asyncio
async def test_disclosing_headers_and_tech_fingerprint(engagement_id):
    http = FakeHTTP(
        routes={
            "https://example.com/": _resp(
                200,
                [
                    ("Server", "nginx/1.25.3"),
                    ("X-Powered-By", "PHP/8.2.1"),
                    ("Set-Cookie", "PHPSESSID=deadbeef; path=/"),
                ],
            )
        }
    )
    async with module_harness(engagement_id, "http_analyzer", http=http) as ctx:
        await HTTPAnalyzerModule().run(ctx)

    http_headers = await evidence_for(engagement_id, subject_type="http_header")
    assert {e.raw_data["name"] for e in http_headers} >= {"Server", "X-Powered-By"}

    tech = await evidence_for(engagement_id, subject_type="tech")
    names = {e.raw_data["name"] for e in tech}
    assert {"nginx", "PHP"} <= names
    nginx = next(e for e in tech if e.raw_data["name"] == "nginx")
    assert nginx.raw_data["version"] == "1.25.3"
