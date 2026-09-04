"""js_analyzer module - JS bodies are served by FakeHTTP; no real network."""

from __future__ import annotations

import httpx
import pytest

from recon.models.enums import FindingPolarity
from recon.modules.passive.js_analyzer import JSAnalyzerModule
from tests.harness import FakeHTTP, evidence_for, module_harness

_APP_JS_URL = "https://example.com/app.js"


def _js_route(source: str) -> FakeHTTP:
    resp = httpx.Response(
        200,
        text=source,
        headers={"content-type": "application/javascript"},
        request=httpx.Request("GET", _APP_JS_URL),
    )
    return FakeHTTP({_APP_JS_URL: resp})


def _seed():
    return [
        {
            "subject_type": "js_file",
            "subject_value": _APP_JS_URL,
            "raw_data": {"url": _APP_JS_URL},
            "polarity": FindingPolarity.PRESENT,
        }
    ]


async def _run(engagement_id, source: str):
    http = _js_route(source)
    async with module_harness(
        engagement_id, "js_analyzer", http=http, prior_evidence=_seed()
    ) as ctx:
        await JSAnalyzerModule().run(ctx)
    return http


@pytest.mark.asyncio
async def test_fetch_call_becomes_endpoint(engagement_id):
    await _run(engagement_id, 'async function load() { const r = await fetch("/api/users"); return r.json(); }')

    endpoints = await evidence_for(engagement_id, subject_type="endpoint")
    by_value = {e.subject_value: e for e in endpoints}
    assert "/api/users" in by_value
    assert by_value["/api/users"].raw_data["kind"] == "fetch"
    assert by_value["/api/users"].raw_data["method"] == "GET"
    assert by_value["/api/users"].raw_data["source_file"] == _APP_JS_URL


@pytest.mark.asyncio
async def test_aws_access_key_detected_and_redacted(engagement_id):
    full_key = "AKIAIOSFODNN7EXAMPLE"
    await _run(engagement_id, f'const cfg = {{ region: "us-east-1", key: "{full_key}" }};')

    secrets = await evidence_for(engagement_id, subject_type="secret")
    aws = [e for e in secrets if e.raw_data["kind"] == "aws_access_key"]
    assert len(aws) == 1
    assert full_key not in aws[0].raw_data["match_redacted"]
    assert full_key not in aws[0].raw_data["context"]
    assert aws[0].raw_data["match_redacted"] == "AKIA...MPLE"


@pytest.mark.asyncio
async def test_jwt_detected(engagement_id):
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    await _run(engagement_id, f'const AUTH = "{jwt}";')

    secrets = await evidence_for(engagement_id, subject_type="secret")
    kinds = {e.raw_data["kind"] for e in secrets}
    assert "jwt" in kinds
    jwt_ev = next(e for e in secrets if e.raw_data["kind"] == "jwt")
    assert jwt not in jwt_ev.raw_data["match_redacted"]


@pytest.mark.asyncio
async def test_harmless_js_yields_no_secrets(engagement_id):
    harmless = """
    function greet(name) { return "Hello, " + name + "!"; }
    const palette = ["red", "green", "blue", "orange", "purple"];
    export const sum = (a, b) => a + b;
    window.addEventListener("load", () => console.log("page ready"));
    const message = "the quick brown fox jumps over the lazy dog";
    """
    await _run(engagement_id, harmless)

    secrets = await evidence_for(engagement_id, subject_type="secret")
    assert secrets == []


@pytest.mark.asyncio
async def test_absolute_url_endpoints_extracted(engagement_id):
    source = (
        'const API_BASE = "https://api.example.com/v2/orders";\n'
        'const CDN = "https://cdn.thirdparty.net/lib/bundle";\n'
        "fetch(API_BASE + '/recent');\n"
    )
    await _run(engagement_id, source)

    endpoints = await evidence_for(engagement_id, subject_type="endpoint")
    values = {e.subject_value: e for e in endpoints}
    assert "https://api.example.com/v2/orders" in values
    assert values["https://api.example.com/v2/orders"].raw_data["kind"] == "absolute"
    # out-of-scope absolute host is still emitted (correlation flags it)
    assert "https://cdn.thirdparty.net/lib/bundle" in values


@pytest.mark.asyncio
async def test_scope_violation_recorded_as_error(engagement_id):
    from recon.net.http_client import ReconRequestError

    http = FakeHTTP({_APP_JS_URL: ReconRequestError("boom")})
    async with module_harness(
        engagement_id, "js_analyzer", http=http, prior_evidence=_seed()
    ) as ctx:
        await JSAnalyzerModule().run(ctx)

    errors = await evidence_for(engagement_id, subject_type="error")
    assert any(_APP_JS_URL in (e.subject_value or "") for e in errors)


@pytest.mark.asyncio
async def test_inline_js_is_analyzed(engagement_id):
    page = "https://example.com/dashboard"
    prior = [
        {
            "subject_type": "inline_js",
            "subject_value": page,
            "raw_data": {"code": 'fetch("/api/inline/thing");', "url": page},
            "polarity": FindingPolarity.PRESENT,
        }
    ]
    async with module_harness(
        engagement_id, "js_analyzer", http=FakeHTTP(), prior_evidence=prior
    ) as ctx:
        await JSAnalyzerModule().run(ctx)

    endpoints = await evidence_for(engagement_id, subject_type="endpoint")
    assert any(
        e.subject_value == "/api/inline/thing" and e.raw_data["source_file"] == page
        for e in endpoints
    )
