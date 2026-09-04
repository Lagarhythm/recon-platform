"""ct_subdomains module - crt.sh is faked; no real network."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.passive.ct_subdomains import CTSubdomainsModule
from tests.harness import FakeHTTP, evidence_for, module_harness

_CRTSH_JSON = [
    {"id": 1, "name_value": "www.example.com"},
    {"id": 2, "name_value": "api.example.com\nwww.example.com"},
    {"id": 3, "name_value": "*.dev.example.com\nmail.example.com"},
    {"id": 4, "name_value": "shared.otherdomain.net"},
]


def _routes(response: httpx.Response) -> dict:
    return {"crt.sh": lambda method, url: response}


@pytest.mark.asyncio
async def test_subdomains_under_apex_emitted(engagement_id):
    http = FakeHTTP(_routes(httpx.Response(200, json=_CRTSH_JSON)))
    async with module_harness(engagement_id, "ct_subdomains", http=http) as ctx:
        await CTSubdomainsModule().run(ctx)

    subs = await evidence_for(engagement_id, subject_type="subdomain")
    by_value = {e.subject_value: e for e in subs}

    assert "www.example.com" in by_value
    assert "api.example.com" in by_value
    assert by_value["www.example.com"].raw_data["parent"] == "example.com"
    assert by_value["www.example.com"].raw_data["source"] == "crt.sh"
    assert "cert_ids" in by_value["www.example.com"].raw_data

    # crt.sh was actually queried (third-party, is_target=False)
    assert any("crt.sh" in url for _, url in http.calls)


@pytest.mark.asyncio
async def test_wildcard_and_multiname_parsed(engagement_id):
    http = FakeHTTP(_routes(httpx.Response(200, json=_CRTSH_JSON)))
    async with module_harness(engagement_id, "ct_subdomains", http=http) as ctx:
        await CTSubdomainsModule().run(ctx)

    subs = await evidence_for(engagement_id, subject_type="subdomain")
    values = {e.subject_value for e in subs}

    # "*.dev.example.com\nmail.example.com" split + wildcard stripped
    assert "dev.example.com" in values
    assert "mail.example.com" in values

    # out-of-scope name still emitted, but flagged
    other = next(e for e in subs if e.subject_value == "shared.otherdomain.net")
    assert other.raw_data.get("note") == "outside in-scope apex"
    assert "parent" not in other.raw_data


@pytest.mark.asyncio
async def test_non_200_produces_error_not_crash(engagement_id):
    http = FakeHTTP(_routes(httpx.Response(502, text="bad gateway")))
    async with module_harness(engagement_id, "ct_subdomains", http=http) as ctx:
        await CTSubdomainsModule().run(ctx)

    errors = await evidence_for(engagement_id, subject_type="error")
    assert errors
    assert any("crt.sh" in (e.summary or "") for e in errors)

    subs = await evidence_for(engagement_id, subject_type="subdomain")
    assert subs == []


@pytest.mark.asyncio
async def test_dedup(engagement_id):
    http = FakeHTTP(_routes(httpx.Response(200, json=_CRTSH_JSON)))
    async with module_harness(engagement_id, "ct_subdomains", http=http) as ctx:
        await CTSubdomainsModule().run(ctx)

    subs = await evidence_for(engagement_id, subject_type="subdomain")
    values = [e.subject_value for e in subs]
    # www.example.com appears in two cert entries -> one evidence row
    assert values.count("www.example.com") == 1
    www = next(e for e in subs if e.subject_value == "www.example.com")
    assert sorted(www.raw_data["cert_ids"]) == ["1", "2"]
