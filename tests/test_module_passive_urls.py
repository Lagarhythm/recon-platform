from __future__ import annotations

import httpx
import pytest

from recon.modules.osint.passive_urls import PassiveURLsModule
from tests.harness import FakeHTTP, evidence_for, module_harness


@pytest.mark.asyncio
async def test_passive_urls_collects_deduplicated_in_domain_urls(engagement_id):
    routes = {
        "web.archive.org": httpx.Response(200, json=[["original"], ["https://app.example.com/a"], ["https://evil.example.org/"]]),
        "index.commoncrawl.org": httpx.Response(200, json=[{"url": "https://app.example.com/a"}, {"url": "https://api.example.com/b"}]),
        "otx.alienvault.com": httpx.Response(200, json={"url_list": [{"url": "https://api.example.com/b"}]}),
        "urlscan.io": httpx.Response(200, json={"results": [{"page": {"url": "https://www.example.com/c"}}]}),
    }
    async with module_harness(engagement_id, "passive_urls", http=FakeHTTP(routes)) as ctx:
        ctx.roe.osint.enabled = True
        ctx.roe.osint.seed_domains = ["example.com"]
        await PassiveURLsModule().run(ctx)
    rows = await evidence_for(engagement_id, subject_type="url")
    by_url = {row.subject_value: row for row in rows}
    assert set(by_url) == {"https://app.example.com/a", "https://api.example.com/b", "https://www.example.com/c"}
    assert by_url["https://app.example.com/a"].raw_data["sources"] == ["commoncrawl", "wayback"]


@pytest.mark.asyncio
async def test_passive_urls_handles_empty_otx_url_list(engagement_id):
    routes = {
        "web.archive.org": httpx.Response(200, json=[]),
        "index.commoncrawl.org": httpx.Response(200, json=[]),
        "otx.alienvault.com": httpx.Response(200, json={"url_list": []}),
        "urlscan.io": httpx.Response(200, json={"results": []}),
    }
    async with module_harness(engagement_id, "passive_urls", http=FakeHTTP(routes)) as ctx:
        ctx.roe.osint.enabled = True
        ctx.roe.osint.seed_domains = ["example.com"]
        await PassiveURLsModule().run(ctx)
    assert await evidence_for(engagement_id) == []
