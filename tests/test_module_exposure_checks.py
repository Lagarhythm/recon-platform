"""exposure_checks - no real network (FakeHTTP)."""

from __future__ import annotations

import httpx
import pytest

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.enums import AssetType, FindingPolarity, ScopeStatus
from recon.modules.active.exposure_checks import ExposureChecksModule
from tests.harness import FakeHTTP, evidence_for, module_harness


async def _seed_url_asset(engagement_id: str, url: str) -> None:
    async with session_scope() as s:
        s.add(Asset(
            engagement_id=engagement_id, type=AssetType.URL, value=url,
            in_scope_status=ScopeStatus.IN_SCOPE, confidence_score=0.9,
        ))


def _liveness_ev(host: str, *, live: bool) -> dict:
    return {
        "subject_type": "liveness",
        "subject_value": host,
        "raw_data": {"source": "probe_http", "host": host, "live": live},
        "polarity": FindingPolarity.PRESENT,
    }


@pytest.mark.asyncio
async def test_roots_skip_probe_http_dead_hosts(engagement_id):
    async with session_scope() as s:
        for host in ("dead.example.com", "unseen.example.com"):
            s.add(Asset(engagement_id=engagement_id, type=AssetType.SUBDOMAIN, value=host,
                        in_scope_status=ScopeStatus.IN_SCOPE, confidence_score=0.6))
    prior = [_liveness_ev("dead.example.com", live=False)]
    async with module_harness(engagement_id, "exposure_checks", prior_evidence=prior) as ctx:
        roots = await ExposureChecksModule()._roots(ctx)
    netlocs = {r.split("/")[2] for r in roots}
    assert "dead.example.com" not in netlocs
    assert "unseen.example.com" in netlocs


@pytest.mark.asyncio
async def test_git_head_leak_detected_as_high_value(engagement_id):
    await _seed_url_asset(engagement_id, "https://example.com/")
    http = FakeHTTP(routes={
        "/.git/HEAD": httpx.Response(200, text="ref: refs/heads/master\n",
                                      headers={"content-type": "text/plain"}),
    }, default_status=404)
    async with module_harness(engagement_id, "exposure_checks", http=http) as ctx:
        await ExposureChecksModule().run(ctx)

    exposures = await evidence_for(engagement_id, subject_type="exposure")
    hit = next((e for e in exposures if e.raw_data["category"] == "git"
                and e.raw_data["url"].endswith(".git/HEAD")), None)
    assert hit is not None
    assert hit.raw_data["interest"] == "high_value"


@pytest.mark.asyncio
async def test_env_file_leak_detected(engagement_id):
    await _seed_url_asset(engagement_id, "https://example.com/")
    http = FakeHTTP(routes={
        "/.env": httpx.Response(
            200, text="DB_HOST=localhost\nDB_USER=root\nDB_PASS=secret\n",
            headers={"content-type": "text/plain"},
        ),
    }, default_status=404)
    async with module_harness(engagement_id, "exposure_checks", http=http) as ctx:
        await ExposureChecksModule().run(ctx)

    exposures = await evidence_for(engagement_id, subject_type="exposure")
    hit = next((e for e in exposures if e.raw_data["category"] == "env"), None)
    assert hit is not None
    assert hit.raw_data["interest"] == "high_value"


@pytest.mark.asyncio
async def test_backup_file_non_html_content_type_detected(engagement_id):
    await _seed_url_asset(engagement_id, "https://example.com/")
    http = FakeHTTP(routes={
        "/backup.zip": httpx.Response(200, content=b"PK\x03\x04...",
                                       headers={"content-type": "application/zip"}),
    }, default_status=404)
    async with module_harness(engagement_id, "exposure_checks", http=http) as ctx:
        await ExposureChecksModule().run(ctx)

    exposures = await evidence_for(engagement_id, subject_type="exposure")
    hit = next((e for e in exposures if e.raw_data["category"] == "backup"), None)
    assert hit is not None
    assert hit.raw_data["interest"] == "high_value"


@pytest.mark.asyncio
async def test_graphql_introspection_reachability_detected(engagement_id):
    await _seed_url_asset(engagement_id, "https://example.com/")
    http = FakeHTTP(routes={
        "/graphql": httpx.Response(
            200, text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
            headers={"content-type": "application/json"},
        ),
    }, default_status=404)
    async with module_harness(engagement_id, "exposure_checks", http=http) as ctx:
        await ExposureChecksModule().run(ctx)

    exposures = await evidence_for(engagement_id, subject_type="exposure")
    hit = next((e for e in exposures if e.raw_data["category"] == "graphql_introspection"), None)
    assert hit is not None
    assert hit.raw_data["interest"] == "notable"


@pytest.mark.asyncio
async def test_soft_404_catch_all_suppresses_weak_reachability_hits(engagement_id):
    """Every path on this host (real or not) 200s with an identical empty
    body - a soft-404/SPA-fallback catch-all. dir_fuzz's cluster filter
    should drop the ambiguous 'reachable' style checks (admin_panel,
    heapdump) even though status alone would otherwise look like a hit."""
    await _seed_url_asset(engagement_id, "https://example.com/")
    http = FakeHTTP(routes={}, default_status=200)  # every path 200s identically
    async with module_harness(engagement_id, "exposure_checks", http=http) as ctx:
        await ExposureChecksModule().run(ctx)

    exposures = await evidence_for(engagement_id, subject_type="exposure")
    assert not any(e.raw_data["category"] == "admin_panel" for e in exposures)
