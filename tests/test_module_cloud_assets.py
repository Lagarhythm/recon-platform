from __future__ import annotations

import httpx
import pytest

from recon.modules.osint.cloud_assets import CloudAssetsModule, candidate_names
from tests.harness import FakeHTTP, evidence_for, module_harness


def test_candidate_names_are_bounded_and_safe():
    names = candidate_names("Example Corp", ["example.com"])
    assert "examplecorp-assets" in names
    assert "example-com-backups" in names
    assert all(3 <= len(name) <= 63 for name in names)
    assert all("." not in name for name in names)


@pytest.mark.asyncio
async def test_cloud_assets_records_listable_and_non_listable_without_objects(engagement_id):
    routes = {
        ".s3.amazonaws.com": httpx.Response(200, text="<ListBucketResult/>") ,
        "storage.googleapis.com": httpx.Response(403, text="forbidden"),
        ".blob.core.windows.net": httpx.Response(404),
    }
    http = FakeHTTP(routes)
    async with module_harness(engagement_id, "cloud_assets", http=http) as ctx:
        ctx.roe.osint.enabled = True
        ctx.roe.osint.company = "Example Corp"
        ctx.roe.osint.seed_domains = ["example.com"]
        await CloudAssetsModule().run(ctx)
    findings = await evidence_for(engagement_id, subject_type="finding")
    accesses = {e.raw_data["access"] for e in findings}
    assert {"listable", "exists_not_listable"} <= accesses
    assert all("max-keys=1" in url or "maxResults=1" in url or "maxresults=1" in url
               for _method, url in http.calls)
    assert all(e.raw_data.get("interest") == "high_value" for e in findings
               if e.raw_data["access"] == "listable")
    assert all(e.raw_data.get("interest") == "notable" for e in findings
               if e.raw_data["access"] == "exists_not_listable")
