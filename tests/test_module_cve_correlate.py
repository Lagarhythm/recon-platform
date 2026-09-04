"""cve_correlate - no real network; the local CVERecord index is seeded
directly (it's not engagement-scoped), OSV.dev is mocked via FakeHTTP."""

from __future__ import annotations

import httpx
import pytest

from recon.db import session_scope
from recon.models.cve import CVERecord
from recon.modules.active.cve_correlate import CveCorrelateModule
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order
from tests.harness import FakeHTTP, evidence_for, module_harness


def _internetdb_cve(cve_id, ip, ports):
    return {
        "subject_type": "cve", "subject_value": cve_id,
        "raw_data": {"source": "internetdb", "ip": ip, "ports": ports},
    }


def _service(host, port, *, product=None, version=None, name="http"):
    return {
        "subject_type": "service", "subject_value": f"{host}:{port}",
        "raw_data": {"host": host, "port": port, "name": name,
                     "product": product, "version": version},
    }


def _tech(name, version, *, url="https://app.example.com/app.js"):
    return {
        "subject_type": "tech", "subject_value": name,
        "raw_data": {"url": url, "name": name, "version": version, "evidence": "js"},
    }


async def _seed_cve_record(**kwargs) -> None:
    async with session_scope() as session:
        session.add(CVERecord(**{
            "cve_id": "CVE-2024-0001", "cpe_matches": [], "references": [],
            **kwargs,
        }))


async def _run(engagement_id, prior_evidence, *, http=None):
    async with module_harness(
        engagement_id, "cve_correlate", prior_evidence=prior_evidence, http=http
    ) as ctx:
        await CveCorrelateModule().run(ctx)


async def _cves(engagement_id):
    return await evidence_for(engagement_id, subject_type="cve")


# --------------------------------------------------------------------------
def test_resolves_in_active_phase_after_port_scan():
    load_builtin_modules()
    order = [m.name for m in resolve_order(["cve_correlate"])]
    assert order.index("port_scan") < order.index("cve_correlate")
    assert MODULES["cve_correlate"].phase.value == "active"


@pytest.mark.asyncio
async def test_internetdb_cve_gets_an_affects_edge(engagement_id):
    await _run(engagement_id, [_internetdb_cve("CVE-2023-1111", "203.0.113.5", [443])])

    cves = await _cves(engagement_id)
    linked = [c for c in cves if (c.raw_data or {}).get("linked_from") == "internetdb"]
    assert len(linked) == 1
    assert linked[0].subject_value == "CVE-2023-1111"
    assert linked[0].raw_data["relationships"] == [
        {"type": "affects", "target_type": "service", "target_value": "203.0.113.5:443"},
    ]


@pytest.mark.asyncio
async def test_local_index_matches_by_product_and_version_range(engagement_id):
    await _seed_cve_record(
        cve_id="CVE-2024-0001", cvss_v31_score=8.1, cvss_v31_severity="HIGH", in_kev=False,
        cpe_matches=[{
            "cpe": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "part": "a",
            "vendor": "acme", "product": "widget",
            "version_start": "1.0", "version_end": "2.0", "vulnerable": True,
        }],
    )
    await _run(engagement_id, [_service("10.0.0.5", 8080, product="widget", version="1.5")])

    cves = await _cves(engagement_id)
    local = [c for c in cves if (c.raw_data or {}).get("matched_via") == "local_index"]
    assert len(local) == 1
    assert local[0].subject_value == "CVE-2024-0001"
    assert local[0].raw_data["interest"] == "notable"
    assert local[0].raw_data["relationships"] == [
        {"type": "affects", "target_type": "service", "target_value": "10.0.0.5:8080"},
    ]


@pytest.mark.asyncio
async def test_kev_match_is_high_value_regardless_of_score(engagement_id):
    await _seed_cve_record(
        cve_id="CVE-2024-0001", cvss_v31_score=5.0, cvss_v31_severity="MEDIUM", in_kev=True,
        cpe_matches=[{"cpe": "x", "product": "widget", "version_start": None, "version_end": None}],
    )
    await _run(engagement_id, [_service("10.0.0.5", 8080, product="widget", version="1.5")])

    [cve] = [c for c in await _cves(engagement_id)
             if (c.raw_data or {}).get("matched_via") == "local_index"]
    assert cve.raw_data["interest"] == "high_value"


@pytest.mark.asyncio
async def test_version_outside_range_is_not_matched(engagement_id):
    await _seed_cve_record(
        cpe_matches=[{
            "cpe": "x", "product": "widget",
            "version_start": "1.0", "version_end": "2.0", "vulnerable": True,
        }],
    )
    # 3.0 is outside [1.0, 2.0)
    await _run(engagement_id, [_service("10.0.0.5", 8080, product="widget", version="3.0")])

    local = [c for c in await _cves(engagement_id)
             if (c.raw_data or {}).get("matched_via") == "local_index"]
    assert local == []


@pytest.mark.asyncio
async def test_unrelated_product_is_not_matched(engagement_id):
    await _seed_cve_record(
        cpe_matches=[{"cpe": "x", "product": "widget",
                      "version_start": None, "version_end": None}],
    )
    await _run(engagement_id, [_service("10.0.0.5", 22, product="openssh", version="9.6")])

    local = [c for c in await _cves(engagement_id)
             if (c.raw_data or {}).get("matched_via") == "local_index"]
    assert local == []


@pytest.mark.asyncio
async def test_no_local_index_degrades_gracefully_no_crash(engagement_id):
    await _run(engagement_id, [_service("10.0.0.5", 8080, product="widget", version="1.5")])
    local = [c for c in await _cves(engagement_id)
             if (c.raw_data or {}).get("matched_via") == "local_index"]
    assert local == []


@pytest.mark.asyncio
async def test_osv_match_on_known_npm_package(engagement_id):
    routes = {
        "api.osv.dev/v1/query": httpx.Response(200, json={
            "vulns": [{"id": "GHSA-xxxx", "aliases": ["CVE-2024-2222"],
                       "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                       "database_specific": {"severity": "CRITICAL"}}],
        }),
    }
    await _run(
        engagement_id, [_tech("React", "17.0.2")], http=FakeHTTP(routes),
    )
    osv = [c for c in await _cves(engagement_id)
           if (c.raw_data or {}).get("matched_via") == "osv.dev"]
    assert len(osv) == 1
    assert osv[0].subject_value == "CVE-2024-2222"
    assert osv[0].raw_data["interest"] == "high_value"
    assert osv[0].raw_data["package"] == "react"


@pytest.mark.asyncio
async def test_osv_skips_tech_names_not_confidently_mappable(engagement_id):
    fake_http = FakeHTTP({"api.osv.dev/v1/query": httpx.Response(500)})  # must never be called
    await _run(engagement_id, [_tech("Laravel", "10.2")], http=fake_http)
    assert fake_http.calls == []

    osv = [c for c in await _cves(engagement_id)
           if (c.raw_data or {}).get("matched_via") == "osv.dev"]
    assert osv == []


@pytest.mark.asyncio
async def test_osv_lookup_failure_is_non_fatal(engagement_id):
    routes = {"api.osv.dev/v1/query": ConnectionError("boom")}
    await _run(engagement_id, [_tech("React", "17.0.2")], http=FakeHTTP(routes))

    errs = [e for e in await evidence_for(engagement_id) if e.is_error]
    assert any("OSV.dev" in (e.summary or "") for e in errs)
