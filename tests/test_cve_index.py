"""cve_index - the CISA KEV / NVD fetch is mocked via httpx.MockTransport, no
real network."""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from recon.db import session_scope
from recon.models.cve import CVEIndexMeta, CVERecord
from recon.orchestrator.cve_index import CVEIndexError, refresh_index

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _kev_response(cve_ids: list[str]) -> httpx.Response:
    return httpx.Response(200, json={
        "catalogVersion": "2026.09.04",
        "vulnerabilities": [{"cveID": c} for c in cve_ids],
    })


def _nvd_cve(cve_id: str, *, score=8.1, severity="HIGH", cpe="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-05T00:00:00.000",
            "descriptions": [{"lang": "en", "value": f"{cve_id} description"}],
            "references": [{"url": "https://example.com/advisory", "source": "nvd",
                             "tags": ["Vendor Advisory"]}],
            "metrics": {
                "cvssMetricV31": [{
                    "source": "nvd@nist.gov", "type": "Primary",
                    "cvssData": {"version": "3.1", "baseScore": score,
                                 "baseSeverity": severity,
                                 "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                }],
            },
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True, "criteria": cpe,
                "versionStartIncluding": "1.0", "versionEndExcluding": "2.0",
            }]}]}],
        },
    }


def _nvd_page(items: list[dict], *, total: int | None = None) -> httpx.Response:
    return httpx.Response(200, json={
        "resultsPerPage": len(items), "startIndex": 0,
        "totalResults": total if total is not None else len(items),
        "vulnerabilities": items,
    })


def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _index_rows() -> list[CVERecord]:
    async with session_scope() as session:
        return list((await session.execute(select(CVERecord))).scalars())


async def _meta() -> CVEIndexMeta | None:
    async with session_scope() as session:
        return await session.get(CVEIndexMeta, "singleton")


# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_local_refresh_upserts_kev_and_high_cvss_records():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return _kev_response(["CVE-2024-0001"])
        if str(request.url).startswith(_NVD_URL):
            severity = request.url.params.get("cvssV3Severity")
            if severity == "HIGH":
                return _nvd_page([_nvd_cve("CVE-2024-0002", score=8.1, severity="HIGH")])
            if severity == "CRITICAL":
                return _nvd_page([_nvd_cve("CVE-2024-0003", score=9.8, severity="CRITICAL")])
        raise AssertionError(f"unexpected request: {request.url}")

    async with session_scope() as session:
        meta = await refresh_index(session, source="local", client=_mock_client(handler))
        assert meta.source == "local"
        assert meta.feed_version == "2026.09.04"

    rows = {r.cve_id: r for r in await _index_rows()}
    assert set(rows) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    assert rows["CVE-2024-0002"].cvss_v31_score == 8.1
    assert rows["CVE-2024-0002"].cvss_v31_severity == "HIGH"
    assert rows["CVE-2024-0003"].cvss_v31_score == 9.8
    assert not rows["CVE-2024-0002"].in_kev
    assert not rows["CVE-2024-0003"].in_kev


@pytest.mark.asyncio
async def test_kev_only_cve_gets_a_bare_record_with_in_kev_true():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            # In KEV but NVD scored it below the HIGH/CRITICAL cutoff (or it's
            # simply not in the queried severity pages) - still must appear.
            return _kev_response(["CVE-2024-9999"])
        if str(request.url).startswith(_NVD_URL):
            return _nvd_page([])
        raise AssertionError(f"unexpected request: {request.url}")

    async with session_scope() as session:
        await refresh_index(session, source="local", client=_mock_client(handler))

    [row] = await _index_rows()
    assert row.cve_id == "CVE-2024-9999"
    assert row.in_kev is True
    assert row.cvss_v31_score is None
    assert row.cpe_matches == []


@pytest.mark.asyncio
async def test_cpe_matches_are_flattened_with_part_vendor_product():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return _kev_response([])
        severity = request.url.params.get("cvssV3Severity")
        if severity == "HIGH":
            return _nvd_page([_nvd_cve("CVE-2024-0002")])
        return _nvd_page([])

    async with session_scope() as session:
        await refresh_index(session, source="local", client=_mock_client(handler))

    [row] = await _index_rows()
    assert row.cpe_matches == [{
        "cpe": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
        "part": "a", "vendor": "acme", "product": "widget",
        "version_start": "1.0", "version_end": "2.0", "vulnerable": True,
    }]


@pytest.mark.asyncio
async def test_nvd_pagination_is_followed_to_completion():
    page1 = [_nvd_cve(f"CVE-2024-{i:04d}") for i in range(2)]
    page2 = [_nvd_cve(f"CVE-2024-{i:04d}") for i in range(2, 3)]

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return _kev_response([])
        if request.url.params.get("cvssV3Severity") != "HIGH":
            return _nvd_page([])
        start = int(request.url.params.get("startIndex", "0"))
        if start == 0:
            return httpx.Response(200, json={
                "resultsPerPage": 2, "startIndex": 0, "totalResults": 3,
                "vulnerabilities": page1,
            })
        return httpx.Response(200, json={
            "resultsPerPage": 2, "startIndex": 2, "totalResults": 3,
            "vulnerabilities": page2,
        })

    import recon.orchestrator.cve_index as cve_index_mod
    orig_interval = cve_index_mod._NVD_REQUEST_INTERVAL
    cve_index_mod._NVD_REQUEST_INTERVAL = 0  # don't actually sleep in tests
    try:
        async with session_scope() as session:
            await refresh_index(session, source="local", client=_mock_client(handler))
    finally:
        cve_index_mod._NVD_REQUEST_INTERVAL = orig_interval

    rows = await _index_rows()
    assert {r.cve_id for r in rows} == {"CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002"}


@pytest.mark.asyncio
async def test_refresh_upserts_not_duplicates_on_rerun():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return _kev_response(["CVE-2024-0001"])
        return _nvd_page([])

    async with session_scope() as session:
        await refresh_index(session, source="local", client=_mock_client(handler))
    async with session_scope() as session:
        await refresh_index(session, source="local", client=_mock_client(handler))

    rows = await _index_rows()
    assert len(rows) == 1

    meta = await _meta()
    assert meta.record_count == 1


@pytest.mark.asyncio
async def test_kev_fetch_failure_raises_and_writes_nothing():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return httpx.Response(503)
        raise AssertionError("NVD should never be reached if KEV fails first")

    with pytest.raises(CVEIndexError):
        async with session_scope() as session:
            await refresh_index(session, source="local", client=_mock_client(handler))

    assert await _index_rows() == []
    assert await _meta() is None


@pytest.mark.asyncio
async def test_nvd_fetch_failure_raises_and_writes_nothing():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return _kev_response(["CVE-2024-0001"])
        return httpx.Response(500)

    with pytest.raises(CVEIndexError):
        async with session_scope() as session:
            await refresh_index(session, source="local", client=_mock_client(handler))

    # KEV succeeded but NVD failed before any write - nothing committed.
    assert await _index_rows() == []


@pytest.mark.asyncio
async def test_unknown_source_is_rejected_before_any_network_call():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not make any request for an invalid source")

    with pytest.raises(CVEIndexError):
        async with session_scope() as session:
            await refresh_index(session, source="bogus", client=_mock_client(handler))


@pytest.mark.asyncio
async def test_cli_cve_status_and_refresh_round_trip(monkeypatch):
    from recon.cli.client import InProcessClient

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_KEV_URL):
            return _kev_response(["CVE-2024-0001"])
        return _nvd_page([])

    real_refresh_index = refresh_index  # capture before patching - avoid self-recursion

    async def fake_refresh_index(session, *, source="local", client=None):
        return await real_refresh_index(session, source=source, client=_mock_client(handler))

    monkeypatch.setattr(
        "recon.orchestrator.cve_index.refresh_index", fake_refresh_index
    )

    client = InProcessClient()
    before = await client.cve_status()
    assert before["available"] is False

    out = await client.cve_refresh("local")
    assert out["source"] == "local"
    assert out["record_count"] == 1

    after = await client.cve_status()
    assert after["available"] is True
    assert after["record_count"] == 1
    assert after["kev_count"] == 1
