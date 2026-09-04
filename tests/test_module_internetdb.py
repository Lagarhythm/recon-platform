"""Shodan InternetDB module - all HTTP faked, no real network."""

from __future__ import annotations

import httpx
import pytest

from recon.modules.passive.internetdb import InternetDBModule
from tests.harness import FakeHTTP, evidence_for, module_harness

_IP = "203.0.113.10"          # inside EXAMPLE_ROE in_scope 203.0.113.0/24
_EXCLUDED_IP = "203.0.113.130"  # inside excluded 203.0.113.128/28

_RESPONSE = {
    "ip": _IP,
    "ports": [80, 443, 22],
    "cpes": ["cpe:/a:nginx:nginx:1.24.0", "cpe:/a:openbsd:openssh:9.6"],
    "hostnames": ["web01.example.com", "example.com"],
    "tags": ["cdn"],
    "vulns": ["CVE-2024-1234", "CVE-2023-9999"],
}


async def _run(engagement_id, routes, prior_ips):
    http = FakeHTTP(routes, default_status=404)
    prior = [
        {"subject_type": "ip", "subject_value": ip, "raw_data": {}}
        for ip in prior_ips
    ]
    async with module_harness(
        engagement_id, "internetdb", http=http, prior_evidence=prior
    ) as ctx:
        await InternetDBModule().run(ctx)
    return http


@pytest.mark.asyncio
async def test_emits_service_hostname_and_cve_evidence(engagement_id):
    routes = {f"internetdb.shodan.io/{_IP}": httpx.Response(200, json=_RESPONSE)}
    await _run(engagement_id, routes, [_IP])

    services = {e.subject_value for e in await evidence_for(engagement_id, subject_type="service")}
    assert services == {f"{_IP}:22", f"{_IP}:80", f"{_IP}:443"}

    svc = next(iter(await evidence_for(engagement_id, subject_type="service")))
    assert svc.raw_data["source"] == "internetdb"
    assert svc.raw_data["host"] == _IP and svc.raw_data["proto"] == "tcp"

    cves = {e.subject_value for e in await evidence_for(engagement_id, subject_type="cve")}
    assert cves == {"CVE-2024-1234", "CVE-2023-9999"}
    cve_ev = next(iter(await evidence_for(engagement_id, subject_type="cve")))
    assert cve_ev.raw_data["ip"] == _IP and cve_ev.raw_data["interest"] == "notable"

    hosts = {e.subject_value for e in await evidence_for(engagement_id, subject_type="subdomain")}
    hosts |= {e.subject_value for e in await evidence_for(engagement_id, subject_type="domain")}
    assert "web01.example.com" in hosts and "example.com" in hosts


@pytest.mark.asyncio
async def test_404_is_silent_not_an_error(engagement_id):
    # no route -> FakeHTTP default 404
    await _run(engagement_id, {}, [_IP])
    assert await evidence_for(engagement_id, subject_type="service") == []
    errors = [e for e in await evidence_for(engagement_id) if e.is_error]
    assert errors == []


@pytest.mark.asyncio
async def test_500_records_a_nonfatal_error_and_continues(engagement_id):
    routes = {
        f"internetdb.shodan.io/{_IP}": httpx.Response(500, text="boom"),
        "internetdb.shodan.io/198.51.100.7": httpx.Response(200, json={
            "ip": "198.51.100.7", "ports": [443], "cpes": [], "hostnames": [],
            "tags": [], "vulns": [],
        }),
    }
    await _run(engagement_id, routes, [_IP, "198.51.100.7"])
    errs = [e for e in await evidence_for(engagement_id) if e.is_error]
    assert len(errs) == 1 and "HTTP 500" in errs[0].summary
    # the healthy IP still produced its service
    assert {e.subject_value for e in await evidence_for(engagement_id, subject_type="service")} == {
        "198.51.100.7:443"
    }


@pytest.mark.asyncio
async def test_excluded_ip_is_never_looked_up(engagement_id):
    http = await _run(
        engagement_id,
        {f"internetdb.shodan.io/{_EXCLUDED_IP}": httpx.Response(200, json=_RESPONSE)},
        [_EXCLUDED_IP],
    )
    assert http.calls == []  # no request made at all
    assert await evidence_for(engagement_id, subject_type="service") == []


@pytest.mark.asyncio
async def test_ipv6_is_skipped(engagement_id):
    http = await _run(engagement_id, {}, ["2606:4700:10::6814:179a"])
    assert http.calls == []
