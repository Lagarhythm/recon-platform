"""Active modules (nmap / ffuf wrappers) - subprocess is mocked, no real scans."""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.enums import AssetType, InterestLevel, ScopeStatus
from recon.modules.active.dir_fuzz import DirFuzzModule
from recon.modules.active.port_scan import PortScanModule
from recon.net.external import CommandResult
from tests.harness import evidence_for, module_harness

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames><hostname name="api.example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


async def _seed_asset(engagement_id, atype, value, scope=ScopeStatus.IN_SCOPE):
    async with session_scope() as s:
        s.add(Asset(engagement_id=engagement_id, type=atype, value=value,
                    in_scope_status=scope, confidence_score=1.0,
                    interest_level=InterestLevel.INFORMATIONAL))


@pytest.mark.asyncio
async def test_port_scan_parses_services(engagement_id, monkeypatch):
    await _seed_asset(engagement_id, AssetType.IP, "203.0.113.10")

    monkeypatch.setattr("recon.modules.active.port_scan.find_binary", lambda n: "/usr/bin/nmap")

    async def fake_run(argv, **kw):
        assert "203.0.113.10" in argv
        assert "--max-rate" in argv
        return CommandResult(argv=argv, returncode=0, stdout=_NMAP_XML, stderr="")

    monkeypatch.setattr("recon.modules.active.port_scan.run_command", fake_run)

    async with module_harness(engagement_id, "port_scan") as ctx:
        await PortScanModule().run(ctx)

    svcs = await evidence_for(engagement_id, subject_type="service")
    ports = sorted(e.raw_data["port"] for e in svcs)
    assert ports == [22, 80]  # closed 3306 excluded
    assert any(e.raw_data["product"] == "OpenSSH" for e in svcs)


@pytest.mark.asyncio
async def test_port_scan_skips_when_binary_missing(engagement_id, monkeypatch):
    await _seed_asset(engagement_id, AssetType.IP, "203.0.113.10")
    monkeypatch.setattr("recon.modules.active.port_scan.find_binary", lambda n: None)
    async with module_harness(engagement_id, "port_scan") as ctx:
        await PortScanModule().run(ctx)
    errs = await evidence_for(engagement_id, subject_type="error")
    assert any("nmap not found" in (e.summary or "") for e in errs)
    assert await evidence_for(engagement_id, subject_type="service") == []


@pytest.mark.asyncio
async def test_port_scan_never_targets_excluded(engagement_id, monkeypatch):
    await _seed_asset(engagement_id, AssetType.SUBDOMAIN, "mail.example.com",
                      scope=ScopeStatus.IN_SCOPE)  # mislabelled in-scope on purpose
    monkeypatch.setattr("recon.modules.active.port_scan.find_binary", lambda n: "/usr/bin/nmap")
    captured = {}

    async def fake_run(argv, **kw):
        captured["argv"] = argv
        return CommandResult(argv=argv, returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

    monkeypatch.setattr("recon.modules.active.port_scan.run_command", fake_run)
    async with module_harness(engagement_id, "port_scan") as ctx:
        await PortScanModule().run(ctx)
    # mail.example.com is in excluded.hosts of EXAMPLE_ROE -> must not be scanned
    assert "argv" not in captured or "mail.example.com" not in captured["argv"]


_FFUF_RESULTS = {
    "results": [
        {"url": "https://example.com/admin", "status": 200, "length": 512, "words": 40, "lines": 12},
        {"url": "https://example.com/login", "status": 401, "length": 20, "words": 3, "lines": 1},
        # a big cluster of identical soft-404s:
        *[
            {"url": f"https://example.com/x{i}", "status": 200, "length": 999,
             "words": 100, "lines": 50}
            for i in range(30)
        ],
    ]
}


@pytest.mark.asyncio
async def test_dir_fuzz_filters_soft_404(engagement_id, monkeypatch, tmp_path):
    await _seed_asset(engagement_id, AssetType.URL, "https://example.com/")

    monkeypatch.setattr("recon.modules.active.dir_fuzz.find_binary", lambda n: "/usr/bin/ffuf")
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\n")
    from recon.config import get_settings
    monkeypatch.setattr(get_settings(), "fuzz_wordlist", wl, raising=False)

    async def fake_run(argv, **kw):
        out = argv[argv.index("-o") + 1]
        Path(out).write_text(json.dumps(_FFUF_RESULTS))
        return CommandResult(argv=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("recon.modules.active.dir_fuzz.run_command", fake_run)

    async with module_harness(engagement_id, "dir_fuzz") as ctx:
        await DirFuzzModule().run(ctx)

    urls = {e.subject_value for e in await evidence_for(engagement_id, subject_type="url")}
    assert "https://example.com/admin" in urls
    assert "https://example.com/login" in urls
    assert not any(u.startswith("https://example.com/x") for u in urls)  # soft-404 cluster dropped


@pytest.mark.asyncio
async def test_port_scan_dedupes_hostnames_sharing_an_ip(engagement_id, monkeypatch):
    # Three in-scope names, all resolving to one box -> nmap should get one
    # target, not three copies of the same 1000-port sweep.
    for host in ("a.example.com", "b.example.com", "c.example.com"):
        await _seed_asset(engagement_id, AssetType.SUBDOMAIN, host)

    async def fake_getaddrinfo(host, *a, **k):  # noqa: ANN001
        return [(2, 1, 6, "", ("198.51.100.7", 0))]

    monkeypatch.setattr(
        "recon.modules.active.port_scan.asyncio.get_running_loop",
        lambda: types.SimpleNamespace(getaddrinfo=fake_getaddrinfo),
    )
    monkeypatch.setattr("recon.modules.active.port_scan.find_binary", lambda n: "/usr/bin/nmap")

    seen = {}

    async def fake_run(argv, **kw):
        seen["argv"] = argv
        return CommandResult(argv=argv, returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

    monkeypatch.setattr("recon.modules.active.port_scan.run_command", fake_run)

    async with module_harness(engagement_id, "port_scan") as ctx:
        await PortScanModule().run(ctx)

    targets = [a for a in seen["argv"] if "example.com" in a]
    assert len(targets) == 1  # collapsed to a single name for the shared IP


@pytest.mark.asyncio
async def test_dir_fuzz_does_not_guess_https_for_a_confirmed_http_host(
    engagement_id, monkeypatch, tmp_path
):
    # A confirmed http:// root and a bare subdomain asset for the *same* host:
    # dir_fuzz must fuzz only the confirmed root, not also waste a full wordlist
    # run on a https:// guess that dead-ends.
    await _seed_asset(engagement_id, AssetType.URL, "http://box.example.com/")
    await _seed_asset(engagement_id, AssetType.SUBDOMAIN, "box.example.com")

    monkeypatch.setattr("recon.modules.active.dir_fuzz.find_binary", lambda n: "/usr/bin/ffuf")
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    from recon.config import get_settings
    monkeypatch.setattr(get_settings(), "fuzz_wordlist", wl, raising=False)

    fuzzed: list[str] = []

    async def fake_run(argv, **kw):
        fuzzed.append(argv[argv.index("-u") + 1])
        Path(argv[argv.index("-o") + 1]).write_text("{}")
        return CommandResult(argv=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("recon.modules.active.dir_fuzz.run_command", fake_run)

    async with module_harness(engagement_id, "dir_fuzz") as ctx:
        await DirFuzzModule().run(ctx)

    assert fuzzed == ["http://box.example.com/FUZZ"]


@pytest.mark.asyncio
async def test_port_scan_rejects_argument_injection_target(engagement_id, monkeypatch):
    # a crafted hostname that would be an nmap flag if passed through
    await _seed_asset(engagement_id, AssetType.SUBDOMAIN, "-oN/tmp/x.example.com")
    await _seed_asset(engagement_id, AssetType.IP, "203.0.113.9")
    monkeypatch.setattr("recon.modules.active.port_scan.find_binary", lambda n: "/usr/bin/nmap")
    seen = {}

    async def fake_run(argv, **kw):
        seen["argv"] = argv
        return CommandResult(argv=argv, returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

    monkeypatch.setattr("recon.modules.active.port_scan.run_command", fake_run)
    async with module_harness(engagement_id, "port_scan") as ctx:
        await PortScanModule().run(ctx)
    assert not any(a.startswith("-oN") for a in seen.get("argv", []))
    assert "203.0.113.9" in seen.get("argv", [])
