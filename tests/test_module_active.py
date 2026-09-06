"""Active modules (nmap / ffuf wrappers) - subprocess is mocked, no real scans."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recon.db import session_scope
from recon.models.asset import Asset
from recon.models.enums import (
    AssetType,
    InterestLevel,
    ModuleRunStatus,
    ScopeStatus,
    SkipReason,
)
from recon.modules.active.dir_fuzz import DirFuzzModule
from recon.modules.active.port_scan import PortScanModule
from recon.net.external import CommandResult
from tests.harness import evidence_for, module_harness


async def _seed_asset(engagement_id, atype, value, scope=ScopeStatus.IN_SCOPE):
    async with session_scope() as s:
        s.add(Asset(engagement_id=engagement_id, type=atype, value=value,
                    in_scope_status=scope, confidence_score=1.0,
                    interest_level=InterestLevel.INFORMATIONAL))


@pytest.mark.asyncio
async def test_port_scan_is_out_of_g2_and_skips_unverified(engagement_id):
    """Port scanning is out of the G2 active surface (Security G2 re-review,
    S2). The module records an explicit SKIPPED / unverified_targets and never
    resolves a target or execs a binary - it does not even import run_command."""
    import recon.modules.active.port_scan as ps

    assert not hasattr(ps, "run_command")

    async with module_harness(engagement_id, "port_scan") as ctx:
        await PortScanModule().run(ctx)
        assert ctx._module_run.status is ModuleRunStatus.SKIPPED
        assert ctx._module_run.skip_reason is SkipReason.UNVERIFIED_TARGETS

    assert await evidence_for(engagement_id, subject_type="service") == []


@pytest.mark.asyncio
async def test_port_scan_never_execs_even_with_passive_targets(engagement_id, monkeypatch):
    """Even with same-run DNS evidence and in-scope assets present - the exact
    legacy S1 bypass - the module still skips and no subprocess runs."""
    from recon.net import external

    async def _boom(*a, **k):
        raise AssertionError("port_scan must not exec a subprocess in G2")

    monkeypatch.setattr(external, "run_command", _boom)
    await _seed_asset(engagement_id, AssetType.IP, "203.0.113.10")

    async with module_harness(engagement_id, "port_scan") as ctx:
        await ctx.add_evidence(
            subject_type="dns_record", subject_value="api.example.com",
            raw_data={"name": "api.example.com", "rtype": "A", "value": "203.0.113.10"},
        )
        await ctx.flush()
        await PortScanModule().run(ctx)
        assert ctx._module_run.status is ModuleRunStatus.SKIPPED
        assert ctx._module_run.skip_reason is SkipReason.UNVERIFIED_TARGETS


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


