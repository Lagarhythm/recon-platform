"""Wave 0: artifact store + AssetSnapshot schema + shared rate limiter +
correlation evidence chunking.

Coverage for the Hermes net/db/correlation foundations work:
  * content-addressed artifact store (dedup, path resolution, soft cap, trash),
  * AssetSnapshot row round-trip,
  * the scan-run shared token bucket injected into ReconHTTPClient and
    ModuleContext (no module news up its own),
  * correlation streams evidence in chunks (large-engagement memory bound).
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest
from sqlalchemy import func, select

from recon.artifacts.store import ArtifactStore
from recon.db import session_scope
from recon.models.artifact import Artifact
from recon.models.asset import Asset
from recon.models.engagement import Engagement
from recon.models.enums import AssetType
from recon.models.evidence import Evidence
from recon.models.snapshot import AssetSnapshot
from recon.net.http_client import ReconHTTPClient
from recon.net.rate_limit import RateLimiter


# ===========================================================================
# Artifact store
# ===========================================================================
@pytest.fixture
def artifact_dir(tmp_path: Path) -> Path:
    return tmp_path / "artifacts"


@pytest.fixture
def store(artifact_dir: Path) -> ArtifactStore:
    return ArtifactStore(base_dir=artifact_dir)


def test_store_bytes_is_content_addressed_and_dedupes(store: ArtifactStore, artifact_dir: Path):
    payload = b"hello-screenshot-bytes"
    a1 = store.store_bytes("eng-1", payload, kind="screenshot", content_type="image/png")
    a2 = store.store_bytes("eng-1", payload, kind="screenshot", content_type="image/png")

    # same bytes -> same sha256 -> same path (content addressing)
    assert a1.sha256 == a2.sha256 == hashlib.sha256(payload).hexdigest()
    assert a1.path == a2.path == f"eng-1/{a1.sha256}"
    assert a1.bytes == a2.bytes == len(payload)

    # file exists under data/artifacts/<engagement_id>/<sha256>
    rel_file = (artifact_dir / a1.path)
    assert rel_file.is_file()
    assert rel_file.read_bytes() == payload

    # exactly one copy even though stored twice
    eng_dir = artifact_dir / "eng-1"
    assert len(list(eng_dir.iterdir())) == 1


def test_store_bytes_rejects_empty(store: ArtifactStore):
    with pytest.raises(ValueError):
        store.store_bytes("eng-1", b"", kind="http_body")


def test_different_bytes_same_engagement_get_distinct_paths(store: ArtifactStore):
    a1 = store.store_bytes("eng-1", b"aaa", kind="http_body")
    a2 = store.store_bytes("eng-1", b"bbb", kind="http_body")
    assert a1.sha256 != a2.sha256
    assert a1.path != a2.path


def test_absolute_path_resolves_under_base(store: ArtifactStore):
    row = store.store_bytes("eng-1", b"abc", kind="http_body")
    abs_path = store.absolute_path(row.path)
    assert abs_path.is_relative_to(store._base)
    assert abs_path.read_bytes() == b"abc"


def test_absolute_path_rejects_traversal(store: ArtifactStore):
    with pytest.raises(ValueError):
        store.absolute_path("../../etc/passwd")


def test_soft_cap_warns_but_writes(artifact_dir: Path, caplog):
    import logging

    store = ArtifactStore(base_dir=artifact_dir, soft_cap_bytes=5)
    with caplog.at_level(logging.WARNING):
        store.store_bytes("eng-1", b"x" * 32, kind="screenshot")
    assert any("soft cap" in r.message for r in caplog.records)
    # the write still landed
    assert (artifact_dir / "eng-1").is_dir()


@pytest.mark.asyncio
async def test_artifact_row_persists(engagement_id: str, store: ArtifactStore):
    row = store.store_bytes(engagement_id, b"body-bytes", kind="http_body", content_type="text/html")
    async with session_scope() as s:
        s.add(row)
        await s.commit()
    async with session_scope() as s:
        got = (await s.execute(select(Artifact))).scalar_one()
        assert got.engagement_id == engagement_id
        assert got.kind == "http_body"
        assert got.content_type == "text/html"
        assert got.bytes == 10  # len(b"body-bytes")


# ===========================================================================
# AssetSnapshot schema round-trip
# ===========================================================================
@pytest.mark.asyncio
async def test_asset_snapshot_round_trip(engagement_id: str):
    """AssetSnapshot is schema-only in Wave 0 - the row round-trips and holds
    the signature set + summary that scan_diff (Wave 2) will consume."""
    from recon.models.scanrun import ScanRun

    async with session_scope() as s:
        run_obj = ScanRun(
            engagement_id=engagement_id,
            roe_config_snapshot={},
            roe_config_hash="hash",
            modules_requested=[],
            modules_completed=[],
        )
        s.add(run_obj)
        await s.commit()
        sn = AssetSnapshot(
            engagement_id=engagement_id,
            scan_run_id=run_obj.id,
            signature_set=["subdomain:api.acme.com", "service:1.2.3.4:443:nginx/1.24"],
            summary={"subdomain": 1, "service": 1},
        )
        s.add(sn)
        await s.commit()
        got = (await s.execute(select(AssetSnapshot))).scalar_one()
        assert got.engagement_id == engagement_id
        assert got.scan_run_id == run_obj.id
        assert got.signature_set == ["subdomain:api.acme.com", "service:1.2.3.4:443:nginx/1.24"]
        assert got.summary == {"subdomain": 1, "service": 1}
        assert got.taken_at is not None


# ===========================================================================
# Shared rate limiter
# ===========================================================================
def test_http_client_uses_injected_shared_limiter(engagement_id: str):
    """The scan-run's shared token bucket is what the HTTP client draws from,
    not a private one it news up itself."""
    from recon.core.roe import RoEConfig
    from recon.core.scope import ScopeManager

    shared = RateLimiter(7.0)
    roe = RoEConfig(
        engagement={"name": "e", "client": "c"},
        scope={"in_scope": {"domains": ["example.com"]}},
        rate_limits={"max_requests_per_second": 99.0},
    )
    client = ReconHTTPClient(
        roe=roe,
        scope=ScopeManager(roe),
        engagement_id=engagement_id,
        roe_config_hash="h",
        scan_run_id="run",
        rate_limiter=shared,
    )
    try:
        assert client.rate_limiter is shared
        # the injected bucket wins over the RoE's rate - one shared budget
        assert client.rate_limiter._rate == 7.0
    finally:
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(client.aclose())


@pytest.mark.asyncio
async def test_module_context_falls_back_to_roe_sized_bucket(engagement_id: str):
    """Without an injected bucket (test harness), ModuleContext builds a private
    one sized from the RoE so isolated module runs still rate-limit."""
    from recon.core.roe import RoEConfig
    from recon.core.scope import ScopeManager
    from recon.models.scanrun import ScanRun, ScanModuleRun
    from recon.modules.base import ModuleContext
    from tests.harness import FakeHTTP

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        roe = RoEConfig.model_validate(eng.roe_config)
        run = ScanRun(engagement_id=engagement_id, roe_config_snapshot=eng.roe_config,
                      roe_config_hash=eng.roe_config_hash, modules_requested=[], modules_completed=[])
        s.add(run)
        await s.flush()
        modrun = ScanModuleRun(scan_run_id=run.id, engagement_id=engagement_id,
                               module_name="x", phase="passive")
        s.add(modrun)
        await s.flush()
        ctx = ModuleContext(
            engagement=eng, roe=roe, scope=ScopeManager(roe), scan_run_id=run.id,
            module_name="x", module_run=modrun, session=s, http=FakeHTTP(),
            emit_event=lambda *a, **k: asyncio.sleep(0), is_cancelled=lambda: False,
        )
        assert ctx.rate_limiter._rate == roe.rate_limits.max_requests_per_second
        await ctx.flush()


@pytest.mark.asyncio
async def test_module_context_uses_injected_shared_bucket(engagement_id: str):
    """When the orchestrator injects the scan-run bucket, the context exposes
    exactly that instance - so module DNS actions share it with HTTP."""
    from recon.core.roe import RoEConfig
    from recon.core.scope import ScopeManager
    from recon.models.scanrun import ScanRun, ScanModuleRun
    from recon.modules.base import ModuleContext
    from tests.harness import FakeHTTP

    shared = RateLimiter(3.0)

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        roe = RoEConfig.model_validate(eng.roe_config)
        run = ScanRun(engagement_id=engagement_id, roe_config_snapshot=eng.roe_config,
                      roe_config_hash=eng.roe_config_hash, modules_requested=[], modules_completed=[])
        s.add(run)
        await s.flush()
        modrun = ScanModuleRun(scan_run_id=run.id, engagement_id=engagement_id,
                               module_name="x", phase="passive")
        s.add(modrun)
        await s.flush()
        ctx = ModuleContext(
            engagement=eng, roe=roe, scope=ScopeManager(roe), scan_run_id=run.id,
            module_name="x", module_run=modrun, session=s, http=FakeHTTP(),
            emit_event=lambda *a, **k: asyncio.sleep(0), is_cancelled=lambda: False,
            rate_limiter=shared,
        )
        assert ctx.rate_limiter is shared
        await ctx.flush()


# ===========================================================================
# Correlation streaming
# ===========================================================================
@pytest.mark.asyncio
async def test_correlation_streams_many_evidence_rows(engagement_id: str):
    """A large evidence set is consumed in bounded streamed batches; grouping
    and asset creation still produce the right result."""
    from recon.correlation.engine import CorrelationEngine

    n = 1200  # > the 500-row chunk size, forces multiple stream batches
    async with session_scope() as s:
        for i in range(n):
            s.add(Evidence(
                engagement_id=engagement_id,
                source_module="ct",
                subject_type="subdomain",
                subject_value=f"host{i}.example.com",
                raw_data={},
            ))
        await s.commit()

    async with session_scope() as s:
        eng = await s.get(Engagement, engagement_id)
        summary = await CorrelationEngine().correlate(s, eng)

    assert summary.evidence_processed == n
    assert summary.assets_created == n  # one subdomain asset each

    async with session_scope() as s:
        count = (await s.execute(
            select(func.count(Asset.id)).where(
                Asset.engagement_id == engagement_id, Asset.type == AssetType.SUBDOMAIN
            )
        )).scalar_one()
    assert count == n
