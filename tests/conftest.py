"""Test fixtures.

The DB engine in ``recon.db`` is created from settings at import time, so the
environment must be pointed at a throwaway database *before* any ``recon``
import happens.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="recon-test-"))
atexit.register(shutil.rmtree, _TMP, ignore_errors=True)
os.environ.setdefault("RECON_SECRET_KEY", "test-secret-key-do-not-use-in-prod")
os.environ["RECON_DATA_DIR"] = str(_TMP)
os.environ["RECON_DATABASE_URL"] = f"sqlite+aiosqlite:///{(_TMP / 'test.db').as_posix()}"

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from recon.db import engine  # noqa: E402
from recon.main import app  # noqa: E402
from recon.models import Base  # noqa: E402


_schema_ready = False


@pytest_asyncio.fixture(autouse=True)
async def _schema():
    """Create the schema once, then just wipe rows between tests (much faster
    than drop_all/create_all per test)."""
    global _schema_ready
    if not _schema_ready:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        _schema_ready = True
    yield
    async with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", follow_redirects=False
    ) as c:
        yield c


class Flow:
    """Helper that carries CSRF state through a form-driven session."""

    def __init__(self, client: AsyncClient) -> None:
        self.client = client

    @property
    def csrf(self) -> str:
        return self.client.cookies.get("recon_csrf", "")

    async def prime_csrf(self, url: str = "/login") -> str:
        await self.client.get(url)
        return self.csrf

    async def post(self, url: str, data: dict) -> "object":
        if "csrf_token" not in data:
            if not self.csrf:
                await self.prime_csrf()
            data = {**data, "csrf_token": self.csrf}
        return await self.client.post(url, data=data)


@pytest_asyncio.fixture
async def flow(client) -> Flow:
    return Flow(client)


EXAMPLE_ROE = """
engagement:
  name: "Test Engagement"
  client: "Test Client"
  authorized_window:
    start: "2026-01-01T00:00:00Z"
    end: "2030-01-01T00:00:00Z"
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
    cidrs: ["203.0.113.0/24"]
  excluded:
    hosts: ["mail.example.com"]
    cidrs: ["203.0.113.128/28"]
rate_limits:
  max_requests_per_second: 10
  max_concurrent_connections: 20
evasion:
  jitter: {enabled: true, min_ms: 100, max_ms: 1500}
  user_agents: ["UA-1", "UA-2"]
  rotation_strategy: "round_robin"
llm:
  analysis_enabled: false
"""

GOOD_PASSWORD = "Sup3rSecret!pw"


@pytest.fixture
def example_roe() -> str:
    return EXAMPLE_ROE


@pytest_asyncio.fixture
async def engagement_id() -> str:
    """A committed engagement built from EXAMPLE_ROE; returns its id."""
    from recon.db import session_scope
    from recon.orchestrator.engagements import EngagementService

    async with session_scope() as session:
        eng, _ = await EngagementService().create(session, EXAMPLE_ROE)
        return eng.id


async def wait_for(predicate, *, timeout: float = 15.0, interval: float = 0.15):
    """Poll an async predicate until it returns truthy or the timeout elapses."""
    import asyncio

    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        result = await predicate()
        if result:
            return result
        await asyncio.sleep(interval)
    raise AssertionError("condition not met within timeout")
