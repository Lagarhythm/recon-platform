"""Test harness for exercising a single recon module in isolation.

Gives you a real ``ModuleContext`` backed by a real DB session (so evidence is
actually written and can be asserted on) but with a fake HTTP client and a
no-op event emitter. No real network traffic.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator

import httpx
from sqlalchemy import select

from recon.core.roe import RoEConfig
from recon.core.scope import ScopeManager
from recon.db import session_scope
from recon.models.engagement import Engagement
from recon.models.enums import ModulePhase
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.modules.base import ModuleContext


class FakeResponse(httpx.Response):
    pass


class FakeHTTP:
    """Stand-in for ReconHTTPClient.

    Configure with ``routes``: a dict mapping a URL (or a substring) to either
    an ``httpx.Response`` or a callable ``(method, url) -> httpx.Response`` or
    an Exception instance to raise. ``calls`` records every request made.
    """

    def __init__(self, routes: dict | None = None, default_status: int = 404) -> None:
        self.routes = routes or {}
        self.default_status = default_status
        self.calls: list[tuple[str, str]] = []
        self.session = None
        self.module_name = "test"

    def _lookup(self, method: str, url: str) -> httpx.Response:
        self.calls.append((method, url))
        match = None
        if url in self.routes:
            match = self.routes[url]
        else:
            for key, val in self.routes.items():
                if key in url:
                    match = val
                    break
        if match is None:
            return httpx.Response(self.default_status, request=httpx.Request(method, url))
        if isinstance(match, Exception):
            raise match
        if callable(match):
            return match(method, url)
        return match

    async def request(self, method: str, url: str, **kw) -> httpx.Response:  # noqa: ANN003
        return self._lookup(method, url)

    async def get(self, url: str, **kw) -> httpx.Response:  # noqa: ANN003
        return self._lookup("GET", url)

    async def head(self, url: str, **kw) -> httpx.Response:  # noqa: ANN003
        return self._lookup("HEAD", url)

    async def acquire_slot(self) -> None:
        self.calls.append(("SLOT", ""))

    async def aclose(self) -> None:
        pass


@contextlib.asynccontextmanager
async def module_harness(
    engagement_id: str,
    module_name: str,
    *,
    http: FakeHTTP | None = None,
    prior_evidence: list[dict] | None = None,
) -> AsyncIterator[ModuleContext]:
    if prior_evidence:
        async with session_scope() as s:
            for ev in prior_evidence:
                s.add(Evidence(engagement_id=engagement_id, source_module="seed", **ev))

    async with session_scope() as session:
        engagement = await session.get(Engagement, engagement_id)
        roe = RoEConfig.model_validate(engagement.roe_config)
        run = ScanRun(
            engagement_id=engagement_id,
            roe_config_snapshot=engagement.roe_config,
            roe_config_hash=engagement.roe_config_hash,
            modules_requested=[module_name],
            modules_completed=[],
        )
        session.add(run)
        await session.flush()
        module_run = ScanModuleRun(
            scan_run_id=run.id,
            engagement_id=engagement_id,
            module_name=module_name,
            phase=ModulePhase.PASSIVE,
        )
        session.add(module_run)
        await session.flush()
        scan_run_id = run.id

        fake_http = http or FakeHTTP()
        fake_http.session = session
        fake_http.module_name = module_name

        events: list[tuple] = []

        async def _emit(etype, **data):  # noqa: ANN001, ANN003
            events.append((etype, data))

        ctx = ModuleContext(
            engagement=engagement,
            roe=roe,
            scope=ScopeManager(roe),
            scan_run_id=scan_run_id,
            module_name=module_name,
            module_run=module_run,
            session=session,
            http=fake_http,
            emit_event=_emit,
            is_cancelled=lambda: False,
        )
        ctx.events = events  # type: ignore[attr-defined]
        yield ctx
        await ctx.flush()


async def evidence_for(engagement_id: str, *, subject_type: str | None = None) -> list[Evidence]:
    async with session_scope() as s:
        stmt = select(Evidence).where(Evidence.engagement_id == engagement_id)
        if subject_type:
            stmt = stmt.where(Evidence.subject_type == subject_type)
        return list((await s.execute(stmt)).scalars())
