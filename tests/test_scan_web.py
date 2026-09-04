"""Web integration: start a scan through the dashboard, see assets appear."""

from __future__ import annotations

import pytest

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import scan_service
from tests.conftest import EXAMPLE_ROE, GOOD_PASSWORD, wait_for


class _WebFakeModule(ReconModule):
    name = "web_fake"
    phase = ModulePhase.PASSIVE
    description = "emits one subdomain"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="found.example.com", raw_data={}
        )


@pytest.fixture(autouse=True)
def _register():
    MODULES["web_fake"] = _WebFakeModule()
    yield
    MODULES.pop("web_fake", None)


@pytest.fixture(autouse=True)
async def _cleanup():
    yield
    kill_switch.reset()
    await scan_service.shutdown()
    scan_service._handles.clear()


async def _setup(flow):
    await flow.client.get("/setup")
    await flow.prime_csrf("/setup")
    await flow.post(
        "/setup",
        {"username": "op", "password": GOOD_PASSWORD, "password_confirm": GOOD_PASSWORD},
    )
    await flow.client.get("/engagements")
    r = await flow.post("/engagements", {"roe_yaml": EXAMPLE_ROE})
    return r.headers["location"].rsplit("/", 1)[1]


@pytest.mark.asyncio
async def test_start_scan_via_web_and_see_assets(flow):
    await _setup(flow)

    r = await flow.post("/scans", {"modules": "web_fake"})
    assert r.status_code == 303
    scan_path = r.headers["location"]
    assert scan_path.startswith("/scans/")

    async def _run_completed():
        page = await flow.client.get(scan_path)
        return b'id="run-status">completed<' in page.content

    await wait_for(_run_completed, timeout=20)

    async def _asset_visible():
        page = await flow.client.get("/assets")
        return b"found.example.com" in page.content

    await wait_for(_asset_visible, timeout=5)

    # audit log recorded nothing outbound (fake module made no requests) but the
    # scan run and asset browser are consistent
    dash = await flow.client.get("/")
    assert b"What we know" in dash.content


@pytest.mark.asyncio
async def test_scan_requires_module_selection(flow):
    await _setup(flow)
    r = await flow.post("/scans", {})
    assert r.status_code == 303  # redirects back with a flash, not a crash


@pytest.mark.asyncio
async def test_cannot_start_scan_with_kill_switch_engaged(flow):
    await _setup(flow)
    kill_switch.engage("test")
    r = await flow.post("/scans", {"modules": "web_fake"})
    assert r.status_code == 303
    # no run created
    runs_page = await flow.client.get("/scans")
    assert runs_page.content.count(b"/scans/") <= 3  # nav + form only, no run rows
    kill_switch.reset()
