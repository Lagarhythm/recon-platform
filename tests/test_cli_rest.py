"""`recon` CLI - REST transport (``--server``) and the ``/api/v1`` surface.

Drives the JSON API through the in-process ASGI client with a real bearer
token, and the ``RestClient`` against that same ASGI app.
"""

from __future__ import annotations

import json

import pytest

from recon.db import session_scope
from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import scan_service
from tests.conftest import EXAMPLE_ROE, GOOD_PASSWORD


@pytest.fixture
async def token() -> str:
    from recon.orchestrator.auth import AuthService
    from recon.orchestrator.tokens import TokenService

    async with session_scope() as s:
        user = await AuthService().create_initial_admin(s, "operator", GOOD_PASSWORD)
        await s.flush()
        _, raw = await TokenService().create(s, user, "test-cli")
        await s.flush()
        return raw


@pytest.fixture
def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------
async def test_api_requires_bearer_token(client):
    assert (await client.get("/api/v1/engagements")).status_code == 401
    r = await client.get("/api/v1/engagements", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


async def test_api_rejects_revoked_token(client, auth, token):
    from recon.orchestrator.tokens import TokenService
    from recon.models.user import User
    from sqlalchemy import select

    async with session_scope() as s:
        user = (await s.execute(select(User))).scalars().first()
        rows = await TokenService().list(s, user)
        await TokenService().revoke(s, user, rows[0].id)
    assert (await client.get("/api/v1/engagements", headers=auth)).status_code == 401


# ---------------------------------------------------------------------------
# engagement + token endpoints
# ---------------------------------------------------------------------------
async def test_api_engagement_crud(client, auth):
    r = await client.post(
        "/api/v1/engagements", headers=auth, json={"roe_yaml": EXAMPLE_ROE}
    )
    assert r.status_code == 200, r.text
    eid = r.json()["id"]

    r = await client.get("/api/v1/engagements", headers=auth)
    assert [e["id"] for e in r.json()] == [eid]

    r = await client.get(f"/api/v1/engagements/{eid}", headers=auth)
    assert r.json()["assets"] == 0

    r = await client.post(
        f"/api/v1/engagements/{eid}/status", headers=auth, json={"status": "archived"}
    )
    assert r.json()["status"] == "archived"

    r = await client.get(f"/api/v1/engagements/{eid}/report", headers=auth,
                         params={"format": "json"})
    assert r.headers["content-type"].startswith("application/json")
    assert json.loads(r.content)["engagement"]["name"] == "Test Engagement"


async def test_api_purge_requires_matching_confirm_name(client, auth):
    r = await client.post(
        "/api/v1/engagements", headers=auth, json={"roe_yaml": EXAMPLE_ROE}
    )
    eid = r.json()["id"]
    # wrong / missing confirm_name -> 400, engagement survives
    assert (await client.post(f"/api/v1/engagements/{eid}/purge", headers=auth,
                              json={})).status_code == 400
    assert (await client.post(f"/api/v1/engagements/{eid}/purge", headers=auth,
                              json={"confirm_name": "nope"})).status_code == 400
    assert (await client.get(f"/api/v1/engagements/{eid}", headers=auth)).status_code == 200
    # correct name -> gone
    r = await client.post(f"/api/v1/engagements/{eid}/purge", headers=auth,
                          json={"confirm_name": "Test Engagement"})
    assert r.status_code == 200
    assert (await client.get("/api/v1/engagements", headers=auth)).json() == []


async def test_api_bad_roe_is_400(client, auth):
    r = await client.post(
        "/api/v1/engagements", headers=auth, json={"roe_yaml": "engagement: {}"}
    )
    assert r.status_code == 400


async def test_api_token_endpoints(client, auth):
    r = await client.post("/api/v1/tokens", headers=auth, json={"name": "second"})
    assert r.status_code == 200
    raw = r.json()["token"]
    assert raw.startswith("recon_")

    r = await client.get("/api/v1/tokens", headers=auth)
    names = {t["name"] for t in r.json()}
    assert {"test-cli", "second"} <= names

    # the freshly minted token authenticates
    r = await client.get("/api/v1/engagements", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 200


async def test_api_cve_status(client, auth):
    r = await client.get("/api/v1/cve/status", headers=auth)
    assert r.json()["available"] is False


# ---------------------------------------------------------------------------
# scan + SSE
# ---------------------------------------------------------------------------
class _RestFake(ReconModule):
    name = "rest_fake_ok"
    phase = ModulePhase.PASSIVE
    description = "rest cli test"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="rest.example.com", raw_data={}
        )


@pytest.fixture(autouse=True)
def _fake():
    MODULES[_RestFake.name] = _RestFake()
    yield
    MODULES.pop(_RestFake.name, None)


@pytest.fixture(autouse=True)
async def _cleanup_scans():
    yield
    kill_switch.reset()
    await scan_service.shutdown()
    scan_service._handles.clear()


async def test_api_scan_start_and_sse(client, auth):
    r = await client.post(
        "/api/v1/engagements", headers=auth, json={"roe_yaml": EXAMPLE_ROE}
    )
    eid = r.json()["id"]

    r = await client.post(
        "/api/v1/scans", headers=auth,
        json={"engagement_id": eid, "modules": ["rest_fake_ok"]},
    )
    assert r.status_code == 200, r.text
    run_id = r.json()["id"]

    seen = []
    async with client.stream("GET", f"/api/v1/scans/{run_id}/events", headers=auth) as resp:
        assert resp.status_code == 200
        async for line in resp.aiter_lines():
            line = line.strip()
            if line.startswith("data:"):
                evt = json.loads(line[5:].strip())
                seen.append(evt["type"])
                if evt["type"] in ("scan_completed", "scan_failed"):
                    break
    assert "scan_completed" in seen

    r = await client.get(f"/api/v1/scans/{run_id}", headers=auth)
    assert r.json()["status"] == "completed"

    r = await client.get("/api/v1/scans", headers=auth, params={"engagement_id": eid})
    assert run_id in [x["id"] for x in r.json()]


async def test_rest_client_against_asgi(token):
    """RestClient's own request/serialise path against the ASGI app."""
    import httpx

    from recon.cli.client import RestClient
    from recon.main import app

    rc = RestClient("http://testserver", token)
    await rc._http.aclose()
    rc._http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver/api/v1",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        await rc.engagement_create(EXAMPLE_ROE, "Via RestClient")
        rows = await rc.engagement_list()
        assert rows[0]["name"] == "Via RestClient"
    finally:
        await rc.aclose()


async def test_rest_client_missing_token_is_auth_error():
    from recon.cli.client import RestClient
    from recon.cli.output import CliError

    with pytest.raises(CliError) as ei:
        RestClient("http://x", "")
    assert ei.value.exit_code == 3
