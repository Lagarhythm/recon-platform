"""End-to-end HTTP flow: setup -> login -> engagement -> audit -> kill switch."""

from __future__ import annotations

import pytest

from recon.core.audit import audit_logger
from recon.db import session_scope
from recon.models.enums import ScopeStatus
from tests.conftest import EXAMPLE_ROE, GOOD_PASSWORD


async def _do_setup(flow) -> None:
    r = await flow.client.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/setup"
    await flow.prime_csrf("/setup")
    r = await flow.post(
        "/setup",
        {"username": "operator", "password": GOOD_PASSWORD, "password_confirm": GOOD_PASSWORD},
    )
    assert r.status_code == 303 and r.headers["location"] == "/"


@pytest.mark.asyncio
async def test_setup_then_locked_down(flow):
    await _do_setup(flow)
    # setup route now bounces to login
    r = await flow.client.get("/setup")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    # dashboard reachable while authenticated
    r = await flow.client.get("/")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_setup_is_single_shot(flow):
    await _do_setup(flow)
    # A second setup POST must not create another operator.
    r = await flow.post(
        "/setup",
        {"username": "intruder", "password": GOOD_PASSWORD, "password_confirm": GOOD_PASSWORD},
    )
    assert r.status_code in (303, 400)
    r2 = await flow.client.get("/setup")
    assert r2.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_weak_password_rejected(flow):
    await flow.client.get("/setup")
    await flow.prime_csrf("/setup")
    r = await flow.post(
        "/setup", {"username": "op", "password": "weak", "password_confirm": "weak"}
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_csrf_required(flow):
    await flow.client.get("/setup")
    r = await flow.client.post(
        "/setup",
        data={"username": "op", "password": GOOD_PASSWORD, "password_confirm": GOOD_PASSWORD,
              "csrf_token": "wrong"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_login_logout_cycle(flow):
    await _do_setup(flow)
    # log out
    r = await flow.post("/logout", {})
    assert r.status_code == 303
    r = await flow.client.get("/")
    assert r.headers["location"] == "/login"
    # bad login
    await flow.prime_csrf("/login")
    r = await flow.post("/login", {"username": "operator", "password": "nope-nope-nope"})
    assert r.status_code == 401
    # good login
    r = await flow.post("/login", {"username": "operator", "password": GOOD_PASSWORD})
    assert r.status_code == 303
    r = await flow.client.get("/")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_engagement_lifecycle_and_audit_append_only(flow):
    await _do_setup(flow)
    await flow.client.get("/engagements")
    r = await flow.post("/engagements", {"roe_yaml": EXAMPLE_ROE})
    assert r.status_code == 303
    engagement_path = r.headers["location"]
    assert engagement_path.startswith("/engagements/")
    engagement_id = engagement_path.rsplit("/", 1)[1]

    # It was auto-activated; dashboard shows it.
    r = await flow.client.get("/")
    assert r.status_code == 200
    assert b"Test Engagement" in r.content

    # Write an audit entry directly through the logger, then confirm it is
    # visible and that there is no delete path.
    async with session_scope() as session:
        await audit_logger.record(
            session,
            engagement_id=engagement_id,
            module="test",
            target="api.example.com",
            in_scope_status=ScopeStatus.IN_SCOPE,
            roe_config_hash="deadbeef",
            request_detail={"method": "GET", "url": "https://api.example.com/"},
            response_meta={"status": 200, "bytes": 1234},
        )
    r = await flow.client.get("/audit")
    assert r.status_code == 200
    assert b"api.example.com" in r.content

    assert not hasattr(audit_logger, "delete")
    assert not hasattr(audit_logger, "update")


@pytest.mark.asyncio
async def test_status_badge_renders_with_value_and_class(flow):
    """Regression: enum columns must round-trip as enum members, not bare
    strings, or the template's .value call renders an empty, uncoloured badge."""
    await _do_setup(flow)
    await flow.client.get("/engagements")
    r = await flow.post("/engagements", {"roe_yaml": EXAMPLE_ROE})
    engagement_id = r.headers["location"].rsplit("/", 1)[1]

    listing = (await flow.client.get("/engagements")).text
    assert 'class="badge active"' in listing
    assert ">active<" in listing

    detail = (await flow.client.get(f"/engagements/{engagement_id}")).text
    assert 'class="badge active"' in detail

    # And after a status change the new value + class appear.
    await flow.post(f"/engagements/{engagement_id}/status", {"status": "completed"})
    detail2 = (await flow.client.get(f"/engagements/{engagement_id}")).text
    assert 'class="badge completed"' in detail2


@pytest.mark.asyncio
async def test_engagement_purge_requires_name_match(flow):
    await _do_setup(flow)
    await flow.client.get("/engagements")
    r = await flow.post("/engagements", {"roe_yaml": EXAMPLE_ROE})
    engagement_id = r.headers["location"].rsplit("/", 1)[1]

    r = await flow.post(f"/engagements/{engagement_id}/purge", {"confirm_name": "wrong name"})
    assert r.status_code == 303
    r = await flow.client.get(f"/engagements/{engagement_id}")
    assert r.status_code == 200  # still there

    r = await flow.post(f"/engagements/{engagement_id}/purge", {"confirm_name": "Test Engagement"})
    assert r.status_code == 303
    r = await flow.client.get(f"/engagements/{engagement_id}")
    assert r.status_code == 303  # gone -> redirect to list


@pytest.mark.asyncio
async def test_invalid_roe_rejected_by_endpoint(flow):
    await _do_setup(flow)
    await flow.client.get("/engagements")
    bad = EXAMPLE_ROE.replace("203.0.113.0/24", "not-a-cidr")
    r = await flow.post("/engagements", {"roe_yaml": bad})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_guided_form_creates_engagement(flow):
    await _do_setup(flow)
    r = await flow.client.get("/engagements/new")
    assert r.status_code == 200

    r = await flow.post(
        "/engagements/new",
        {
            "name": "Guided Test",
            "client": "Guided Client",
            "in_domains": "example.com\nexample.org",
            "include_subdomains": "on",
            "in_cidrs": "203.0.113.0/24",
            "ex_hosts": "mail.example.com",
            "max_rps": "5",
            "max_conc": "10",
            "jitter_enabled": "on",
            "jitter_min": "50",
            "jitter_max": "200",
            "user_agents": "UA-A\nUA-B",
            "rotation_strategy": "random",
        },
    )
    assert r.status_code == 303
    engagement_id = r.headers["location"].rsplit("/", 1)[1]

    from recon.db import session_scope
    from recon.orchestrator.engagements import EngagementService

    svc = EngagementService()
    async with session_scope() as s:
        eng = await svc.get(s, engagement_id)
        roe = svc.config_of(eng)
    assert "example.com" in roe.scope.in_scope.domains
    assert "*.example.com" in roe.scope.in_scope.domains  # include_subdomains
    assert "*.example.org" in roe.scope.in_scope.domains
    assert "203.0.113.0/24" in roe.scope.in_scope.cidrs
    assert "mail.example.com" in roe.scope.excluded.hosts
    assert roe.rate_limits.max_requests_per_second == 5
    assert roe.evasion.rotation_strategy.value == "random"
    assert roe.llm.analysis_enabled is False


@pytest.mark.asyncio
async def test_guided_form_error_repopulates(flow):
    await _do_setup(flow)
    r = await flow.post(
        "/engagements/new",
        {"name": "", "client": "HasClient", "in_domains": "example.com"},
    )
    assert r.status_code == 400
    assert b"HasClient" in r.content  # preserved on re-render


@pytest.mark.asyncio
async def test_guided_form_rejects_bad_cidr(flow):
    await _do_setup(flow)
    r = await flow.post(
        "/engagements/new",
        {"name": "X", "client": "Y", "in_cidrs": "10.0.0.0/99"},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_json_roe_accepted(flow):
    await _do_setup(flow)
    await flow.client.get("/engagements")
    roe_json = (
        '{"engagement": {"name": "JSON Eng", "client": "JC"}, '
        '"scope": {"in_scope": {"domains": ["json.example.com"]}}}'
    )
    r = await flow.post("/engagements", {"roe_yaml": roe_json})
    assert r.status_code == 303


@pytest.mark.asyncio
async def test_killswitch_toggle(flow):
    await _do_setup(flow)
    r = await flow.client.get("/health")
    assert r.json()["kill_switch"]["engaged"] is False

    r = await flow.post("/system/killswitch/engage", {"reason": "client called"})
    assert r.status_code == 303
    r = await flow.client.get("/health")
    assert r.json()["kill_switch"]["engaged"] is True
    assert r.json()["kill_switch"]["reason"] == "client called"

    r = await flow.post("/system/killswitch/reset", {})
    r = await flow.client.get("/health")
    assert r.json()["kill_switch"]["engaged"] is False


@pytest.mark.asyncio
async def test_everything_gated_before_setup(client):
    for path in ("/", "/engagements", "/audit", "/account"):
        r = await client.get(path)
        assert r.status_code == 303
        assert r.headers["location"] == "/setup"


@pytest.mark.asyncio
async def test_auth_required_after_logout(flow):
    await _do_setup(flow)
    await flow.post("/logout", {})
    for path in ("/", "/engagements", "/audit", "/account"):
        r = await flow.client.get(path)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"
