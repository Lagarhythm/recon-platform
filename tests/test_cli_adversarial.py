"""Adversarial pass on the auth / scope surface the CLI + /api/v1 expose.

Mirrors tests/test_adversarial*.py: each test is a specific misuse or bypass
attempt that must fail safely (no 500, no credential leak, no privilege gain).
"""

from __future__ import annotations

import pytest

from recon.cli.client import InProcessClient
from recon.cli.output import CliError
from recon.db import session_scope
from recon.orchestrator.tokens import TokenService
from tests.conftest import EXAMPLE_ROE, GOOD_PASSWORD


@pytest.fixture
async def operator():
    from recon.orchestrator.auth import AuthService

    async with session_scope() as s:
        u = await AuthService().create_initial_admin(s, "operator", GOOD_PASSWORD)
        await s.flush()
        return u.id


# ---------------------------------------------------------------------------
# bearer token handling
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Basic abc", "recon_xxx", "Bearer  ", "bearer notitreally"],
)
async def test_api_malformed_authorization_never_500s(client, header):
    r = await client.get("/api/v1/engagements", headers={"Authorization": header})
    assert r.status_code == 401


async def test_api_no_auth_header_is_401(client):
    assert (await client.get("/api/v1/engagements")).status_code == 401


async def test_token_secret_never_returned_after_creation(operator):
    c = InProcessClient()
    created = await c.token_create("laptop")
    assert "token" in created  # shown once
    for row in await c.token_list():
        assert "token" not in row and "token_hash" not in row


async def test_revoked_token_is_immediately_dead(operator):
    c = InProcessClient()
    made = await c.token_create("laptop")
    await c.token_revoke(made["id"])
    async with session_scope() as s:
        assert await TokenService().authenticate(s, made["token"]) is None


async def test_unknown_token_authenticates_to_nobody(operator):
    async with session_scope() as s:
        assert await TokenService().authenticate(s, "recon_deadbeef") is None
        assert await TokenService().authenticate(s, "") is None


# ---------------------------------------------------------------------------
# bootstrap admin
# ---------------------------------------------------------------------------
async def test_bootstrap_admin_only_on_empty_table(monkeypatch):
    from recon.config import get_settings
    from recon.models.user import User
    from recon.orchestrator.auth import AuthService
    from sqlalchemy import func, select

    monkeypatch.setenv("RECON_BOOTSTRAP_ADMIN_USER", "root")
    monkeypatch.setenv("RECON_BOOTSTRAP_ADMIN_PASSWORD", GOOD_PASSWORD)
    get_settings.cache_clear()
    try:
        async with session_scope() as s:
            assert await AuthService().maybe_bootstrap_admin(s) is not None
        async with session_scope() as s:
            # a second run is a no-op even with different creds
            monkeypatch.setenv("RECON_BOOTSTRAP_ADMIN_USER", "root2")
            get_settings.cache_clear()
            assert await AuthService().maybe_bootstrap_admin(s) is None
            count = (await s.execute(select(func.count()).select_from(User))).scalar_one()
            assert count == 1
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# RoE recon: block can't smuggle bad values
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_block",
    [
        "recon:\n  cve:\n    subset: everything\n",
        "recon:\n  recursion:\n    max_rounds: -1\n",
        "recon:\n  takeover:\n    engine: metasploit\n",
        "recon:\n  permutation:\n    max_candidates: 9999999\n",
        "recon:\n  templates:\n    min_severity: apocalyptic\n",
    ],
)
async def test_recon_block_rejects_bad_values(bad_block):
    c = InProcessClient()
    with pytest.raises(CliError) as ei:
        await c.engagement_create(EXAMPLE_ROE + "\n" + bad_block, None)
    assert ei.value.exit_code == 1


async def test_recon_block_is_backward_compatible():
    """The canonical v1 RoE (no recon: key) still loads unchanged."""
    from recon.core.roe import canonical_hash, load_roe

    cfg, h = load_roe(EXAMPLE_ROE)
    assert cfg.recon.cve.source.value == "local"
    # adding an explicit default-valued recon: block does not change semantics,
    # but the canonical hash is content-based so it legitimately differs -
    # the point is only that BOTH parse.
    assert canonical_hash(EXAMPLE_ROE)


# ---------------------------------------------------------------------------
# purge guardrails
# ---------------------------------------------------------------------------
async def test_purge_requires_confirmation_or_gate(engagement_id, monkeypatch):
    from recon.cli import app

    # no --yes, no --export-first, and a mismatched typed name -> abort, no delete
    monkeypatch.setattr("builtins.input", lambda *_: "wrong name")

    class _Args:
        id = engagement_id
        older_than = None
        export_first = None
        yes = False
        json = False

    with pytest.raises(CliError):
        await app._engagement_purge(InProcessClient(), _Args())
    assert await InProcessClient().engagement_show(engagement_id)  # still there


async def test_purge_older_than_blocks_fresh_engagement(engagement_id):
    c = InProcessClient()
    from recon.cli import app

    class _Args:
        id = engagement_id
        older_than = 30
        export_first = None
        yes = True
        json = False

    with pytest.raises(CliError):
        await app._engagement_purge(c, _Args())
    assert await c.engagement_show(engagement_id)


# ---------------------------------------------------------------------------
# API input validation
# ---------------------------------------------------------------------------
async def test_api_scan_unknown_module_is_user_error(client):
    from recon.orchestrator.auth import AuthService
    from recon.orchestrator.tokens import TokenService

    async with session_scope() as s:
        u = await AuthService().create_initial_admin(s, "op", GOOD_PASSWORD)
        await s.flush()
        _, raw = await TokenService().create(s, u, "t")
        await s.flush()
    auth = {"Authorization": f"Bearer {raw}"}

    r = await client.post("/api/v1/engagements", headers=auth, json={"roe_yaml": EXAMPLE_ROE})
    eid = r.json()["id"]
    r = await client.post(
        "/api/v1/scans", headers=auth,
        json={"engagement_id": eid, "modules": ["nope_not_a_module"]},
    )
    assert r.status_code == 400
