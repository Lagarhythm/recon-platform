"""`recon` CLI - in-process transport (PRD Section 12).

Exercises the command layer through ``InProcessClient`` (the real orchestrator
path) plus a few end-to-end ``recon.__main__.main`` invocations for arg parsing
and the exit-code contract.
"""

from __future__ import annotations

import json

import pytest

from recon.cli.client import InProcessClient
from recon.cli.output import (
    EXIT_MODULE_FAILURES,
    EXIT_OK,
    EXIT_USER_ERROR,
    CliError,
)
from recon.db import session_scope
from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES
from recon.orchestrator.killswitch import kill_switch
from recon.orchestrator.scans import scan_service
from tests.conftest import EXAMPLE_ROE, GOOD_PASSWORD, wait_for

RECON_BLOCK_ROE = EXAMPLE_ROE + """
recon:
  passive_sources:
    disable: ["hackertarget", "HackerTarget"]
  recursion:
    max_rounds: 3
  git_secrets:
    verify: true
  cve:
    subset: full
  screenshots:
    enabled: false
"""


@pytest.fixture
def roe_file(tmp_path):
    def _write(text: str = EXAMPLE_ROE) -> str:
        p = tmp_path / "roe.yaml"
        p.write_text(text)
        return str(p)

    return _write


@pytest.fixture
async def operator():
    from recon.orchestrator.auth import AuthService

    async with session_scope() as s:
        user = await AuthService().create_initial_admin(s, "operator", GOOD_PASSWORD)
        await s.flush()
        return user.id


# ---------------------------------------------------------------------------
# engagement
# ---------------------------------------------------------------------------
async def test_engagement_create_list_show_archive(roe_file):
    c = InProcessClient()
    created = await c.engagement_create(open(roe_file()).read(), None)
    assert created["name"] == "Test Engagement"
    assert created["status"] == "active"
    eid = created["id"]

    listed = await c.engagement_list()
    assert [e["id"] for e in listed] == [eid]

    shown = await c.engagement_show(eid)
    assert shown["assets"] == 0 and shown["recent_runs"] == []

    archived = await c.engagement_set_status(eid, "archived")
    assert archived["status"] == "archived"
    assert await c.engagement_list(include_archived=False) == []


async def test_engagement_create_name_override(roe_file):
    c = InProcessClient()
    created = await c.engagement_create(open(roe_file()).read(), "Renamed")
    assert created["name"] == "Renamed"
    # the RoE hash is unchanged - the override is display-only
    plain = await c.engagement_create(open(roe_file()).read(), None)
    assert created["roe_hash"] == plain["roe_hash"]


async def test_engagement_create_rejects_bad_roe(roe_file):
    c = InProcessClient()
    with pytest.raises(CliError) as ei:
        await c.engagement_create("engagement: {name: x}", None)
    assert ei.value.exit_code == EXIT_USER_ERROR


async def test_engagement_show_not_found():
    with pytest.raises(CliError):
        await InProcessClient().engagement_show("does-not-exist")


async def test_recon_block_parses_and_v1_roe_still_loads(roe_file):
    c = InProcessClient()
    # v1 RoE (no recon: key) loads with defaults
    v1 = await c.engagement_create(open(roe_file()).read(), None)
    from recon.core.roe import RoEConfig
    from recon.db import session_scope as ss
    from recon.models.engagement import Engagement

    async with ss() as s:
        e = await s.get(Engagement, v1["id"])
        cfg = RoEConfig.model_validate(e.roe_config)
    assert cfg.recon.cve.subset.value == "kev_high"
    assert cfg.recon.screenshots.enabled is True

    # a recon: block is parsed, normalised, and round-trips
    v2 = await c.engagement_create(open(roe_file(RECON_BLOCK_ROE)).read(), None)
    async with ss() as s:
        e = await s.get(Engagement, v2["id"])
        cfg = RoEConfig.model_validate(e.roe_config)
    assert cfg.recon.passive_sources.disable == ["hackertarget"]  # deduped + lowercased
    assert cfg.recon.recursion.max_rounds == 3
    assert cfg.recon.git_secrets.verify is True
    assert cfg.recon.cve.subset.value == "full"
    assert cfg.recon.screenshots.enabled is False


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------
async def test_token_lifecycle_and_auth(operator):
    c = InProcessClient()
    made = await c.token_create("laptop")
    raw = made["token"]
    assert raw.startswith("recon_")

    rows = await c.token_list()
    assert rows[0]["name"] == "laptop" and rows[0]["revoked"] is False

    from recon.orchestrator.tokens import TokenService

    async with session_scope() as s:
        user = await TokenService().authenticate(s, raw)
        assert user is not None and user.id == operator

    await c.token_revoke(made["id"])
    async with session_scope() as s:
        assert await TokenService().authenticate(s, raw) is None


async def test_token_owner_isolation(operator):
    """A token belongs to its creator; another user cannot revoke it."""
    from recon.models.user import User
    from recon.orchestrator.tokens import TokenNotFound, TokenService

    async with session_scope() as s:
        other = User(username="intruder", password_hash="x")
        s.add(other)
        await s.flush()
        token, _ = await TokenService().create(s, await s.get(User, operator), "victim")
        await s.flush()
        with pytest.raises(TokenNotFound):
            await TokenService().revoke(s, other, token.id)


async def test_token_create_requires_operator():
    # no operator account, no bootstrap vars
    with pytest.raises(CliError) as ei:
        await InProcessClient().token_create("x")
    assert ei.value.exit_code == 3


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
class _CliFakePassive(ReconModule):
    name = "cli_fake_ok"
    phase = ModulePhase.PASSIVE
    description = "cli test passive"

    async def run(self, ctx: ModuleContext) -> None:
        await ctx.add_evidence(
            subject_type="subdomain", subject_value="cli.example.com", raw_data={}
        )


class _CliFakeFail(ReconModule):
    name = "cli_fake_fail"
    phase = ModulePhase.PASSIVE
    description = "cli test failing"

    async def run(self, ctx: ModuleContext) -> None:
        raise RuntimeError("boom")


@pytest.fixture(autouse=True)
def _fakes():
    for cls in (_CliFakePassive, _CliFakeFail):
        MODULES[cls.name] = cls()
    yield
    for cls in (_CliFakePassive, _CliFakeFail):
        MODULES.pop(cls.name, None)


@pytest.fixture(autouse=True)
async def _cleanup_scans():
    yield
    kill_switch.reset()
    await scan_service.shutdown()
    scan_service._handles.clear()


async def test_scan_start_wait_and_status(engagement_id):
    c = InProcessClient()
    started = await c.scan_start(
        engagement_id, ["cli_fake_ok"], allow_out_of_scope=False, yes_active=False
    )
    run_id = started["id"]
    events = [e async for e in c.scan_stream(run_id)]
    assert any(e["type"] == "scan_completed" for e in events)
    status = await c.scan_status(run_id)
    assert status["status"] == "completed"
    assert status["modules"][0]["status"] == "completed"


async def test_scan_start_without_wait_blocks_in_process(engagement_id):
    """In-process has no daemon: `scan start` (no --wait) must still drive the
    run to completion before returning, or the task dies with the event loop."""
    from recon.cli import app

    class _Args:
        engagement = engagement_id
        modules = "cli_fake_ok"
        all = all_passive = False
        allow_out_of_scope = yes_active = wait = json = False
        server = token = None

    rc = await app._scan_start(InProcessClient(), _Args())
    assert rc == EXIT_OK
    runs = await InProcessClient().scan_list(engagement_id)
    assert runs and runs[0]["status"] == "completed"


async def test_scan_list_and_module_failure_exit_code(engagement_id):
    c = InProcessClient()
    started = await c.scan_start(
        engagement_id, ["cli_fake_ok", "cli_fake_fail"],
        allow_out_of_scope=False, yes_active=False,
    )
    run_id = started["id"]
    await wait_for(lambda: _run_done(run_id))
    status = await c.scan_status(run_id)
    from recon.cli.app import _scan_exit_code

    assert _scan_exit_code(status) == EXIT_MODULE_FAILURES

    runs = await c.scan_list(engagement_id)
    assert run_id in [r["id"] for r in runs]


async def _run_done(run_id) -> bool:
    from recon.models.enums import ScanRunStatus
    from recon.models.scanrun import ScanRun

    async with session_scope() as s:
        run = await s.get(ScanRun, run_id)
        return run is not None and run.status in (
            ScanRunStatus.COMPLETED, ScanRunStatus.FAILED, ScanRunStatus.AWAITING_CHECKPOINT
        )


# ---------------------------------------------------------------------------
# report / diff / cve
# ---------------------------------------------------------------------------
async def test_report_formats(engagement_id):
    c = InProcessClient()
    js = await c.report(engagement_id, "json", redacted=False)
    assert json.loads(js)["engagement"]["name"] == "Test Engagement"
    csv_blob = await c.report(engagement_id, "csv", redacted=False)
    assert csv_blob.startswith(b"type,value,confidence")
    with pytest.raises(CliError):
        await c.report(engagement_id, "xml", redacted=False)


async def test_diff_needs_two_snapshots(engagement_id):
    out = await InProcessClient().diff(engagement_id, None)
    assert out["snapshots"] == 0 and out["added"] == []


async def test_cve_is_wave2(engagement_id):
    c = InProcessClient()
    assert (await c.cve_status())["available"] is False
    with pytest.raises(CliError):
        await c.cve_refresh(None)


# ---------------------------------------------------------------------------
# __main__ integration (sync - arg parsing + exit codes)
# ---------------------------------------------------------------------------
def test_main_version(capsys):
    from recon.__main__ import main

    assert main(["version"]) == EXIT_OK


def test_main_unknown_engagement_exit_code(capsys):
    from recon.__main__ import main

    rc = main(["engagement", "show", "nope", "--json"])
    assert rc == EXIT_USER_ERROR


def test_main_engagement_list_json(capsys):
    from recon.__main__ import main

    assert main(["engagement", "list", "--json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out) == []
