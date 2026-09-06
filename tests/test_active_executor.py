"""ActiveExecutor is the only path to the network and it fails closed
(G0 Part 3, "the executor boundary")."""

from __future__ import annotations

import asyncio
import socket
import time

import pytest
import pytest_asyncio

from recon.core import active_policy as active_policy_mod
from recon.core.active_policy import ActiveScanPolicy
from recon.net.active_executor import DESTINATION_TOKEN, ActiveExecutor
from recon.net.external import CommandResult
from recon.net.permit import PermitError, mint_permit

pytestmark = pytest.mark.asyncio


class _FakeRateLimiter:
    def __init__(self) -> None:
        self.acquired = 0

    async def acquire(self) -> None:
        self.acquired += 1


class _FakeKillSwitch:
    is_engaged = False


async def _ok_predispatch(_permit) -> None:
    return None


def _make_executor(**overrides):
    kwargs = {
        "rate_limiter": _FakeRateLimiter(),
        "kill_switch": _FakeKillSwitch(),
        "is_cancelled": lambda: False,
        "predispatch_check": _ok_predispatch,
    }
    kwargs.update(overrides)
    return ActiveExecutor(**kwargs)


def _cidr_permit(**overrides):
    base = {
        "destination_ip": "203.0.113.7",
        "operation": "host_discovery",
        "method_profile_id": "dns_connect_bind_v1",
        "effective_argv_shape": ("echo", DESTINATION_TOKEN),
        "scan_run_id": "run-1",
        "scan_module_run_id": "smr-1",
        "module_name": "host_discovery",
        "authorization_snapshot_id": "snap-1",
        "authorized_cidr_id": "cidr-1",
        "authorized_target_id": None,
        "parent_authorized_cidr": "203.0.113.0/24",
        "source_hostname": None,
        "checkpoint_ack_hash": "ack",
        "policy_version": "p1",
        "liveness_attestation_id": None,
    }
    base.update(overrides)
    return mint_permit(**base)


async def test_run_rejects_a_raw_string() -> None:
    ex = _make_executor()
    with pytest.raises(PermitError):
        await ex.run("203.0.113.7")


async def test_run_rejects_a_non_minted_lookalike() -> None:
    ex = _make_executor()

    class Fake:
        destination_ip = "203.0.113.7"
        operation = "host_discovery"
        dispatch_nonce = "x"

    with pytest.raises(PermitError):
        await ex.run(Fake())


async def test_expired_permit_is_refused_before_traffic() -> None:
    rl = _FakeRateLimiter()
    ex = _make_executor(rate_limiter=rl)
    permit = _cidr_permit(expires_at=time.monotonic() - 1)
    with pytest.raises(PermitError):
        await ex.run(permit)
    assert rl.acquired == 0


async def test_dispatch_nonce_is_single_use() -> None:
    runs = []

    async def runner(argv, **kw):
        runs.append(argv)
        return CommandResult(argv=argv, returncode=0, stdout="", stderr="")

    ex = _make_executor(command_runner=runner)
    permit = _cidr_permit()
    await ex.run(permit)
    with pytest.raises(PermitError):
        await ex.run(permit)
    assert len(runs) == 1


async def test_predispatch_failure_blocks_traffic() -> None:
    rl = _FakeRateLimiter()
    ran = []

    async def runner(argv, **kw):
        ran.append(argv)
        return CommandResult(argv=argv, returncode=0, stdout="", stderr="")

    async def deny(_permit):
        raise PermitError("snapshot revoked")

    ex = _make_executor(rate_limiter=rl, predispatch_check=deny, command_runner=runner)
    with pytest.raises(PermitError):
        await ex.run(_cidr_permit())
    assert rl.acquired == 0
    assert ran == []


async def test_cancelled_run_blocks_traffic() -> None:
    ex = _make_executor(is_cancelled=lambda: True)
    with pytest.raises(PermitError):
        await ex.run(_cidr_permit())


async def test_kill_switch_blocks_traffic() -> None:
    ks = _FakeKillSwitch()
    ks.is_engaged = True
    ex = _make_executor(kill_switch=ks)
    with pytest.raises(PermitError):
        await ex.run(_cidr_permit())


async def test_argv_is_built_from_destination_ip_only() -> None:
    seen = {}

    async def runner(argv, **kw):
        seen["argv"] = argv
        return CommandResult(argv=argv, returncode=0, stdout="", stderr="")

    ex = _make_executor(command_runner=runner)
    await ex.run(_cidr_permit(effective_argv_shape=("nmap", "-sn", DESTINATION_TOKEN)))
    assert seen["argv"] == ["nmap", "-sn", "203.0.113.7"]


async def test_non_canonical_destination_is_refused() -> None:
    # mint a permit then tamper is impossible (frozen); construct with a bad IP.
    ex = _make_executor()
    with pytest.raises(PermitError):
        await ex.run(_cidr_permit(destination_ip="203.0.113.007"))


# --- dns_connect_bind socket path -----------------------------------------


def _policy_with_port(version: str, port: int) -> ActiveScanPolicy:
    return ActiveScanPolicy(
        version=version,
        method_allowlist=frozenset({"dns_connect_bind_v1"}),
        max_addresses_per_run=16,
        max_aggregate_cidr_addresses=256,
        per_method_rate={"dns_connect_bind_v1": 2.0},
        per_method_concurrency={"dns_connect_bind_v1": 2},
        per_method_ports={"dns_connect_bind_v1": (port,)},
        probe_timeout_seconds=2.0,
        max_retries=0,
        total_time_budget_seconds=30.0,
    )


@pytest_asyncio.fixture
async def _loopback_policy(monkeypatch):
    """Register two policy versions: ``test-loopback`` points at a live loopback
    listener; ``test-dead`` points at a port with nothing on it."""

    async def _serve(reader, writer):
        writer.close()

    server = await asyncio.start_server(_serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    # grab a second port, then free it so a connect is refused
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()

    monkeypatch.setitem(
        active_policy_mod._POLICIES, "test-loopback", _policy_with_port("test-loopback", port)
    )
    monkeypatch.setitem(
        active_policy_mod._POLICIES, "test-dead", _policy_with_port("test-dead", dead_port)
    )
    yield port
    server.close()
    await server.wait_closed()


def _bind_permit(**overrides):
    base = {
        "destination_ip": "127.0.0.1",
        "operation": "dns_connect_bind",
        "method_profile_id": "dns_connect_bind_v1",
        "effective_argv_shape": (),
        "scan_run_id": "run-1",
        "scan_module_run_id": "smr-1",
        "module_name": "dns",
        "authorization_snapshot_id": "snap-1",
        "authorized_cidr_id": None,
        "authorized_target_id": "tgt-1",
        "parent_authorized_cidr": None,
        "source_hostname": "host.example.com",
        "checkpoint_ack_hash": "ack",
        "policy_version": "test-loopback",
        "liveness_attestation_id": None,
    }
    base.update(overrides)
    return mint_permit(**base)


async def test_connect_bind_completes_when_peer_matches(_loopback_policy) -> None:
    ex = _make_executor()
    result = await ex.run(_bind_permit())
    assert result.outcome == "completed"
    assert result.peer_ip == "127.0.0.1"
    assert result.dispatched is True


async def test_connect_bind_rejects_a_peer_ip_mismatch(_loopback_policy, monkeypatch) -> None:
    class _FakeWriter:
        def get_extra_info(self, _key):
            return ("198.51.100.9", 443)

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def _fake_open_connection(host, port):
        return (object(), _FakeWriter())

    monkeypatch.setattr("asyncio.open_connection", _fake_open_connection)
    ex = _make_executor()
    with pytest.raises(PermitError):
        await ex.run(_bind_permit())


async def test_connect_bind_refused_is_a_miss_not_a_bypass(_loopback_policy) -> None:
    # point at a port with no listener on loopback
    ex = _make_executor()
    permit = _bind_permit(policy_version="test-dead")
    result = await ex.run(permit)
    assert result.outcome in {"refused", "timeout", "no_response"}
    assert result.outcome != "completed"
