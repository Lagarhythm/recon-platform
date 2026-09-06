"""The single choke point through which an active probe reaches the network
(P0-1 / G0 Part 3, "the executor boundary").

``ActiveExecutor.run`` accepts **only** an :class:`~recon.net.permit.ActiveTargetPermit`.
There is deliberately no ``run(host: str)`` and no public method that takes a
target string - an active module holds an ``ActiveExecutor`` and can do nothing
with it except hand back a permit the resolver minted.

Before any traffic, every call:

1. confirms the argument is a genuine, minted permit (fails closed);
2. confirms the permit is not expired and its ``dispatch_nonce`` is unused;
3. runs the injected dispatch-time re-verification (``predispatch_check``) -
   snapshot still active, authorization row unchanged, kill switch clear, not
   cancelled, destination still in scope, policy version current;
4. acquires a rate-limiter token.

Only then is the probe built - from ``permit.destination_ip`` (a canonical IP),
never from a name - and executed. For a socket probe the actual
``getpeername()`` peer address must equal ``permit.destination_ip`` or the
result is discarded as a redirect / DNS-rebind attempt.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from recon.core.active_policy import active_policy
from recon.core.netscope import NetscopeError, canonical_ip
from recon.net.external import CommandResult, run_command
from recon.net.permit import ActiveTargetPermit, PermitError, is_genuine_permit

# Literal token in ``effective_argv_shape`` that the executor replaces with the
# permit's destination IP. Anything else in the shape is passed through verbatim.
DESTINATION_TOKEN = "__DESTINATION__"

CommandRunner = Callable[..., Awaitable[CommandResult]]


@dataclass(frozen=True)
class ProbeResult:
    permit_id: str
    operation: str
    method_profile_id: str
    destination_ip: str
    dispatched: bool
    """True iff a packet was actually sent."""
    outcome: str
    """``completed`` | ``no_response`` | ``refused`` | ``timeout`` | ``error``."""
    detail: str
    peer_ip: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    raw: dict[str, str] = field(default_factory=dict)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ActiveExecutor:
    def __init__(
        self,
        *,
        rate_limiter,
        kill_switch,
        is_cancelled: Callable[[], bool | Awaitable[bool]],
        predispatch_check: Callable[[ActiveTargetPermit], Awaitable[None]],
        command_runner: CommandRunner = run_command,
    ) -> None:
        self._rate_limiter = rate_limiter
        self._kill_switch = kill_switch
        self._is_cancelled = is_cancelled
        self._predispatch_check = predispatch_check
        self._command_runner = command_runner
        self._consumed_nonces: set[str] = set()

    async def run(self, permit: object) -> ProbeResult:
        # 1. genuine, minted permit - fail closed on anything else.
        if not is_genuine_permit(permit):
            raise PermitError(
                f"ActiveExecutor.run requires a minted ActiveTargetPermit, got "
                f"{type(permit).__name__}"
            )
        assert isinstance(permit, ActiveTargetPermit)  # narrows for type-checkers

        # 2. not expired, nonce not already spent.
        if permit.is_expired:
            raise PermitError(f"permit {permit.permit_id} has expired")
        if permit.dispatch_nonce in self._consumed_nonces:
            raise PermitError(
                f"permit {permit.permit_id} dispatch_nonce already consumed "
                "(single-use)"
            )

        # destination must still canonicalise to itself - defence in depth
        # against a permit whose IP was somehow tampered with in transit.
        try:
            if canonical_ip(permit.destination_ip) != permit.destination_ip:
                raise PermitError(
                    f"permit destination {permit.destination_ip!r} is not canonical"
                )
        except NetscopeError as exc:
            raise PermitError(f"permit destination is not a valid IP: {exc}") from exc

        # 3. dispatch-time re-verification. Any failure -> PermitError, no traffic.
        await self._predispatch_check(permit)
        if await _maybe_await(self._is_cancelled()):
            raise PermitError(f"run cancelled before dispatch of {permit.permit_id}")
        if getattr(self._kill_switch, "is_engaged", False):
            raise PermitError("global kill switch engaged; no dispatch")

        # Consume the nonce now: a failure past this point still burns the permit.
        self._consumed_nonces.add(permit.dispatch_nonce)

        # 4. rate limit.
        await self._rate_limiter.acquire()

        policy = active_policy(permit.policy_version)
        started = _utcnow()
        try:
            if permit.operation == "dns_connect_bind":
                result = await self._connect_bind(permit, policy, started)
            else:
                result = await self._subprocess_probe(permit, policy, started)
        except PermitError:
            raise
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            return ProbeResult(
                permit_id=permit.permit_id,
                operation=permit.operation,
                method_profile_id=permit.method_profile_id,
                destination_ip=permit.destination_ip,
                dispatched=True,
                outcome="error",
                detail=f"{type(exc).__name__}: {exc}",
                started_at=started,
                ended_at=_utcnow(),
            )
        return result

    async def _connect_bind(
        self, permit: ActiveTargetPermit, policy, started: datetime
    ) -> ProbeResult:
        ports = policy.ports_for(permit.method_profile_id)
        if len(ports) != 1:
            raise PermitError(
                f"dns_connect_bind requires exactly one approved port, policy "
                f"{policy.version} has {ports!r}"
            )
        port = ports[0]
        writer = None
        try:
            reader_writer = await asyncio.wait_for(
                asyncio.open_connection(permit.destination_ip, port),
                timeout=policy.probe_timeout_seconds,
            )
            _, writer = reader_writer
            peer = writer.get_extra_info("peername")
            peer_ip = peer[0] if peer else None
            # 7. DNS-rebind / redirect defence: the socket's real peer must be
            #    exactly the permitted IP.
            if peer_ip != permit.destination_ip:
                raise PermitError(
                    f"connected peer {peer_ip!r} != permitted "
                    f"{permit.destination_ip!r}; discarding as redirect/rebind"
                )
            return ProbeResult(
                permit_id=permit.permit_id,
                operation=permit.operation,
                method_profile_id=permit.method_profile_id,
                destination_ip=permit.destination_ip,
                dispatched=True,
                outcome="completed",
                detail=f"tcp connect to {permit.destination_ip}:{port} established",
                peer_ip=peer_ip,
                started_at=started,
                ended_at=_utcnow(),
            )
        except TimeoutError:
            return self._probe_miss(permit, started, "timeout", f"connect timeout on :{port}")
        except ConnectionRefusedError:
            return self._probe_miss(permit, started, "refused", f"connection refused on :{port}")
        except OSError as exc:
            return self._probe_miss(permit, started, "no_response", f"{type(exc).__name__}: {exc}")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (TimeoutError, OSError):
                    pass

    def _probe_miss(
        self, permit: ActiveTargetPermit, started: datetime, outcome: str, detail: str
    ) -> ProbeResult:
        return ProbeResult(
            permit_id=permit.permit_id,
            operation=permit.operation,
            method_profile_id=permit.method_profile_id,
            destination_ip=permit.destination_ip,
            dispatched=True,
            outcome=outcome,
            detail=detail,
            started_at=started,
            ended_at=_utcnow(),
        )

    async def _subprocess_probe(
        self, permit: ActiveTargetPermit, policy, started: datetime
    ) -> ProbeResult:
        argv = self._build_argv(permit)
        result = await self._command_runner(
            argv, timeout=policy.probe_timeout_seconds
        )
        outcome = "completed" if not result.timed_out else "timeout"
        return ProbeResult(
            permit_id=permit.permit_id,
            operation=permit.operation,
            method_profile_id=permit.method_profile_id,
            destination_ip=permit.destination_ip,
            dispatched=True,
            outcome=outcome,
            detail=f"exit={result.returncode} timed_out={result.timed_out}",
            started_at=started,
            ended_at=_utcnow(),
            raw={"stdout": result.stdout, "stderr": result.stderr},
        )

    def _build_argv(self, permit: ActiveTargetPermit) -> list[str]:
        shape = permit.effective_argv_shape
        if not shape:
            raise PermitError("permit has an empty effective_argv_shape")
        if DESTINATION_TOKEN in shape:
            return [
                permit.destination_ip if part == DESTINATION_TOKEN else part
                for part in shape
            ]
        # No explicit slot -> destination is the final positional arg.
        return [*shape, permit.destination_ip]


async def _maybe_await(value):
    if asyncio.iscoroutine(value) or isinstance(value, asyncio.Future):
        return await value
    return value


# re-export for callers building a shape
__all__ = ["DESTINATION_TOKEN", "ActiveExecutor", "ProbeResult"]
