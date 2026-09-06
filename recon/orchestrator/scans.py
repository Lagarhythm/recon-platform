"""Scan orchestration: passive-first sequencing, the pre-active checkpoint,
module-level resumability, kill-switch cooperation, and correlation triggering.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from recon.correlation.engine import CorrelationEngine
from recon.core.roe import RoEConfig
from recon.core.scope import ScopeManager
from recon.db import session_scope
from recon.models.base import utcnow
from recon.models.engagement import Engagement
from recon.models.enums import (
    ModulePhase,
    ModuleRunStatus,
    ScanRunStatus,
    SkipReason,
)
from recon.models.scanrun import ScanModuleRun, ScanRun
from recon.modules.base import (
    ModuleContext,
    ModuleTimeout,
    ReconModule,
    ScanCancelled,
)
from recon.modules.registry import load_builtin_modules, resolve_order
from recon.net.http_client import ReconHTTPClient
from recon.net.rate_limit import RateLimiter
from recon.orchestrator.events import event_bus
from recon.orchestrator.killswitch import kill_switch

# Wall-clock ceilings for a single module run. A module can raise its own via
# ``max_runtime_seconds`` (active modules that shell out to nmap/ffuf do, since
# they manage a longer subprocess timeout themselves).
_OSINT_MODULE_TIMEOUT = 12 * 60
_PASSIVE_MODULE_TIMEOUT = 15 * 60
_ACTIVE_MODULE_TIMEOUT = 60 * 60


def _module_timeout(mod: ReconModule) -> float:
    if mod.max_runtime_seconds is not None:
        return float(mod.max_runtime_seconds)
    if mod.phase is ModulePhase.ACTIVE:
        return _ACTIVE_MODULE_TIMEOUT
    if mod.phase is ModulePhase.OSINT:
        return _OSINT_MODULE_TIMEOUT
    return _PASSIVE_MODULE_TIMEOUT


class ScanError(Exception):
    pass


@dataclass
class _RunHandle:
    task: asyncio.Task | None = None
    cancel: asyncio.Event = field(default_factory=asyncio.Event)


class ScanService:
    def __init__(self) -> None:
        self._handles: dict[str, _RunHandle] = {}
        self._correlation = CorrelationEngine()
        load_builtin_modules()

    # --- public API ------------------------------------------------
    async def available_modules(self) -> list[ReconModule]:
        from recon.modules.registry import iter_modules

        return sorted(iter_modules(), key=lambda m: (m.phase.value, m.name))

    async def start_scan(
        self,
        session: AsyncSession,
        engagement: Engagement,
        module_names: Sequence[str],
        *,
        allow_out_of_scope: bool = False,
    ) -> ScanRun:
        if not module_names:
            raise ScanError("select at least one module")
        if kill_switch.is_engaged:
            raise ScanError("global kill switch is engaged - clear it first")

        try:
            ordered = resolve_order(module_names)
        except (KeyError, ValueError) as exc:
            raise ScanError(str(exc)) from exc

        run = ScanRun(
            engagement_id=engagement.id,
            roe_config_snapshot=engagement.roe_config,
            roe_config_hash=engagement.roe_config_hash,
            modules_requested=[m.name for m in ordered],
            modules_completed=[],
            status=ScanRunStatus.RUNNING,
            allow_out_of_scope=allow_out_of_scope,
            started_at=utcnow(),
            current_phase=ordered[0].phase if ordered else ModulePhase.PASSIVE,
        )
        session.add(run)
        await session.flush()

        for i, mod in enumerate(ordered):
            session.add(
                ScanModuleRun(
                    scan_run_id=run.id,
                    engagement_id=engagement.id,
                    module_name=mod.name,
                    phase=mod.phase,
                    status=ModuleRunStatus.PENDING,
                    order_index=i,
                )
            )
        await session.commit()

        self._launch(run.id, allow_out_of_scope)
        return run

    async def resume_scan(self, session: AsyncSession, scan_run_id: str) -> None:
        run = await session.get(ScanRun, scan_run_id)
        if run is None:
            raise ScanError("scan run not found")
        if run.status not in (
            ScanRunStatus.AWAITING_CHECKPOINT,
            ScanRunStatus.PAUSED,
        ):
            raise ScanError(f"cannot resume a run in state {run.status.value}")
        if kill_switch.is_engaged:
            raise ScanError("global kill switch is engaged - clear it first")
        if run.status is ScanRunStatus.AWAITING_CHECKPOINT:
            run.active_confirmed = True
        run.status = ScanRunStatus.RUNNING
        run.error = None
        allow_oos = run.allow_out_of_scope
        await session.commit()
        self._launch(run.id, allow_oos)

    async def cancel_scan(self, scan_run_id: str) -> None:
        handle = self._handles.get(scan_run_id)
        if handle:
            handle.cancel.set()

    async def shutdown(self) -> None:
        for handle in list(self._handles.values()):
            handle.cancel.set()
        for handle in list(self._handles.values()):
            if handle.task:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(handle.task, timeout=10)

    @staticmethod
    async def reap_orphans() -> None:
        """On startup, a RUNNING row means the process died mid-scan. Make it
        resumable rather than leaving it stuck."""
        async with session_scope() as session:
            await session.execute(
                update(ScanRun)
                .where(ScanRun.status == ScanRunStatus.RUNNING)
                .values(status=ScanRunStatus.PAUSED, error="interrupted by a restart")
            )
            await session.execute(
                update(ScanModuleRun)
                .where(ScanModuleRun.status == ModuleRunStatus.RUNNING)
                .values(status=ModuleRunStatus.PENDING)
            )

    # --- internals -----------------------------------------------
    def _launch(self, scan_run_id: str, allow_oos: bool) -> None:
        handle = self._handles.get(scan_run_id) or _RunHandle()
        handle.cancel = asyncio.Event()
        self._handles[scan_run_id] = handle
        handle.task = asyncio.create_task(self._execute(scan_run_id, allow_oos))

    def _is_cancelled(self, scan_run_id: str) -> bool:
        handle = self._handles.get(scan_run_id)
        return bool(handle and handle.cancel.is_set()) or kill_switch.is_engaged

    async def _execute(self, scan_run_id: str, allow_oos: bool) -> None:
        try:
            await self._execute_inner(scan_run_id, allow_oos)
        except Exception:  # never let the task die silently
            tb = traceback.format_exc()
            async with session_scope() as session:
                run = await session.get(ScanRun, scan_run_id)
                if run and run.status is ScanRunStatus.RUNNING:
                    run.status = ScanRunStatus.FAILED
                    run.error = tb[-4000:]
                    run.completed_at = utcnow()
            await event_bus.publish(scan_run_id, "scan_failed", error=tb[-2000:])
        finally:
            self._handles.pop(scan_run_id, None)

    async def _execute_inner(self, scan_run_id: str, allow_oos: bool) -> None:
        async with session_scope() as session:
            run = await session.get(ScanRun, scan_run_id)
            engagement = await session.get(Engagement, run.engagement_id)
            roe = RoEConfig.model_validate(engagement.roe_config)
            engagement_id = engagement.id
            roe_hash = engagement.roe_config_hash
            ordered = resolve_order(run.modules_requested)
            completed = set(run.modules_completed or [])

        scope = ScopeManager(roe)
        # One shared token bucket per scan run: every module's HTTP traffic and
        # its audited DNS actions draw from the same bucket, so concurrent
        # activity on one engagement never spends the RoE budget twice.
        rate_limiter = RateLimiter(roe.rate_limits.max_requests_per_second)
        http = ReconHTTPClient(
            roe=roe,
            scope=scope,
            engagement_id=engagement_id,
            roe_config_hash=roe_hash,
            scan_run_id=scan_run_id,
            allow_out_of_scope=allow_oos,
            rate_limiter=rate_limiter,
        )
        await event_bus.publish(scan_run_id, "scan_started", modules=[m.name for m in ordered])

        try:
            for mod in ordered:
                if self._is_cancelled(scan_run_id):
                    await self._pause(scan_run_id, "cancelled or kill switch engaged")
                    return

                if mod.name in completed:
                    # Already done. If it ran in THIS run (passive phase before
                    # the checkpoint), leave its COMPLETED/FAILED row and its
                    # real duration alone - only a module carried over from an
                    # earlier scan run is genuinely "skipped".
                    was_skipped = await self._skip_if_pending(scan_run_id, mod.name)
                    if was_skipped:
                        await event_bus.publish(
                            scan_run_id, "module_skipped", module=mod.name
                        )
                    continue

                # passive-first checkpoint
                if mod.phase is ModulePhase.ACTIVE and not await self._active_ok(scan_run_id):
                    await self._correlate(scan_run_id, engagement_id)
                    await self._await_checkpoint(scan_run_id)
                    return

                try:
                    await self._run_one_module(
                        scan_run_id, mod, roe, scope, http, engagement_id, allow_oos,
                        rate_limiter=rate_limiter,
                    )
                except ScanCancelled:
                    return  # _pause already recorded the state
                if not self._is_cancelled(scan_run_id):
                    completed.add(mod.name)

            await self._correlate(scan_run_id, engagement_id)
            await self._finish(scan_run_id)
        finally:
            await http.aclose()

    async def _run_one_module(
        self, scan_run_id, mod, roe, scope, http, engagement_id, allow_oos=False,
        *, rate_limiter: RateLimiter | None = None,
    ) -> None:  # noqa: ANN001
        await self._set_module_status(
            scan_run_id, mod.name, ModuleRunStatus.RUNNING, set_started=True
        )
        started_at = utcnow()
        timeout_s = _module_timeout(mod)
        await event_bus.publish(
            scan_run_id, "module_started", module=mod.name, phase=mod.phase.value,
            started_at=started_at.isoformat(),
        )

        def _duration() -> float:
            return round((utcnow() - started_at).total_seconds(), 1)

        async with session_scope() as session:
            eng = await session.get(Engagement, engagement_id)
            module_run = (
                await session.execute(
                    select(ScanModuleRun).where(
                        ScanModuleRun.scan_run_id == scan_run_id,
                        ScanModuleRun.module_name == mod.name,
                    )
                )
            ).scalar_one()
            http.module_name = mod.name
            ctx = ModuleContext(
                engagement=eng,
                roe=roe,
                scope=scope,
                scan_run_id=scan_run_id,
                module_name=mod.name,
                module_run=module_run,
                session=session,
                http=http,
                emit_event=lambda etype, **d: event_bus.publish(scan_run_id, etype, **d),
                is_cancelled=lambda: self._is_cancelled(scan_run_id),
                allow_out_of_scope=allow_oos,
                deadline=time.monotonic() + timeout_s,
                rate_limiter=rate_limiter,
            )
            http.audit_context = ctx  # audit rows share the module's session
            try:
                # check_alive() enforces the deadline cooperatively; wait_for is
                # the hard backstop for a module wedged on a single long await
                # that never reaches a check_alive() call.
                hard_timeout = timeout_s + max(15.0, 0.2 * timeout_s)
                await asyncio.wait_for(mod.run(ctx), timeout=hard_timeout)
                await ctx.flush()
                # Modules can persist an explicit skipped/no-target outcome.
                # Do not overwrite it with COMPLETED: doing so falsely turns
                # intentionally disabled coverage into a clean empty result.
                if module_run.status is ModuleRunStatus.RUNNING:
                    module_run.status = ModuleRunStatus.COMPLETED
                module_run.completed_at = utcnow()
                await session.commit()
                await self._append_completed(scan_run_id, mod.name)
                accounting = (module_run.coverage_metadata or {}).get("target_accounting")
                await event_bus.publish(
                    scan_run_id, "module_skipped" if module_run.status is ModuleRunStatus.SKIPPED else "module_completed", module=mod.name,
                    evidence=module_run.evidence_count, errors=module_run.error_count,
                    duration=_duration(),
                    skip_reason=(
                        module_run.skip_reason.value
                        if module_run.skip_reason is not None else None
                    ),
                    targets=(accounting or {}).get("eligible"),
                    target_sources=(accounting or {}).get("by_source"),
                )
            except ScanCancelled:
                await ctx.flush()
                module_run.status = ModuleRunStatus.PENDING
                await session.commit()
                await self._pause(scan_run_id, "cancelled during module run")
                raise
            except (ModuleTimeout, asyncio.TimeoutError):
                # A hard wait_for cancel can land mid-write and leave the shared
                # session unusable - persist the FAILED state on a clean one and
                # roll this session back so session_scope's exit commit is a
                # no-op (a raise there would fail the whole run).
                msg = f"timed out after {timeout_s:.0f}s (partial results kept)"
                with contextlib.suppress(Exception):
                    await ctx.flush()
                with contextlib.suppress(Exception):
                    await session.rollback()
                await self._force_module_failed(scan_run_id, mod.name, msg)
                await event_bus.publish(
                    scan_run_id, "module_failed", module=mod.name, error=msg,
                    duration=_duration(),
                )
            except Exception as exc:  # module failed; run continues (resilience NFR)
                with contextlib.suppress(Exception):
                    await ctx.flush()
                module_run.status = ModuleRunStatus.FAILED
                module_run.completed_at = utcnow()
                module_run.error = f"{type(exc).__name__}: {exc}"[:4000]
                await session.commit()
                await event_bus.publish(
                    scan_run_id, "module_failed", module=mod.name, error=str(exc),
                    duration=_duration(),
                )
            finally:
                http.audit_context = None

    # --- state helpers ----------------------------------------
    async def _active_ok(self, scan_run_id: str) -> bool:
        async with session_scope() as session:
            run = await session.get(ScanRun, scan_run_id)
            return bool(run and run.active_confirmed)

    async def _await_checkpoint(self, scan_run_id: str) -> None:
        async with session_scope() as session:
            run = await session.get(ScanRun, scan_run_id)
            run.status = ScanRunStatus.AWAITING_CHECKPOINT
            run.current_phase = ModulePhase.ACTIVE
        await event_bus.publish(scan_run_id, "checkpoint_reached")

    async def _pause(self, scan_run_id: str, reason: str) -> None:
        async with session_scope() as session:
            run = await session.get(ScanRun, scan_run_id)
            if run and run.status is ScanRunStatus.RUNNING:
                run.status = ScanRunStatus.PAUSED
                run.error = reason
        await event_bus.publish(scan_run_id, "scan_paused", reason=reason)

    async def _finish(self, scan_run_id: str) -> None:
        async with session_scope() as session:
            run = await session.get(ScanRun, scan_run_id)
            run.status = ScanRunStatus.COMPLETED
            run.completed_at = utcnow()
            run.current_phase = None
        await event_bus.publish(scan_run_id, "scan_completed")

    async def _correlate(self, scan_run_id: str, engagement_id: str) -> None:
        await event_bus.publish(scan_run_id, "correlation_started")
        async with session_scope() as session:
            engagement = await session.get(Engagement, engagement_id)
            summary = await self._correlation.correlate(session, engagement)
        await event_bus.publish(
            scan_run_id, "correlation_completed",
            assets_created=summary.assets_created,
            assets_updated=summary.assets_updated,
            relationships=summary.relationships_created,
            by_type=summary.by_type,
        )

    async def _set_module_status(
        self, scan_run_id, module_name, status, *, set_started=False
    ) -> None:  # noqa: ANN001
        async with session_scope() as session:
            row = (
                await session.execute(
                    select(ScanModuleRun).where(
                        ScanModuleRun.scan_run_id == scan_run_id,
                        ScanModuleRun.module_name == module_name,
                    )
                )
            ).scalar_one()
            row.status = status
            if set_started:
                row.started_at = utcnow()

    async def _force_module_failed(
        self, scan_run_id: str, module_name: str, error: str
    ) -> None:
        """Mark a module FAILED on a fresh session. Used after a hard timeout,
        where the module's own session may have been left unusable by the
        cancellation."""
        with contextlib.suppress(Exception):
            async with session_scope() as session:
                row = (
                    await session.execute(
                        select(ScanModuleRun).where(
                            ScanModuleRun.scan_run_id == scan_run_id,
                            ScanModuleRun.module_name == module_name,
                        )
                    )
                ).scalar_one()
                if row.status is not ModuleRunStatus.COMPLETED:
                    row.status = ModuleRunStatus.FAILED
                    row.completed_at = utcnow()
                    row.error = error

    async def _skip_if_pending(self, scan_run_id: str, module_name: str) -> bool:
        """Mark a module SKIPPED only if it hasn't already run. Returns whether
        it was actually skipped (vs. left COMPLETED/FAILED from this run)."""
        async with session_scope() as session:
            row = (
                await session.execute(
                    select(ScanModuleRun).where(
                        ScanModuleRun.scan_run_id == scan_run_id,
                        ScanModuleRun.module_name == module_name,
                    )
                )
            ).scalar_one()
            if row.status in (ModuleRunStatus.COMPLETED, ModuleRunStatus.FAILED):
                return False
            row.status = ModuleRunStatus.SKIPPED
            # A benign carry-over from an earlier scan run - explicitly distinct
            # from a "module had no input" SKIPPED so the release gate can tell
            # them apart.
            row.skip_reason = SkipReason.RESUMED_PRIOR_RUN
            return True

    async def _append_completed(self, scan_run_id: str, module_name: str) -> None:
        async with session_scope() as session:
            run = await session.get(ScanRun, scan_run_id)
            done = list(run.modules_completed or [])
            if module_name not in done:
                done.append(module_name)
                run.modules_completed = done


scan_service = ScanService()
