"""The module contract.

A module implements :class:`ReconModule` and does its work through the
:class:`ModuleContext` handed to ``run()``. The context is the only sanctioned
side-effect channel: evidence emission, audited outbound requests, progress
events, and the liveness check all go through it.
"""

from __future__ import annotations

import abc
import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.audit import audit_logger
from recon.core.roe import RoEConfig
from recon.core.scope import ScopeManager
from recon.models.artifact import Artifact
from recon.models.engagement import Engagement
from recon.models.enums import (
    FindingPolarity,
    ModulePhase,
    ModuleRunStatus,
    ScopeStatus,
    SkipReason,
)
from recon.models.evidence import Evidence
from recon.models.scanrun import ScanModuleRun
from recon.net.http_client import ReconHTTPClient
from recon.net.rate_limit import RateLimiter

ModulePhaseType = ModulePhase

EventEmitter = Callable[..., Awaitable[None]]

_COMMIT_EVERY = 25


class ScanCancelled(RuntimeError):
    """Raised inside a module when the operator cancels the run or hits the kill switch."""


class ModuleTimeout(RuntimeError):
    """Raised inside a module when it overruns its wall-clock budget. Marks the
    module FAILED (partial evidence is kept); the scan run continues."""


class ModuleContext:
    """Handed to ``ReconModule.run``. Not constructed by modules."""

    def __init__(
        self,
        *,
        engagement: Engagement,
        roe: RoEConfig,
        scope: ScopeManager,
        scan_run_id: str,
        module_name: str,
        module_run: ScanModuleRun,
        session: AsyncSession,
        http: ReconHTTPClient,
        emit_event: EventEmitter,
        is_cancelled: Callable[[], bool],
        allow_out_of_scope: bool = False,
        deadline: float | None = None,
        #: The scan-run's *shared* token bucket. Non-HTTP outbound actions (a
        #: DNS query, a raw TLS handshake) that a module rate-limits itself
        #: MUST draw from this bucket so they share the RoE budget with every
        #: HTTP request, instead of each module spending it independently.
        #: ``None`` builds a private bucket sized from the RoE (test harness);
        #: production always injects the orchestrator's single shared bucket.
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.engagement = engagement
        self.roe = roe
        self.scope = scope
        self.scan_run_id = scan_run_id
        self.module_name = module_name
        self.http = http
        #: operator opted this run in to touching flagged/excluded targets
        self.allow_out_of_scope = allow_out_of_scope
        self.rate_limiter = rate_limiter or RateLimiter(
            roe.rate_limits.max_requests_per_second
        )
        self._module_run = module_run
        self._session = session
        self._emit_event = emit_event
        self._is_cancelled = is_cancelled
        #: ``time.monotonic()`` value past which ``check_alive`` raises
        #: ``ModuleTimeout``. ``None`` = no wall-clock limit.
        self._deadline = deadline
        self._since_commit = 0
        # Serialises DB writes so a module doing concurrent work (asyncio.gather
        # over many hosts) can't corrupt the shared session.
        self._lock = asyncio.Lock()

    # --- liveness --------------------------------------------------------
    def check_alive(self) -> None:
        """Call frequently - at every request boundary and loop iteration.

        Raises ``ScanCancelled`` if the operator stopped the run, or
        ``ModuleTimeout`` if the module has overrun its wall-clock budget.
        """
        if self._is_cancelled():
            raise ScanCancelled(f"{self.module_name}: run cancelled")
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise ModuleTimeout(f"{self.module_name}: exceeded its time budget")

    # --- evidence emission ----------------------------------------------
    async def add_evidence(
        self,
        *,
        subject_type: str,
        subject_value: str,
        raw_data: dict[str, Any],
        summary: str | None = None,
        request_metadata: dict[str, Any] | None = None,
        polarity: FindingPolarity = FindingPolarity.PRESENT,
        relationships: list[dict[str, str]] | None = None,
    ) -> None:
        """Record a positive discovery (or, with ``polarity=ABSENT``, a
        recorded absence).

        ``relationships`` is an optional list of
        ``{"type": "...", "target_type": "...", "target_value": "..."}`` hints
        the Correlation Engine turns into AssetRelationship rows.
        """
        payload = dict(raw_data)
        if relationships:
            payload.setdefault("relationships", relationships)
        ev = Evidence(
            engagement_id=self.engagement.id,
            scan_run_id=self.scan_run_id,
            source_module=self.module_name,
            subject_type=subject_type,
            subject_value=subject_value[:1024],
            raw_data=payload,
            summary=summary,
            request_metadata=request_metadata,
            polarity=polarity,
        )
        async with self._lock:
            self._session.add(ev)
            self._module_run.evidence_count += 1
            await self._tick()
        await self._emit_event(
            "evidence",
            module=self.module_name,
            subject_type=subject_type,
            subject_value=subject_value,
            polarity=polarity.value,
        )

    async def add_negative(
        self,
        *,
        subject_type: str,
        subject_value: str,
        summary: str,
        raw_data: dict[str, Any] | None = None,
    ) -> None:
        """Absence of a control is itself a finding (PRD Section 7.2)."""
        await self.add_evidence(
            subject_type=subject_type,
            subject_value=subject_value,
            raw_data=raw_data or {},
            summary=summary,
            polarity=FindingPolarity.ABSENT,
        )

    async def add_error(
        self, *, subject_value: str, summary: str, raw_data: dict[str, Any] | None = None
    ) -> None:
        """A per-target failure. Logged as evidence; does not abort the run."""
        ev = Evidence(
            engagement_id=self.engagement.id,
            scan_run_id=self.scan_run_id,
            source_module=self.module_name,
            subject_type="error",
            subject_value=subject_value[:1024],
            raw_data=raw_data or {},
            summary=summary,
            is_error=True,
        )
        async with self._lock:
            self._session.add(ev)
            self._module_run.error_count += 1
            await self._tick()

    async def mark_skipped(self, reason: str) -> None:
        """Persist an intentional no-coverage outcome for report consumers."""
        async with self._lock:
            self._module_run.status = ModuleRunStatus.SKIPPED
            self._module_run.error = reason[:4000]
            await self._tick()

    async def set_coverage_metadata(self, metadata: dict[str, Any]) -> None:
        """Attach sanitized coverage/exclusion metadata to this module run."""
        async with self._lock:
            self._module_run.coverage_metadata = dict(metadata)
            await self._tick()

    async def mark_no_input(self, reason: SkipReason | str) -> None:
        """Persist a *no-input* outcome: the module ran but had nothing eligible
        to act on (``zero_eligible_targets``), a required backend was not
        configured (``not_configured``), or its binary was absent
        (``missing_binary``).

        This is distinct from ``mark_skipped`` (free-text) and from a benign
        ``COMPLETED`` with zero evidence: the release gate must be able to tell
        "the scan did nothing because there was nothing to do" apart from a
        clean empty result. ``ScanService`` will not overwrite ``SKIPPED`` with
        ``COMPLETED``.
        """
        reason = SkipReason(reason)
        async with self._lock:
            self._module_run.status = ModuleRunStatus.SKIPPED
            self._module_run.skip_reason = reason
            self._module_run.error = f"no input: {reason.value}"
            await self._tick()

    async def record_target_accounting(self, resolution: Any) -> None:
        """Persist the bounded target-provenance summary from
        :meth:`resolve_targets` into ``coverage_metadata['target_accounting']``
        so the run page / events / CLI can state the number and provenance of
        targets supplied to this active module (P0-2 acceptance)."""
        async with self._lock:
            md = dict(self._module_run.coverage_metadata or {})
            md["target_accounting"] = resolution.accounting()
            self._module_run.coverage_metadata = md
            await self._tick()

    async def resolve_targets(
        self, *accept_types: str, include_prior_assets: bool = False
    ) -> Any:
        """Build this active module's target set for the CURRENT scan run.

        Draws from current-run Evidence (a same-run dependency's output is
        visible without waiting for correlation - the P0-2 fix), RoE-declared
        hosts/domains, and optionally the engagement's prior correlated Assets
        (``include_prior_assets``). Scope classification and safe-form
        validation are applied centrally, so an EXCLUDED / out-of-scope / crafted
        value can never reach the returned ``eligible`` list.
        """
        from recon.modules._targets import resolve_targets

        return await resolve_targets(
            self, *accept_types, include_prior_assets=include_prior_assets
        )

    async def _scalars(self, stmt: Any) -> list[Any]:
        """Run a SELECT on the module's session under the write lock and return
        the scalar rows. Used by :mod:`recon.modules._targets`."""
        async with self._lock:
            return list((await self._session.execute(stmt)).scalars().all())

    async def add_artifact(
        self,
        *,
        data: bytes,
        kind: str,
        content_type: str | None = None,
        asset_id: str | None = None,
    ) -> Artifact:
        """Write a large captured blob (clone log, raw output) to the content-
        addressed artifact store and register its manifest row. Keeps bulky raw
        data out of ``Evidence.raw_data`` (PRD Section 9)."""
        from recon.artifacts.store import ArtifactStore

        artifact = ArtifactStore().store_bytes(
            self.engagement.id,
            data,
            kind=kind,
            content_type=content_type,
            asset_id=asset_id,
        )
        async with self._lock:
            self._session.add(artifact)
            await self._tick()
        return artifact

    # --- reading prior findings (module chaining) ----------------------
    async def known_values(self, *subject_types: str) -> list[str]:
        """Distinct evidence subject values of the given types for this
        engagement, across every prior module and scan run. This is how a
        downstream module (crawler, JS analyzer) picks up its inputs."""
        stmt = (
            select(Evidence.subject_value)
            .where(
                Evidence.engagement_id == self.engagement.id,
                Evidence.subject_type.in_(subject_types),
                Evidence.polarity == FindingPolarity.PRESENT,
                Evidence.is_error.is_(False),
            )
            .distinct()
        )
        async with self._lock:
            rows = (await self._session.execute(stmt)).scalars().all()
        return list(rows)

    async def known_evidence(self, *subject_types: str) -> Sequence[Evidence]:
        stmt = select(Evidence).where(
            Evidence.engagement_id == self.engagement.id,
            Evidence.subject_type.in_(subject_types),
            Evidence.is_error.is_(False),
        )
        async with self._lock:
            return (await self._session.execute(stmt)).scalars().all()

    def scoped_targets(self, targets) -> list[str]:  # noqa: ANN001
        """Filter a target iterable for active use: EXCLUDED is always dropped;
        FLAGGED is dropped unless the run has an out-of-scope override."""
        from recon.models.enums import ScopeStatus

        out: list[str] = []
        for t in targets:
            status = self.scope.classify(t).status
            if status is ScopeStatus.EXCLUDED:
                continue
            if status is ScopeStatus.FLAGGED and not self.allow_out_of_scope:
                continue
            out.append(t)
        return out

    async def known_assets(
        self, *asset_types: str, in_scope_only: bool = True
    ) -> list[str]:
        """Correlated Asset values of the given types. Active modules use this
        (post-checkpoint) to get their targets, defaulting to in-scope only."""
        from recon.models.asset import Asset
        from recon.models.enums import AssetType, ScopeStatus

        types = [AssetType(t) for t in asset_types]
        stmt = select(Asset.value).where(
            Asset.engagement_id == self.engagement.id, Asset.type.in_(types)
        )
        if in_scope_only:
            stmt = stmt.where(Asset.in_scope_status == ScopeStatus.IN_SCOPE)
        async with self._lock:
            return list((await self._session.execute(stmt)).scalars().all())

    async def known_asset_rows(
        self, *asset_types: str, in_scope_only: bool = True
    ) -> list[Any]:
        """Full correlated Asset rows (not just ``.value``) for the given
        types - lets a module read ``interest_level``/``confidence_score``
        alongside the value, e.g. ``scan_diff`` inheriting a finding's
        interest onto the delta it emits for that finding."""
        from recon.models.asset import Asset
        from recon.models.enums import AssetType, ScopeStatus

        types = [AssetType(t) for t in asset_types]
        stmt = select(Asset).where(
            Asset.engagement_id == self.engagement.id, Asset.type.in_(types)
        )
        if in_scope_only:
            stmt = stmt.where(Asset.in_scope_status == ScopeStatus.IN_SCOPE)
        async with self._lock:
            return list((await self._session.execute(stmt)).scalars().all())

    # --- scan_diff's snapshot/delta persistence --------------------------
    # AssetSnapshot/ScanDelta are scan_diff's own data model (PRD S11.10) - no
    # other module writes them, so these three methods are its sanctioned
    # side-effect channel, the same role add_evidence plays for everything else.
    async def latest_asset_snapshot(self) -> Any | None:
        """The most recent AssetSnapshot for this engagement (across every
        scan run), or ``None`` on a first run - the diff baseline."""
        from recon.models.snapshot import AssetSnapshot

        stmt = (
            select(AssetSnapshot)
            .where(AssetSnapshot.engagement_id == self.engagement.id)
            .order_by(AssetSnapshot.taken_at.desc())
            .limit(1)
        )
        async with self._lock:
            return (await self._session.execute(stmt)).scalars().first()

    async def write_asset_snapshot(
        self, *, signature_set: list[str], summary: dict[str, int]
    ) -> Any:
        from recon.models.snapshot import AssetSnapshot

        snap = AssetSnapshot(
            engagement_id=self.engagement.id,
            scan_run_id=self.scan_run_id,
            signature_set=signature_set,
            summary=summary,
        )
        async with self._lock:
            self._session.add(snap)
            await self._tick()
        return snap

    async def write_scan_delta(
        self,
        *,
        base_snapshot_id: str | None,
        added: list[str],
        removed: list[str],
        changed: list[dict[str, str]],
    ) -> None:
        from recon.models.snapshot import ScanDelta

        delta = ScanDelta(
            engagement_id=self.engagement.id,
            scan_run_id=self.scan_run_id,
            base_snapshot_id=base_snapshot_id,
            added=added,
            removed=removed,
            changed=changed,
        )
        async with self._lock:
            self._session.add(delta)
            await self._tick()

    # --- audit for non-HTTP outbound actions --------------------------
    async def audit_action(
        self,
        *,
        target: str,
        request_detail: dict[str, Any],
        response_meta: dict[str, Any] | None = None,
        in_scope_status: ScopeStatus = ScopeStatus.NOT_APPLICABLE,
        override_used: bool = False,
    ) -> None:
        """For outbound actions the shared HTTP client does not make - e.g. a
        DNS query. HTTP requests through ``self.http`` are audited automatically."""
        await self.record_audit(
            target=target,
            request_detail=request_detail,
            response_meta=response_meta,
            in_scope_status=in_scope_status,
            override_used=override_used,
        )

    async def record_audit(
        self,
        *,
        target: str,
        request_detail: dict[str, Any],
        response_meta: dict[str, Any] | None = None,
        in_scope_status: ScopeStatus = ScopeStatus.NOT_APPLICABLE,
        override_used: bool = False,
        module: str | None = None,
    ) -> None:
        """Write one audit row on the module's own session (single writer, no
        cross-connection lock contention). Also used by ReconHTTPClient."""
        async with self._lock:
            await audit_logger.record(
                self._session,
                engagement_id=self.engagement.id,
                scan_run_id=self.scan_run_id,
                module=module or self.module_name,
                target=target,
                in_scope_status=in_scope_status,
                roe_config_hash=self.engagement.roe_config_hash,
                request_detail=request_detail,
                response_meta=response_meta,
                override_used=override_used,
            )
            await self._tick()

    # --- progress -----------------------------------------------------
    async def progress(
        self,
        message: str,
        *,
        current: int | None = None,
        total: int | None = None,
        **fields: Any,
    ) -> None:
        """Emit a live progress event.

        Pass ``current`` and ``total`` when the module is working through a
        countable set of units - the dashboard turns them into a live percent
        for the running module. ``count`` (legacy) is still accepted via
        ``**fields`` but carries no percent.
        """
        if current is not None:
            fields["current"] = current
        if total:
            fields["total"] = total
            fields["pct"] = max(0, min(100, round(100 * (current or 0) / total)))
        await self._emit_event(
            "progress", module=self.module_name, message=message, **fields
        )

    # --- internal ---------------------------------------------------
    async def _tick(self) -> None:
        """Caller must already hold ``self._lock``."""
        self._since_commit += 1
        if self._since_commit >= _COMMIT_EVERY:
            await self._session.commit()
            self._since_commit = 0

    async def flush(self) -> None:
        async with self._lock:
            await self._session.commit()
            self._since_commit = 0


class ReconModule(abc.ABC):
    """Base class for all recon modules.

    Subclasses set the class attributes and implement ``run``. Registration is
    by decorating with ``@register`` (see ``recon.modules.registry``).
    """

    #: unique slug, e.g. "dns"
    name: str = ""
    #: passive modules run (and reach a checkpoint) before any active module
    phase: ModulePhase = ModulePhase.PASSIVE
    #: module slugs that must complete before this one starts
    depends_on: tuple[str, ...] = ()
    #: one-line description for the scan-setup UI
    description: str = ""
    #: whether this module needs an external binary (nmap/ffuf) present
    requires_binary: str | None = None
    #: wall-clock ceiling for one run of this module, in seconds. ``None`` uses
    #: the orchestrator's per-phase default. A module that manages its own hard
    #: timeout internally (e.g. an nmap subprocess) can set this higher.
    max_runtime_seconds: float | None = None

    @abc.abstractmethod
    async def run(self, ctx: ModuleContext) -> None:
        """Do the recon. Emit findings via ``ctx.add_evidence`` / ``add_negative``.

        Raising propagates and marks the module failed (the scan run continues
        to the next module). Per-target failures should use ``ctx.add_error``
        and keep going.
        """
        raise NotImplementedError
