"""CLI transport: in-process (imports the orchestrator) or REST (``--server``).

Both implementations return plain JSON-able dicts/lists so the command layer is
transport-agnostic - it never sees an ORM object or an HTTP response.
"""

from __future__ import annotations

import abc
import json
from collections.abc import AsyncIterator
from typing import Any

from recon.cli.output import (
    EXIT_AUTH,
    EXIT_USER_ERROR,
    CliError,
)

# Terminal scan-stream events - ``--wait`` stops on any of these.
_STREAM_STOP = {"scan_completed", "scan_failed", "checkpoint_reached", "scan_paused"}


def _iso(dt: Any) -> str | None:
    return dt.isoformat() if dt is not None and hasattr(dt, "isoformat") else dt


class ReconClient(abc.ABC):
    @abc.abstractmethod
    async def engagement_create(self, roe_yaml: str, name: str | None) -> dict: ...
    @abc.abstractmethod
    async def engagement_list(self, *, include_archived: bool = True) -> list[dict]: ...
    @abc.abstractmethod
    async def engagement_show(self, engagement_id: str) -> dict: ...
    @abc.abstractmethod
    async def engagement_set_status(self, engagement_id: str, status: str) -> dict: ...
    @abc.abstractmethod
    async def engagement_purge(
        self, engagement_id: str, confirm_name: str | None = None
    ) -> dict: ...
    @abc.abstractmethod
    async def scan_start(
        self, engagement_id: str, modules: list[str], *, allow_out_of_scope: bool,
        yes_active: bool,
    ) -> dict: ...
    @abc.abstractmethod
    async def scan_status(self, run_id: str) -> dict: ...
    @abc.abstractmethod
    async def scan_checkpoint(self, run_id: str) -> dict: ...
    @abc.abstractmethod
    async def scan_resume(self, run_id: str) -> dict: ...
    @abc.abstractmethod
    async def scan_cancel(self, run_id: str) -> dict: ...
    @abc.abstractmethod
    async def scan_list(self, engagement_id: str) -> list[dict]: ...
    @abc.abstractmethod
    def scan_stream(self, run_id: str) -> AsyncIterator[dict]: ...
    @abc.abstractmethod
    async def scan_join(self, run_id: str) -> dict: ...
    @abc.abstractmethod
    async def available_modules(self) -> list[dict]: ...
    @abc.abstractmethod
    async def report(self, engagement_id: str, fmt: str, *, redacted: bool) -> bytes: ...
    @abc.abstractmethod
    async def diff(self, engagement_id: str, since: str | None) -> dict: ...
    @abc.abstractmethod
    async def analyst_run(self, engagement_id: str) -> dict: ...
    @abc.abstractmethod
    async def cve_status(self) -> dict: ...
    @abc.abstractmethod
    async def cve_refresh(self, source: str | None) -> dict: ...
    @abc.abstractmethod
    async def token_create(self, name: str) -> dict: ...
    @abc.abstractmethod
    async def token_list(self) -> list[dict]: ...
    @abc.abstractmethod
    async def token_revoke(self, token_id: str) -> dict: ...

    async def aclose(self) -> None:  # noqa: D401 - optional cleanup hook
        pass


# ===========================================================================
# In-process
# ===========================================================================
class InProcessClient(ReconClient):
    """Runs the orchestrator in this process against its configured database."""

    def __init__(self, user_id: str | None = None) -> None:
        from recon.orchestrator.engagements import EngagementService
        from recon.orchestrator.tokens import TokenService

        self._engagements = EngagementService()
        self._tokens = TokenService()
        # Set by the REST layer to the authenticated token owner. Left None for
        # the local CLI, which resolves the sole operator account.
        self._user_id = user_id

    # --- helpers ---------------------------------------------------
    async def _resolve_user(self, session):  # noqa: ANN001
        """The account operations attribute to. The REST layer pins the token
        owner; the local CLI uses the single operator account, bootstrapping one
        if the env vars are set and the table is empty (headless bring-up)."""
        from sqlalchemy import select

        from recon.models.user import User
        from recon.orchestrator.auth import AuthService

        if self._user_id is not None:
            user = await session.get(User, self._user_id)
            if user is None:
                raise CliError("authenticated user no longer exists", EXIT_AUTH)
            return user

        await AuthService().maybe_bootstrap_admin(session)
        user = (
            await session.execute(select(User).order_by(User.created_at))
        ).scalars().first()
        if user is None:
            raise CliError(
                "no operator account exists - run the dashboard once and complete "
                "/setup, or set RECON_BOOTSTRAP_ADMIN_USER / _PASSWORD.",
                EXIT_AUTH,
            )
        return user

    @staticmethod
    def _engagement_dict(e) -> dict:  # noqa: ANN001
        return {
            "id": e.id,
            "name": e.name,
            "client": e.client_name,
            "status": e.status.value if hasattr(e.status, "value") else e.status,
            "roe_hash": e.roe_config_hash[:12],
            "llm_analysis": e.llm_analysis_enabled,
            "window_start": _iso(e.authorized_window_start),
            "window_end": _iso(e.authorized_window_end),
            "created_at": _iso(e.created_at),
        }

    @staticmethod
    def _run_dict(r) -> dict:  # noqa: ANN001
        return {
            "id": r.id,
            "engagement_id": r.engagement_id,
            "status": r.status.value if hasattr(r.status, "value") else r.status,
            "phase": (r.current_phase.value if getattr(r, "current_phase", None) else None),
            "modules_requested": list(r.modules_requested or []),
            "modules_completed": list(r.modules_completed or []),
            "allow_out_of_scope": r.allow_out_of_scope,
            "started_at": _iso(r.started_at),
            "completed_at": _iso(r.completed_at),
            "error": r.error,
        }

    # --- engagements ---------------------------------------------
    async def engagement_create(self, roe_yaml: str, name: str | None) -> dict:
        from recon.core.roe import RoEError
        from recon.db import session_scope

        try:
            async with session_scope() as session:
                engagement, advisories = await self._engagements.create(
                    session, roe_yaml, name_override=name
                )
                await session.flush()
                out = self._engagement_dict(engagement)
            out["advisories"] = advisories
            return out
        except RoEError as exc:
            raise CliError(f"RoE rejected: {exc}", EXIT_USER_ERROR) from exc

    async def engagement_list(self, *, include_archived: bool = True) -> list[dict]:
        from recon.db import session_scope

        async with session_scope() as session:
            rows = await self._engagements.list(
                session, include_archived=include_archived
            )
            return [self._engagement_dict(e) for e in rows]

    async def engagement_show(self, engagement_id: str) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.engagements import EngagementNotFound
        from recon.orchestrator.queries import asset_queries, scan_queries

        async with session_scope() as session:
            try:
                e = await self._engagements.get(session, engagement_id)
            except EngagementNotFound as exc:
                raise CliError(f"engagement not found: {engagement_id}") from exc
            stats = await asset_queries.stats(session, engagement_id)
            runs = await scan_queries.list_runs(session, engagement_id, limit=5)
            out = self._engagement_dict(e)
            out["assets"] = stats.total
            out["findings"] = stats.findings
            out["assets_by_type"] = stats.by_type
            out["recent_runs"] = [self._run_dict(r) for r in runs]
            return out

    async def engagement_set_status(self, engagement_id: str, status: str) -> dict:
        from recon.db import session_scope
        from recon.models.enums import EngagementStatus
        from recon.orchestrator.engagements import EngagementNotFound

        try:
            new_status = EngagementStatus(status)
        except ValueError as exc:
            raise CliError(f"unknown status: {status!r}") from exc
        async with session_scope() as session:
            try:
                e = await self._engagements.set_status(session, engagement_id, new_status)
            except EngagementNotFound as exc:
                raise CliError(f"engagement not found: {engagement_id}") from exc
            return self._engagement_dict(e)

    async def engagement_purge(
        self, engagement_id: str, confirm_name: str | None = None
    ) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.engagements import EngagementNotFound

        async with session_scope() as session:
            try:
                e = await self._engagements.get(session, engagement_id)
            except EngagementNotFound as exc:
                raise CliError(f"engagement not found: {engagement_id}") from exc
            name = e.name
            # confirm_name is checked by the local CLI gate and by the REST
            # route before we get here; when it is passed, enforce it too.
            if confirm_name is not None and confirm_name != name:
                raise CliError("purge aborted: confirmation name did not match")
            await self._engagements.purge(session, engagement_id)
            return {"purged": engagement_id, "name": name}

    # --- scans --------------------------------------------------
    async def available_modules(self) -> list[dict]:
        from recon.orchestrator.scans import scan_service

        mods = await scan_service.available_modules()
        return [{"name": m.name, "phase": m.phase.value, "description": m.description}
                for m in mods]

    async def scan_start(
        self, engagement_id: str, modules: list[str], *, allow_out_of_scope: bool,
        yes_active: bool,
    ) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.engagements import EngagementNotFound
        from recon.orchestrator.scans import ScanError, scan_service

        async with session_scope() as session:
            try:
                engagement = await self._engagements.get(session, engagement_id)
            except EngagementNotFound as exc:
                raise CliError(f"engagement not found: {engagement_id}") from exc
            try:
                run = await scan_service.start_scan(
                    session, engagement, modules,
                    allow_out_of_scope=allow_out_of_scope,
                )
            except ScanError as exc:
                raise CliError(f"could not start scan: {exc}") from exc
            run_id = run.id

        if yes_active:
            # Pre-authorise the passive->active checkpoint, still logged as a
            # conscious override (resume_scan flips active_confirmed).
            await self._preauthorize_active(run_id)
        return await self.scan_status(run_id)

    async def _preauthorize_active(self, run_id: str) -> None:
        from recon.db import session_scope
        from recon.models.scanrun import ScanRun

        async with session_scope() as session:
            run = await session.get(ScanRun, run_id)
            if run is not None:
                run.active_confirmed = True

    async def scan_status(self, run_id: str) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.queries import scan_queries

        async with session_scope() as session:
            run = await scan_queries.get_run(session, run_id)
            if run is None:
                raise CliError(f"scan run not found: {run_id}")
            rows = await scan_queries.module_rows(session, run_id)
            out = self._run_dict(run)
            out["modules"] = [
                {
                    "module": r.module_name,
                    "phase": r.phase.value if hasattr(r.phase, "value") else r.phase,
                    "status": r.status.value if hasattr(r.status, "value") else r.status,
                    "evidence": r.evidence_count,
                    "errors": r.error_count,
                }
                for r in rows
            ]
            return out

    async def scan_join(self, run_id: str) -> dict:
        """Block until the run leaves RUNNING. In-process there is no daemon to
        hand the scan task to - it lives on this event loop - so a non-streaming
        ``scan start`` must wait here or the task dies when the loop exits."""
        import asyncio

        from recon.db import session_scope
        from recon.models.enums import ScanRunStatus
        from recon.models.scanrun import ScanRun

        while True:
            async with session_scope() as session:
                run = await session.get(ScanRun, run_id)
                if run is None:
                    raise CliError(f"scan run not found: {run_id}")
                if run.status is not ScanRunStatus.RUNNING:
                    break
            await asyncio.sleep(0.25)
        return await self.scan_status(run_id)

    async def scan_checkpoint(self, run_id: str) -> dict:
        return await self._resume(run_id, checkpoint=True)

    async def scan_resume(self, run_id: str) -> dict:
        return await self._resume(run_id, checkpoint=False)

    async def _resume(self, run_id: str, *, checkpoint: bool) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.scans import ScanError, scan_service

        async with session_scope() as session:
            try:
                await scan_service.resume_scan(session, run_id)
            except ScanError as exc:
                raise CliError(str(exc)) from exc
        return await self.scan_status(run_id)

    async def scan_cancel(self, run_id: str) -> dict:
        from recon.orchestrator.scans import scan_service

        await scan_service.cancel_scan(run_id)
        return await self.scan_status(run_id)

    async def scan_list(self, engagement_id: str) -> list[dict]:
        from recon.db import session_scope
        from recon.orchestrator.queries import scan_queries

        async with session_scope() as session:
            runs = await scan_queries.list_runs(session, engagement_id)
            return [self._run_dict(r) for r in runs]

    async def scan_stream(self, run_id: str) -> AsyncIterator[dict]:
        from recon.orchestrator.events import event_bus

        queue = event_bus.subscribe(run_id)
        try:
            while True:
                event = await queue.get()
                if event.get("type") == "synced":
                    continue
                yield event
                if event.get("type") in _STREAM_STOP:
                    return
        finally:
            event_bus.unsubscribe(run_id, queue)

    # --- report / diff / analyst -------------------------------
    async def report(self, engagement_id: str, fmt: str, *, redacted: bool) -> bytes:
        from recon.db import session_scope
        from recon.orchestrator.engagements import EngagementNotFound
        from recon.reporting.collect import build_report_data
        from recon.reporting.redaction import RedactionMode, redact_report
        from recon.reporting.render import (
            PdfUnavailable,
            render_csv,
            render_html,
            render_json,
            render_pdf,
        )

        async with session_scope() as session:
            try:
                engagement = await self._engagements.get(session, engagement_id)
            except EngagementNotFound as exc:
                raise CliError(f"engagement not found: {engagement_id}") from exc
            data = await build_report_data(session, engagement)

        mode = RedactionMode.CLIENT if redacted else RedactionMode.INTERNAL
        data = redact_report(data, mode)
        if fmt == "json":
            return render_json(data).encode("utf-8")
        if fmt == "csv":
            return render_csv(data).encode("utf-8")
        if fmt == "html":
            return render_html(data).encode("utf-8")
        if fmt == "pdf":
            try:
                return render_pdf(data)
            except PdfUnavailable as exc:
                raise CliError(str(exc)) from exc
        raise CliError(f"unknown report format: {fmt!r}")

    async def diff(self, engagement_id: str, since: str | None) -> dict:
        from sqlalchemy import select

        from recon.db import session_scope
        from recon.models.snapshot import AssetSnapshot

        async with session_scope() as session:
            snaps = (
                await session.execute(
                    select(AssetSnapshot)
                    .where(AssetSnapshot.engagement_id == engagement_id)
                    .order_by(AssetSnapshot.taken_at.desc())
                )
            ).scalars().all()

        if len(snaps) < 2:
            return {
                "engagement_id": engagement_id,
                "note": "need at least two AssetSnapshots to diff; scan_diff "
                        "(Wave 2) populates them. Nothing to compare yet.",
                "snapshots": len(snaps),
                "added": [], "removed": [], "changed": [],
            }
        current = snaps[0]
        if since:
            base = next((s for s in snaps[1:] if s.scan_run_id == since), None)
            if base is None:
                raise CliError(f"no snapshot for --since run {since!r} on this engagement")
        else:
            base = snaps[1]
        cur, old = set(current.signature_set or []), set(base.signature_set or [])
        return {
            "engagement_id": engagement_id,
            "base_snapshot": base.id,
            "current_snapshot": current.id,
            "added": sorted(cur - old),
            "removed": sorted(old - cur),
            "changed": [],
        }

    async def analyst_run(self, engagement_id: str) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.analyst import AnalystError, AnalystService
        from recon.orchestrator.engagements import EngagementNotFound

        async with session_scope() as session:
            try:
                engagement = await self._engagements.get(session, engagement_id)
            except EngagementNotFound as exc:
                raise CliError(f"engagement not found: {engagement_id}") from exc
            try:
                analysis = await AnalystService().run(session, engagement)
            except AnalystError as exc:
                raise CliError(f"analyst run failed: {exc}") from exc
            return {
                "engagement_id": engagement_id,
                "model": analysis.model,
                "asset_count": analysis.asset_count,
                "summary": analysis.summary,
                "priorities": list(analysis.priorities or []),
                "next_steps": list(analysis.next_steps or []),
            }

    # --- cve (index is Wave 2) ---------------------------------
    async def cve_status(self) -> dict:
        return {
            "available": False,
            "note": "the local CVE index (CVERecord / CVEIndexMeta) and "
                    "cve_correlate land in Wave 2; nothing to report yet.",
        }

    async def cve_refresh(self, source: str | None) -> dict:
        raise CliError(
            "cve refresh is unavailable until the CVE index ships in Wave 2.",
            EXIT_USER_ERROR,
        )

    # --- tokens ------------------------------------------------
    async def token_create(self, name: str) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.tokens import TokenError

        async with session_scope() as session:
            user = await self._resolve_user(session)
            try:
                token, raw = await self._tokens.create(session, user, name)
            except TokenError as exc:
                raise CliError(str(exc)) from exc
            return {
                "id": token.id,
                "name": token.name,
                "token": raw,
                "created_at": _iso(token.created_at),
                "note": "store this now - it is not shown again.",
            }

    async def token_list(self) -> list[dict]:
        from recon.db import session_scope

        async with session_scope() as session:
            user = await self._resolve_user(session)
            rows = await self._tokens.list(session, user)
            return [
                {
                    "id": t.id,
                    "name": t.name,
                    "created_at": _iso(t.created_at),
                    "last_used": _iso(t.last_used),
                    "revoked": t.revoked,
                }
                for t in rows
            ]

    async def token_revoke(self, token_id: str) -> dict:
        from recon.db import session_scope
        from recon.orchestrator.tokens import TokenNotFound

        async with session_scope() as session:
            user = await self._resolve_user(session)
            try:
                token = await self._tokens.revoke(session, user, token_id)
            except TokenNotFound as exc:
                raise CliError(f"token not found: {token_id}") from exc
            return {"id": token.id, "name": token.name, "revoked": True}


# ===========================================================================
# REST
# ===========================================================================
class RestClient(ReconClient):
    """Talks to a running dashboard over ``/api/v1`` with a bearer token."""

    def __init__(self, base_url: str, token: str) -> None:
        import httpx

        if not token:
            raise CliError(
                "REST mode needs an API token - set RECON_API_TOKEN or pass --token.",
                EXIT_AUTH,
            )
        self._base = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=f"{self._base}/api/v1",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, **kw) -> Any:  # noqa: ANN003
        import httpx

        try:
            resp = await self._http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise CliError(f"cannot reach {self._base}: {exc}", EXIT_USER_ERROR) from exc
        if resp.status_code in (401, 403):
            raise CliError("API token rejected (401/403).", EXIT_AUTH)
        if resp.status_code == 404:
            detail = _detail(resp) or "not found"
            raise CliError(detail, EXIT_USER_ERROR)
        if resp.status_code >= 400:
            raise CliError(_detail(resp) or f"HTTP {resp.status_code}", EXIT_USER_ERROR)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.content

    async def engagement_create(self, roe_yaml: str, name: str | None) -> dict:
        return await self._request(
            "POST", "/engagements", json={"roe_yaml": roe_yaml, "name": name}
        )

    async def engagement_list(self, *, include_archived: bool = True) -> list[dict]:
        return await self._request(
            "GET", "/engagements", params={"include_archived": include_archived}
        )

    async def engagement_show(self, engagement_id: str) -> dict:
        return await self._request("GET", f"/engagements/{engagement_id}")

    async def engagement_set_status(self, engagement_id: str, status: str) -> dict:
        return await self._request(
            "POST", f"/engagements/{engagement_id}/status", json={"status": status}
        )

    async def engagement_purge(
        self, engagement_id: str, confirm_name: str | None = None
    ) -> dict:
        return await self._request(
            "POST", f"/engagements/{engagement_id}/purge",
            json={"confirm_name": confirm_name},
        )

    async def available_modules(self) -> list[dict]:
        return await self._request("GET", "/modules")

    async def scan_start(
        self, engagement_id: str, modules: list[str], *, allow_out_of_scope: bool,
        yes_active: bool,
    ) -> dict:
        return await self._request(
            "POST", "/scans",
            json={
                "engagement_id": engagement_id,
                "modules": modules,
                "allow_out_of_scope": allow_out_of_scope,
                "yes_active": yes_active,
            },
        )

    async def scan_status(self, run_id: str) -> dict:
        return await self._request("GET", f"/scans/{run_id}")

    async def scan_checkpoint(self, run_id: str) -> dict:
        return await self._request("POST", f"/scans/{run_id}/checkpoint")

    async def scan_resume(self, run_id: str) -> dict:
        return await self._request("POST", f"/scans/{run_id}/resume")

    async def scan_cancel(self, run_id: str) -> dict:
        return await self._request("POST", f"/scans/{run_id}/cancel")

    async def scan_list(self, engagement_id: str) -> list[dict]:
        return await self._request(
            "GET", "/scans", params={"engagement_id": engagement_id}
        )

    async def scan_join(self, run_id: str) -> dict:
        # The server owns the running scan - fire-and-forget, check back with
        # `recon scan status` (or pass --wait to stream).
        return await self.scan_status(run_id)

    async def scan_stream(self, run_id: str) -> AsyncIterator[dict]:
        import httpx

        try:
            async with self._http.stream("GET", f"/scans/{run_id}/events") as resp:
                if resp.status_code in (401, 403):
                    raise CliError("API token rejected (401/403).", EXIT_AUTH)
                if resp.status_code >= 400:
                    raise CliError(f"cannot stream events: HTTP {resp.status_code}")
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                    event = json.loads(line[5:].strip())
                    if event.get("type") == "synced":
                        continue
                    yield event
                    if event.get("type") in _STREAM_STOP:
                        return
        except httpx.HTTPError as exc:
            raise CliError(f"event stream failed: {exc}") from exc

    async def report(self, engagement_id: str, fmt: str, *, redacted: bool) -> bytes:
        out = await self._request(
            "GET", f"/engagements/{engagement_id}/report",
            params={"format": fmt, "redacted": redacted},
        )
        return out if isinstance(out, bytes) else json.dumps(out).encode("utf-8")

    async def diff(self, engagement_id: str, since: str | None) -> dict:
        return await self._request(
            "GET", f"/engagements/{engagement_id}/diff",
            params={k: v for k, v in {"since": since}.items() if v},
        )

    async def analyst_run(self, engagement_id: str) -> dict:
        return await self._request("POST", f"/engagements/{engagement_id}/analyst")

    async def cve_status(self) -> dict:
        return await self._request("GET", "/cve/status")

    async def cve_refresh(self, source: str | None) -> dict:
        return await self._request(
            "POST", "/cve/refresh",
            json={k: v for k, v in {"source": source}.items() if v},
        )

    async def token_create(self, name: str) -> dict:
        return await self._request("POST", "/tokens", json={"name": name})

    async def token_list(self) -> list[dict]:
        return await self._request("GET", "/tokens")

    async def token_revoke(self, token_id: str) -> dict:
        return await self._request("POST", f"/tokens/{token_id}/revoke")


def _detail(resp) -> str | None:  # noqa: ANN001
    try:
        body = resp.json()
    except Exception:
        return None
    if isinstance(body, dict):
        d = body.get("detail") or body.get("error") or body.get("message")
        if isinstance(d, list) and d:
            return "; ".join(str(x.get("msg", x)) for x in d)
        return d if isinstance(d, str) else None
    return None


def build_client(server: str | None, token: str | None) -> ReconClient:
    if server:
        return RestClient(server, token or "")
    return InProcessClient()
