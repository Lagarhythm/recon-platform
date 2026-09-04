"""The single audited, rate-limited, scope-gated outbound HTTP path.

Every recon module that speaks HTTP does so through one instance of this class,
constructed per scan run. That guarantees:

  * every request is written to the Audit Log (target, scope decision, RoE
    hash, request + response metadata);
  * no request reaches an ``excluded`` or ``flagged`` target without an
    explicit operator override;
  * the RoE's rate limit and concurrency cap are enforced globally;
  * jitter and User-Agent rotation are applied from the RoE.

Phase 3 (Evasion Layer) extends this with adaptive backoff on 429/RST; the
hook (``rate_limiter.update_rate``) already exists.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from recon.core.audit import audit_logger
from recon.core.roe import RoEConfig
from recon.core.scope import ScopeManager
from recon.db import SessionLocal
from recon.models.enums import ScopeStatus
from recon.net.backoff import BackoffController
from recon.net.rate_limit import RateLimiter

_DEFAULT_UA = "recon-platform/0.1 (+authorized-assessment)"
_AUDIT_FALLBACK = logging.getLogger("recon.audit.fallback")


class ReconRequestError(RuntimeError):
    """Any failure making the request (network, timeout, protocol)."""


class ScopeViolation(ReconRequestError):
    """Target is excluded or flagged and no override was given."""

    def __init__(self, decision) -> None:  # noqa: ANN001
        super().__init__(
            f"{decision.host} is {decision.status.value} ({decision.reason}); "
            f"an out-of-scope override is required to proceed"
        )
        self.decision = decision


class ReconHTTPClient:
    def __init__(
        self,
        *,
        roe: RoEConfig,
        scope: ScopeManager,
        engagement_id: str,
        roe_config_hash: str,
        scan_run_id: str,
        allow_out_of_scope: bool = False,
        timeout: float = 15.0,
        verify_tls: bool = False,
        #: The scan-run's *shared* token bucket. Every module's HTTP traffic and
        #: its audited DNS actions draw from the same bucket so concurrent
        #: activity on one engagement never spends the RoE budget more than once.
        #: ``None`` builds a private bucket sized from the RoE (used by the
        #: isolated test harness); production always injects the shared one.
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._roe = roe
        self._scope = scope
        self._engagement_id = engagement_id
        self._roe_hash = roe_config_hash
        self._scan_run_id = scan_run_id
        self._allow_oos = allow_out_of_scope

        self._rate = rate_limiter or RateLimiter(roe.rate_limits.max_requests_per_second)
        self._backoff = BackoffController(roe.rate_limits.max_requests_per_second)
        self._sem = asyncio.Semaphore(roe.rate_limits.max_concurrent_connections)
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            verify=verify_tls,
            limits=httpx.Limits(
                max_connections=roe.rate_limits.max_concurrent_connections
            ),
        )
        self._uas = list(roe.evasion.user_agents)
        self._ua_index = 0

        # Audit writes: preferred path is the current module's own session
        # (set via ``self.audit_context`` by the orchestrator) - one writer, no
        # cross-connection SQLite lock contention. Falls back to a dedicated
        # session when used outside a module (tests, ad-hoc).
        self._audit_lock = asyncio.Lock()
        self._audit_session = None
        self.audit_context = None  # ModuleContext | None

        # Set by the orchestrator before each module runs so audit rows carry
        # the right module name.
        self.module_name: str = "http"

    # --- lifecycle ---------------------------------------------------
    async def aclose(self) -> None:
        await self._client.aclose()
        if self._audit_session is not None:
            await self._audit_session.close()
            self._audit_session = None

    @property
    def rate_limiter(self) -> RateLimiter:
        return self._rate

    # --- evasion primitives ---------------------------------------
    def _next_ua(self) -> str:
        if not self._uas:
            return _DEFAULT_UA
        if self._roe.evasion.rotation_strategy.value == "random":
            return random.choice(self._uas)
        ua = self._uas[self._ua_index % len(self._uas)]
        self._ua_index += 1
        return ua

    async def _jitter(self) -> None:
        j = self._roe.evasion.jitter
        if not j.enabled or j.max_ms <= 0:
            return
        await asyncio.sleep(random.uniform(j.min_ms, j.max_ms) / 1000.0)

    # --- the request path -----------------------------------------
    async def request(
        self,
        method: str,
        url: str,
        *,
        is_target: bool = True,
        allow_out_of_scope: bool | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 5,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an audited request.

        ``is_target=False`` marks a call to a third-party OSINT service (crt.sh,
        a public resolver) - scope is not enforced but the call is still audited
        as ``n/a``.

        Redirects are followed *by this client*, never by httpx: every hop is
        re-classified against scope and written to the audit log. A hop to an
        out-of-scope host without an override raises ``ScopeViolation``.
        """
        kwargs.pop("follow_redirects", None)  # never let httpx do it
        cur_method, cur_url = method, url
        hops = 0
        while True:
            resp = await self._single_request(
                cur_method, cur_url,
                is_target=is_target,
                allow_out_of_scope=allow_out_of_scope,
                headers=headers,
                **kwargs,
            )
            if not (follow_redirects and resp.is_redirect and hops < max_redirects):
                return resp
            location = resp.headers.get("location")
            if not location:
                return resp
            hops += 1
            cur_url = urljoin(cur_url, location)
            if resp.status_code in (301, 302, 303) and cur_method != "HEAD":
                cur_method = "GET"
                kwargs.pop("content", None)
                kwargs.pop("data", None)
                kwargs.pop("json", None)

    async def _single_request(
        self,
        method: str,
        url: str,
        *,
        is_target: bool,
        allow_out_of_scope: bool | None,
        headers: dict[str, str] | None,
        **kwargs: Any,
    ) -> httpx.Response:
        override = self._allow_oos if allow_out_of_scope is None else allow_out_of_scope
        scope_status = ScopeStatus.NOT_APPLICABLE
        used_override = False

        if is_target:
            decision = self._scope.classify(url)
            scope_status = decision.status
            if decision.status in (ScopeStatus.EXCLUDED, ScopeStatus.FLAGGED):
                if not override:
                    await self._audit(
                        url, method, headers or {}, scope_status,
                        response_meta={"blocked": "scope"}, override_used=False,
                    )
                    raise ScopeViolation(decision)
                used_override = True

        req_headers = {**(headers or {})}
        req_headers.setdefault("User-Agent", self._next_ua())

        await self._rate.acquire()
        cooldown = self._backoff.extra_delay()
        if cooldown > 0:
            await asyncio.sleep(min(cooldown, 30.0))
        async with self._sem:
            await self._jitter()
            t0 = time.perf_counter()
            try:
                resp = await self._client.request(
                    method, url, headers=req_headers, **kwargs
                )
            except httpx.HTTPError as exc:
                # A *timeout* or a mid-stream reset can mean we're pushing the
                # target too hard - that feeds the adaptive backoff. A plain
                # connection refusal / DNS failure / no-route (bare ConnectError)
                # just means nothing is listening there; it is a finding, not a
                # reason to throttle traffic to the rest of the scope.
                distress = isinstance(
                    exc, (httpx.TimeoutException, httpx.ReadError, httpx.WriteError,
                          httpx.RemoteProtocolError)
                )
                self._rate.update_rate(
                    self._backoff.record(throttled=False, connection_error=distress)
                )
                await self._audit(
                    url, method, req_headers, scope_status,
                    response_meta={"error": type(exc).__name__, "detail": str(exc)},
                    override_used=used_override,
                )
                raise ReconRequestError(f"{type(exc).__name__}: {exc}") from exc

            self._rate.update_rate(
                self._backoff.record(throttled=(resp.status_code == 429))
            )
            elapsed_ms = round((time.perf_counter() - t0) * 1000)
            await self._audit(
                url, method, req_headers, scope_status,
                response_meta={
                    "status": resp.status_code,
                    "bytes": len(resp.content),
                    "elapsed_ms": elapsed_ms,
                    "content_type": resp.headers.get("content-type"),
                    "location": resp.headers.get("location"),
                },
                override_used=used_override,
            )
            return resp

    async def acquire_slot(self) -> None:
        """For a module making an out-of-band connection (e.g. a raw TLS
        handshake) - subjects it to the same rate limit and jitter."""
        await self._rate.acquire()
        await self._jitter()

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kw)

    # --- audit ----------------------------------------------------
    async def _audit(
        self,
        url: str,
        method: str,
        headers: dict[str, str],
        scope_status: ScopeStatus,
        *,
        response_meta: dict[str, Any] | None,
        override_used: bool,
    ) -> None:
        request_detail = {
            "method": method,
            "url": url,
            "user_agent": headers.get("User-Agent"),
        }
        try:
            if self.audit_context is not None:
                await self.audit_context.record_audit(
                    target=url,
                    request_detail=request_detail,
                    response_meta=response_meta,
                    in_scope_status=scope_status,
                    override_used=override_used,
                    module=self.module_name,
                )
                return
            async with self._audit_lock:
                if self._audit_session is None:
                    self._audit_session = SessionLocal()
                await audit_logger.record(
                    self._audit_session,
                    engagement_id=self._engagement_id,
                    scan_run_id=self._scan_run_id,
                    module=self.module_name,
                    target=url,
                    in_scope_status=scope_status,
                    roe_config_hash=self._roe_hash,
                    request_detail=request_detail,
                    response_meta=response_meta,
                    override_used=override_used,
                )
                await self._audit_session.commit()
        except Exception as exc:
            if self._audit_session is not None:
                with contextlib.suppress(Exception):
                    await self._audit_session.rollback()
            # The DB write failed but the request already went out - make sure
            # it lands *somewhere* rather than vanishing from the record.
            _AUDIT_FALLBACK.error(
                "AUDIT-FALLBACK (%s: %s) engagement=%s scan=%s module=%s %s %s scope=%s override=%s meta=%s",
                type(exc).__name__, exc, self._engagement_id, self._scan_run_id,
                self.module_name, method, url, scope_status.value, override_used, response_meta,
            )
