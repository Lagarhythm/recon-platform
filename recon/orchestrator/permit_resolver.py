"""The one component allowed to mint an :class:`~recon.net.permit.ActiveTargetPermit`
(P0-1 / G0 Part 3, "Minting - only path").

For P0-1 the only wired mechanism is **D0** (``dns_connect_bind_v1``):

* :meth:`ActivePermitResolver.mint_dns_connect_bind_permits` - a hostname is
  eligible only if it is an *exact* ``AuthorizedTarget(target_type="hostname")``
  in the run's currently-active snapshot; one permit per distinct IP this run's
  DNS actually returned for it, **and** only for a resolved IP that falls inside
  a checkpoint-acknowledged ``AuthorizedCidr`` (or is an exact snapshot-owned IP
  target) - a poisoned answer pointing outside the acknowledged address space
  mints nothing (Security G2 re-review, Q1). Bounded by
  ``policy.max_addresses_per_run``.

Port scanning is **out of G2**: minting a port-scan permit under the D0 profile
would authorise a far broader nmap sweep than the operator acknowledged
(Security G2 re-review, S2). It returns in its own separately-checkpointed
method profile with its own resolver. CIDR discovery profiles are likewise
disabled by ``BOOTSTRAP_POLICY``; every CIDR entry point raises
:class:`~recon.net.permit.PermitError`.

:func:`make_predispatch_check` builds the dispatch-time re-verification callable
the :class:`~recon.net.active_executor.ActiveExecutor` runs immediately before it
sends a packet - a second, independent pass over the same invariants against
freshly-loaded rows.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.active_policy import ActiveScanPolicy
from recon.core.netscope import NetscopeError, canonical_ip, contains
from recon.models.authz import (
    DNS_CONNECT_BIND_V1,
    AuthorizationSnapshot,
    AuthorizedCidr,
    AuthorizedTarget,
)
from recon.models.enums import ScopeStatus
from recon.net.permit import (
    ActiveTargetPermit,
    PermitError,
    PermitRevokedError,
    mint_permit,
)

DnsAnswers = Mapping[str, set[str]]


def canonical_probe_hash(payload: object) -> str:
    """SHA-256 over the canonical JSON of a probe-result record. The D0 flow
    stores this on both the ``Evidence.raw_data`` and the
    ``LivenessAttestation.content_hash`` so the resolver can prove the
    attestation refers to unmodified evidence."""
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


async def snapshot_authorizes_ip(
    session: AsyncSession, snapshot_id: str, ip: str
) -> bool:
    """True iff canonical ``ip`` falls inside one of the snapshot's
    checkpoint-acknowledged ``AuthorizedCidr`` networks, or equals an exact
    snapshot-owned ``AuthorizedTarget(target_type="ip")``.

    This is the Q1 check: an exact authorized hostname is authority to
    connect-bind only after its *resolved address* is itself independently
    covered by the acknowledged address space - ``getpeername`` stops a
    post-connect rebind, it does not authenticate the A answer.
    """
    try:
        canon = canonical_ip(ip)
    except NetscopeError:
        return False

    exact_ip = (
        await session.execute(
            select(AuthorizedTarget.id).where(
                AuthorizedTarget.snapshot_id == snapshot_id,
                AuthorizedTarget.target_type == "ip",
                AuthorizedTarget.value == canon,
            )
        )
    ).first()
    if exact_ip is not None:
        return True

    cidrs = (
        await session.execute(
            select(AuthorizedCidr.cidr).where(
                AuthorizedCidr.snapshot_id == snapshot_id
            )
        )
    ).scalars().all()
    for cidr in cidrs:
        try:
            if contains(cidr, canon):
                return True
        except NetscopeError:
            continue
    return False


class ActivePermitResolver:
    def __init__(
        self,
        session: AsyncSession,
        *,
        scan_run_id: str,
        scan_module_run_id: str,
        module_name: str,
        snapshot_id: str,
        policy: ActiveScanPolicy,
        scope_classifier: Callable[..., object],
        dns_answers: DnsAnswers,
    ) -> None:
        self._session = session
        self._scan_run_id = scan_run_id
        self._scan_module_run_id = scan_module_run_id
        self._module_name = module_name
        self._snapshot_id = snapshot_id
        self._policy = policy
        self._classify = scope_classifier
        self._dns_answers = dns_answers

    # -- snapshot re-verification (B1 mint-time) --------------------------

    async def _load_active_snapshot(self) -> AuthorizationSnapshot:
        snap = await self._session.get(AuthorizationSnapshot, self._snapshot_id)
        if snap is None:
            raise PermitError(f"authorization snapshot {self._snapshot_id} not found")
        if snap.scan_run_id != self._scan_run_id:
            raise PermitError(
                f"snapshot {snap.id} belongs to run {snap.scan_run_id}, not "
                f"{self._scan_run_id}"
            )
        if not snap.is_active:
            raise PermitError(
                f"authorization snapshot {snap.id} is revoked or superseded"
            )
        if snap.policy_version != self._policy.version:
            raise PermitError(
                f"snapshot {snap.id} pinned policy {snap.policy_version!r}, "
                f"resolver holds {self._policy.version!r}"
            )
        return snap

    async def _load_authorized_hostname(
        self, hostname: str
    ) -> AuthorizedTarget:
        row = (
            await self._session.execute(
                select(AuthorizedTarget).where(
                    AuthorizedTarget.snapshot_id == self._snapshot_id,
                    AuthorizedTarget.target_type == "hostname",
                    AuthorizedTarget.value == hostname,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise PermitError(
                f"{hostname!r} is not an exactly-authorized hostname in snapshot "
                f"{self._snapshot_id} (no domain-apex / wildcard / subdomain "
                "implicit authorization)"
            )
        return row

    # -- D0: dns_connect_bind -------------------------------------------

    async def mint_dns_connect_bind_permits(
        self, hostname: str
    ) -> list[ActiveTargetPermit]:
        if not self._policy.allows_method(DNS_CONNECT_BIND_V1):
            raise PermitError(
                f"method {DNS_CONNECT_BIND_V1!r} not in policy "
                f"{self._policy.version} allowlist"
            )
        ports = self._policy.ports_for(DNS_CONNECT_BIND_V1)
        if len(ports) != 1:
            raise PermitError(
                f"dns_connect_bind requires exactly one approved port, policy "
                f"{self._policy.version} has {ports!r}"
            )

        snap = await self._load_active_snapshot()
        target = await self._load_authorized_hostname(hostname)

        answers = sorted(self._dns_answers.get(hostname, set()))
        if not answers:
            raise PermitError(
                f"no DNS answer for {hostname!r} in this run's resolution; "
                "nothing to bind"
            )

        permits: list[ActiveTargetPermit] = []
        for raw_ip in answers:
            if len(permits) >= self._policy.max_addresses_per_run:
                break
            try:
                ip = canonical_ip(raw_ip)
            except NetscopeError:
                continue
            decision = self._classify(hostname, resolved_ips=[ip])
            if getattr(decision, "status", None) is ScopeStatus.EXCLUDED:
                continue
            # Q1: the resolved address must itself be inside the acknowledged
            # address space, not merely resolved-from an authorized name.
            if not await snapshot_authorizes_ip(self._session, snap.id, ip):
                continue
            permits.append(
                mint_permit(
                    destination_ip=ip,
                    operation="dns_connect_bind",
                    method_profile_id=DNS_CONNECT_BIND_V1,
                    effective_argv_shape=(),
                    scan_run_id=self._scan_run_id,
                    scan_module_run_id=self._scan_module_run_id,
                    module_name=self._module_name,
                    authorization_snapshot_id=snap.id,
                    authorized_cidr_id=None,
                    authorized_target_id=target.id,
                    parent_authorized_cidr=None,
                    source_hostname=target.value,
                    checkpoint_ack_hash=snap.checkpoint_ack_hash,
                    policy_version=snap.policy_version,
                    liveness_attestation_id=None,
                )
            )
        if not permits:
            raise PermitError(
                f"every DNS answer for {hostname!r} is excluded, unparseable, or "
                "outside the checkpoint-acknowledged address space (Q1)"
            )
        return permits

    # -- port scan: OUT of G2 ------------------------------------------
    # A port-scan permit minted under the D0 profile authorised a far broader
    # nmap sweep than the operator acknowledged (Security G2 re-review, S2).
    # Port scanning returns in its own separately-checkpointed method profile
    # with its own resolver carrying the S3 liveness-semantics checks. There is
    # deliberately no consumer of a LivenessAttestation in the G2 surface.

    # -- CIDR discovery: disabled for P0-1 -----------------------------

    async def resolve_authorized_cidrs(self):
        raise PermitError(
            "CIDR discovery profiles are disabled in the P0-1 active-scan "
            "policy; only dns_connect_bind_v1 is authorized"
        )

    async def mint_discovery_permits(self, *_args, **_kwargs):
        raise PermitError(
            "CIDR discovery profiles are disabled in the P0-1 active-scan policy"
        )


def _safe_canon(value: str) -> str:
    try:
        return canonical_ip(value)
    except NetscopeError:
        return value


# -- dispatch-time re-verification (executor boundary step 3) -----------

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


def make_predispatch_check(
    session_factory: SessionFactory,
    *,
    policy: ActiveScanPolicy,
    scope_classifier: Callable[..., object],
    dns_answers: DnsAnswers,
    persisted_killswitch_engaged: Callable[[AsyncSession], Awaitable[bool]] | None = None,
) -> Callable[[ActiveTargetPermit], Awaitable[None]]:
    """Return an async ``check(permit)`` that re-loads the authorization rows and
    re-runs the B1 invariants immediately before dispatch. Any failure raises
    :class:`PermitError` and the executor sends nothing; a snapshot revoked or
    superseded between mint and dispatch raises :class:`PermitRevokedError` (a
    subclass) so the caller can record a ``cancelled`` disposition rather than
    conflating it with an out-of-scope target (F8 / Q2)."""

    async def check(permit: ActiveTargetPermit) -> None:
        if permit.policy_version != policy.version:
            raise PermitError(
                f"permit policy {permit.policy_version!r} != current "
                f"{policy.version!r}"
            )
        async with session_factory() as session:
            snap = await session.get(
                AuthorizationSnapshot, permit.authorization_snapshot_id
            )
            if snap is None:
                raise PermitError("authorization snapshot vanished before dispatch")
            if snap.revoked_at is not None:
                raise PermitRevokedError(
                    "authorization snapshot revoked before dispatch",
                    reason="revoked",
                )
            if snap.superseded_by_id is not None:
                raise PermitRevokedError(
                    "authorization snapshot superseded before dispatch",
                    reason="superseded",
                )
            if snap.policy_version != permit.policy_version:
                raise PermitError("snapshot policy_version changed before dispatch")

            if permit.authorized_cidr_id is not None:
                row = await session.get(AuthorizedCidr, permit.authorized_cidr_id)
                if row is None or row.snapshot_id != permit.authorization_snapshot_id:
                    raise PermitError("authorized CIDR row changed before dispatch")
                if row.cidr != permit.parent_authorized_cidr:
                    raise PermitError("authorized CIDR value changed before dispatch")
                if not contains(row.cidr, permit.destination_ip):
                    raise PermitError(
                        "destination no longer inside its authorized CIDR"
                    )
                decision = scope_classifier(permit.destination_ip)
            else:
                row = await session.get(
                    AuthorizedTarget, permit.authorized_target_id
                )
                if row is None or row.snapshot_id != permit.authorization_snapshot_id:
                    raise PermitError("authorized target row changed before dispatch")
                if row.value != permit.source_hostname:
                    raise PermitError("authorized hostname changed before dispatch")
                if permit.destination_ip not in {
                    _safe_canon(a)
                    for a in dns_answers.get(permit.source_hostname, set())
                }:
                    raise PermitError(
                        "destination is not a current DNS answer for the "
                        "authorized hostname (possible rebind)"
                    )
                # Q1: re-verify the resolved address is itself inside the
                # checkpoint-acknowledged address space, not merely resolved
                # from an authorized name.
                if not await snapshot_authorizes_ip(
                    session, permit.authorization_snapshot_id, permit.destination_ip
                ):
                    raise PermitError(
                        "destination is outside the checkpoint-acknowledged "
                        "address space (Q1)"
                    )
                decision = scope_classifier(
                    permit.source_hostname, resolved_ips=[permit.destination_ip]
                )

            if getattr(decision, "status", None) is not ScopeStatus.IN_SCOPE:
                raise PermitError(
                    f"destination {permit.destination_ip} is no longer in scope "
                    f"({getattr(decision, 'status', None)})"
                )

            if persisted_killswitch_engaged is not None and await (
                persisted_killswitch_engaged(session)
            ):
                raise PermitError("persisted kill switch engaged; no dispatch")

    return check
