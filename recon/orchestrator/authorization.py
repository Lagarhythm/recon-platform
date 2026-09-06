"""Active-checkpoint authorization snapshot creation (P0-1 / G2 "checkpoint
persistence").

When a run with active modules passes the passive->active checkpoint, this
writes the one immutable :class:`~recon.models.authz.AuthorizationSnapshot` that
every later permit is bound to, plus:

* an :class:`~recon.models.authz.AuthorizedTarget` row for each exact in-scope
  hostname (D0 - ``dns_connect_bind_v1``);
* an :class:`~recon.models.authz.AuthorizedCidr` row for each exact canonical
  in-scope RoE CIDR.

The CIDR rows exist **only** so D0 can check that a hostname's resolved IP falls
inside a checkpoint-acknowledged network before it connect-binds (Security G2
re-review, Q1). No expansion, manifest, or CIDR host-discovery happens here or
anywhere in G2 - those remain disabled in ``BOOTSTRAP_POLICY`` and are G3's. The
discovery prefix ceiling (/24, /120, aggregate 256) is applied by G3 when it
selects rows for expansion, not at persistence: the acknowledged RoE is recorded
as-is.

Actor identity: ``confirmed_by_user_id`` if the caller supplies one, else the
sole ``User`` row. If more than one user exists and no id was supplied this
raises - a wrong actor on an authorization record is exactly what the
multi-operator authorization model (not built) has to prevent, so the
single-operator assumption is made self-enforcing (F4, Security re-review).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.active_policy import BOOTSTRAP_POLICY
from recon.core.netscope import NetscopeError, canonical_cidr
from recon.core.roe import RoEConfig
from recon.models.authz import (
    AuthorizationSnapshot,
    AuthorizedCidr,
    AuthorizedTarget,
)
from recon.models.base import utcnow
from recon.models.scanrun import ScanRun
from recon.models.user import User


class AuthorizationError(RuntimeError):
    """The active-scan authorization snapshot could not be created."""


def _canonical(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _scope_policy_hash(roe: RoEConfig) -> str:
    """sha256 over just the {in_scope, excluded, authorized_window} subset - a
    scope/exclusion edit invalidates an in-flight authorization, an unrelated
    RoE edit does not (G0 Section 2.1)."""
    window = roe.engagement.authorized_window
    subset = {
        "in_scope": {
            "domains": sorted(roe.scope.in_scope.domains),
            "cidrs": sorted(roe.scope.in_scope.cidrs),
            "hosts": sorted(roe.scope.in_scope.hosts),
        },
        "excluded": {
            "domains": sorted(roe.scope.excluded.domains),
            "cidrs": sorted(roe.scope.excluded.cidrs),
            "hosts": sorted(roe.scope.excluded.hosts),
        },
        "authorized_window": (
            None
            if window is None
            else {"start": window.start.isoformat(), "end": window.end.isoformat()}
        ),
    }
    return hashlib.sha256(_canonical(subset)).hexdigest()


def _authorized_cidrs(roe: RoEConfig) -> list[str]:
    """The exact in-scope RoE CIDRs in canonical form, deduplicated and sorted.

    The RoE loader already masks host bits (``strict=False``); routing through
    the single netscope canonicaliser keeps one component in charge of the form.
    A value that still will not canonicalise is a fail-closed error - we do not
    let the operator "acknowledge" a CIDR set we could not fully record.
    """
    out: set[str] = set()
    for raw in roe.scope.in_scope.cidrs:
        if not raw:
            continue
        try:
            out.add(canonical_cidr(raw))
        except NetscopeError as exc:
            raise AuthorizationError(
                f"in-scope CIDR {raw!r} is not canonical: {exc}"
            ) from exc
    return sorted(out)


def _checkpoint_payload(roe: RoEConfig, hostnames: list[str], cidrs: list[str]) -> dict:
    """Exactly what the operator is acknowledging (Security invariant 7)."""
    p = BOOTSTRAP_POLICY
    return {
        "schema": "recon.active_checkpoint.v1",
        "policy_version": p.version,
        "authorized_hostnames": sorted(hostnames),
        "authorized_cidrs": sorted(cidrs),  # membership-check only; no discovery
        "methods": sorted(p.method_allowlist),
        "per_method_ports": {k: list(v) for k, v in sorted(p.per_method_ports.items())},
        "per_method_rate": dict(sorted(p.per_method_rate.items())),
        "per_method_concurrency": dict(sorted(p.per_method_concurrency.items())),
        "max_addresses_per_run": p.max_addresses_per_run,
        "probe_timeout_seconds": p.probe_timeout_seconds,
        "total_time_budget_seconds": p.total_time_budget_seconds,
        "max_retries": p.max_retries,
        "excluded": {
            "domains": sorted(roe.scope.excluded.domains),
            "cidrs": sorted(roe.scope.excluded.cidrs),
            "hosts": sorted(roe.scope.excluded.hosts),
        },
    }


async def _resolve_actor(session: AsyncSession, confirmed_by_user_id: str | None) -> str:
    if confirmed_by_user_id is not None:
        exists = await session.get(User, confirmed_by_user_id)
        if exists is None:
            raise AuthorizationError(
                f"confirming user {confirmed_by_user_id} does not exist"
            )
        return confirmed_by_user_id
    count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
    if count == 1:
        return (await session.execute(select(User.id))).scalar_one()
    raise AuthorizationError(
        f"active-checkpoint actor is ambiguous ({count} users, none supplied); "
        "pass confirmed_by_user_id - the multi-operator authorization model is "
        "not implemented"
    )


async def get_active_snapshot(
    session: AsyncSession, scan_run_id: str
) -> AuthorizationSnapshot | None:
    return (
        await session.execute(
            select(AuthorizationSnapshot).where(
                AuthorizationSnapshot.scan_run_id == scan_run_id
            )
        )
    ).scalar_one_or_none()


async def create_active_snapshot(
    session: AsyncSession,
    run: ScanRun,
    roe: RoEConfig,
    *,
    confirmed_by_user_id: str | None = None,
    flow: str = "interactive",
) -> AuthorizationSnapshot:
    """Create (or return the existing) authorization snapshot for ``run``.

    Idempotent: a run has at most one snapshot (enforced by
    ``uq_authz_snapshot_id_run`` only at the id level, so we guard here too).
    The caller owns the transaction.
    """
    existing = await get_active_snapshot(session, run.id)
    if existing is not None:
        return existing

    if flow not in ("interactive", "pre_authorized"):
        raise AuthorizationError(f"unknown checkpoint flow {flow!r}")

    actor_id = await _resolve_actor(session, confirmed_by_user_id)
    hostnames = sorted({h.strip().lower().rstrip(".") for h in roe.scope.in_scope.hosts if h})
    cidrs = _authorized_cidrs(roe)
    payload = _checkpoint_payload(roe, hostnames, cidrs)

    snapshot = AuthorizationSnapshot(
        scan_run_id=run.id,
        engagement_id=run.engagement_id,
        roe_config_hash=run.roe_config_hash,
        scope_policy_hash=_scope_policy_hash(roe),
        authorized_by_user_id=actor_id,
        authorized_at=utcnow(),
        checkpoint_ack_hash=hashlib.sha256(_canonical(payload)).hexdigest(),
        checkpoint_payload=payload,
        flow=flow,
        policy_version=BOOTSTRAP_POLICY.version,
    )
    session.add(snapshot)
    await session.flush()

    for hostname in hostnames:
        session.add(
            AuthorizedTarget(
                snapshot_id=snapshot.id,
                target_type="hostname",
                value=hostname,
                source="roe_host",
            )
        )
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr)
        session.add(
            AuthorizedCidr(
                snapshot_id=snapshot.id,
                cidr=cidr,
                ip_version=net.version,
                # informational only in G2 (membership check does not expand);
                # clamp so a wide IPv6 grant cannot overflow a 64-bit column.
                address_count=min(net.num_addresses, 2**63 - 1),
                source="roe_cidr",
            )
        )
    await session.flush()
    return snapshot
