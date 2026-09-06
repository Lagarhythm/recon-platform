"""The opaque active-scan permit (P0-1 / G0 Part 3).

An :class:`ActiveTargetPermit` is the only thing :class:`~recon.net.active_executor.ActiveExecutor`
will act on. It is:

* **not a DB row** - what was permitted is persisted as an
  ``AddressAudit`` row keyed by ``permit_id``;
* **frozen** - no field can be rewritten after minting;
* **not caller-constructible** - ``ActiveTargetPermit(...)`` raises
  :class:`PermitError` unless the module-private mint key is supplied, which only
  :func:`mint_permit` (called from ``ActivePermitResolver``) does;
* **single-use and time-boxed** - ``dispatch_nonce`` is consumed by the executor
  and ``expires_at`` is a ``time.monotonic()`` deadline.

Every authorization field is FK-backed and denormalised straight off the row the
resolver verified, so the executor's dispatch-time re-check compares against
persisted values, not free strings.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

# Module-private. A permit is "genuine" iff it carries this exact object.
_MINT_KEY: object = object()

_VALID_OPERATIONS = frozenset(
    {"host_discovery", "port_scan", "dns_connect_bind"}
)

# Default lifetime of a freshly minted permit, in seconds of monotonic time.
DEFAULT_PERMIT_TTL_SECONDS = 120.0


class PermitError(RuntimeError):
    """Raised whenever the executor is handed anything that is not a live, valid,
    single-use permit - or when a permit is constructed outside the resolver."""


class PermitRevokedError(PermitError):
    """The authorization snapshot backing this permit was revoked or superseded
    between mint and dispatch (F8 / Q2).

    Distinct from a plain :class:`PermitError` so the caller can record a
    ``cancelled`` disposition - a revoked authorization is not the same as an
    out-of-scope target, and conflating them degrades forensic interpretation.
    ``reason`` is ``"revoked"`` or ``"superseded"``.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ActiveTargetPermit:
    destination_ip: str
    """Canonical single address - never a CIDR, never a hostname."""

    operation: str
    method_profile_id: str
    effective_argv_shape: tuple[str, ...]
    """Arg template the executor fills with ``destination_ip`` only; audited."""

    scan_run_id: str
    scan_module_run_id: str
    module_name: str
    authorization_snapshot_id: str

    # --- B1: FK-backed, exclusive; exactly one *_id is non-None ---
    authorized_cidr_id: str | None
    authorized_target_id: str | None
    parent_authorized_cidr: str | None  # set iff authorized_cidr_id set
    source_hostname: str | None  # set iff authorized_target_id set

    checkpoint_ack_hash: str
    policy_version: str
    liveness_attestation_id: str | None  # required for operation == "port_scan"

    permit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    dispatch_nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    expires_at: float = field(
        default_factory=lambda: time.monotonic() + DEFAULT_PERMIT_TTL_SECONDS
    )

    # Guard: identity-checked, never compared or printed.
    _mint_key: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._mint_key is not _MINT_KEY:
            raise PermitError(
                "ActiveTargetPermit is not caller-constructible; a permit is "
                "minted only by ActivePermitResolver"
            )
        if self.operation not in _VALID_OPERATIONS:
            raise PermitError(f"unknown permit operation {self.operation!r}")
        cidr_set = self.authorized_cidr_id is not None
        target_set = self.authorized_target_id is not None
        if cidr_set == target_set:
            raise PermitError(
                "permit must carry exactly one of authorized_cidr_id / "
                "authorized_target_id"
            )
        if cidr_set and self.parent_authorized_cidr is None:
            raise PermitError("CIDR permit missing parent_authorized_cidr")
        if target_set and self.source_hostname is None:
            raise PermitError("target permit missing source_hostname")
        if self.operation == "port_scan" and self.liveness_attestation_id is None:
            raise PermitError("port_scan permit requires a liveness_attestation_id")

    @property
    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


def mint_permit(**kwargs: Any) -> ActiveTargetPermit:
    """Internal constructor used by ``ActivePermitResolver``. The mint key never
    leaves this module."""
    kwargs.pop("_mint_key", None)
    return ActiveTargetPermit(**kwargs, _mint_key=_MINT_KEY)


def is_genuine_permit(obj: object) -> bool:
    """True iff ``obj`` is an :class:`ActiveTargetPermit` that was minted here
    (carries the module-private key)."""
    return (
        isinstance(obj, ActiveTargetPermit)
        and object.__getattribute__(obj, "_mint_key") is _MINT_KEY
    )
