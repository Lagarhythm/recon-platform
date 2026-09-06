"""ActiveTargetPermit: frozen, not caller-constructible, self-validating (G0 Part 3)."""

from __future__ import annotations

import time
from dataclasses import FrozenInstanceError

import pytest

from recon.net.permit import (
    ActiveTargetPermit,
    PermitError,
    is_genuine_permit,
    mint_permit,
)

_BASE = {
    "destination_ip": "203.0.113.5",
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
    "policy_version": "p1",
    "liveness_attestation_id": None,
}


def test_direct_construction_is_rejected() -> None:
    with pytest.raises(PermitError):
        ActiveTargetPermit(**_BASE)


def test_mint_permit_produces_a_genuine_permit() -> None:
    p = mint_permit(**_BASE)
    assert isinstance(p, ActiveTargetPermit)
    assert is_genuine_permit(p)
    assert p.permit_id and p.dispatch_nonce
    assert not p.is_expired


def test_permit_is_frozen() -> None:
    p = mint_permit(**_BASE)
    with pytest.raises(FrozenInstanceError):
        p.destination_ip = "10.0.0.1"  # type: ignore[misc]


def test_is_genuine_permit_false_for_impostors() -> None:
    assert not is_genuine_permit("203.0.113.5")
    assert not is_genuine_permit(object())

    class FakePermit:
        _mint_key = object()

    assert not is_genuine_permit(FakePermit())


def test_exactly_one_authorization_reference_required() -> None:
    with pytest.raises(PermitError):
        mint_permit(**{**_BASE, "authorized_cidr_id": "c-1"})  # both set
    with pytest.raises(PermitError):
        mint_permit(
            **{
                **_BASE,
                "authorized_target_id": None,  # neither set
                "source_hostname": None,
            }
        )


def test_cidr_permit_needs_parent_cidr_and_target_permit_needs_hostname() -> None:
    with pytest.raises(PermitError):
        mint_permit(
            **{
                **_BASE,
                "authorized_target_id": None,
                "source_hostname": None,
                "authorized_cidr_id": "c-1",
                "parent_authorized_cidr": None,
            }
        )
    with pytest.raises(PermitError):
        mint_permit(**{**_BASE, "source_hostname": None})


def test_unknown_operation_rejected() -> None:
    with pytest.raises(PermitError):
        mint_permit(**{**_BASE, "operation": "exfiltrate"})


def test_port_scan_permit_requires_attestation() -> None:
    with pytest.raises(PermitError):
        mint_permit(**{**_BASE, "operation": "port_scan"})
    ok = mint_permit(
        **{
            **_BASE,
            "operation": "port_scan",
            "effective_argv_shape": ("nmap", "__DESTINATION__"),
            "liveness_attestation_id": "att-1",
        }
    )
    assert ok.operation == "port_scan"


def test_expiry_is_monotonic_deadline() -> None:
    p = mint_permit(**{**_BASE, "expires_at": time.monotonic() - 1})
    assert p.is_expired
