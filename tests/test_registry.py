"""Module registry: phase ordering (osint -> passive -> active) and dep rules."""

from __future__ import annotations

import pytest

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES, resolve_order


def _mk(name, phase, deps=()):
    async def _run(self, ctx: ModuleContext) -> None:  # noqa: ANN001
        return None

    return type(name, (ReconModule,), {
        "name": name, "phase": phase, "depends_on": tuple(deps),
        "description": "test", "run": _run,
    })()


@pytest.fixture
def fakes():
    mods = {
        "t_osint": _mk("t_osint", ModulePhase.OSINT),
        "t_passive": _mk("t_passive", ModulePhase.PASSIVE, ["t_osint"]),
        "t_active": _mk("t_active", ModulePhase.ACTIVE, ["t_passive"]),
    }
    for n, m in mods.items():
        MODULES[n] = m
    yield mods
    for n in mods:
        MODULES.pop(n, None)


def test_phase_order_is_osint_then_passive_then_active(fakes):
    ordered = [m.name for m in resolve_order(["t_active", "t_passive", "t_osint"])]
    assert ordered == ["t_osint", "t_passive", "t_active"]


def test_missing_earlier_phase_deps_are_pulled_in(fakes):
    ordered = [m.name for m in resolve_order(["t_active"])]
    assert ordered == ["t_osint", "t_passive", "t_active"]


def test_depending_on_a_later_phase_is_rejected(fakes):
    MODULES["t_bad"] = _mk("t_bad", ModulePhase.OSINT, ["t_passive"])
    try:
        with pytest.raises(ValueError, match="later phase"):
            resolve_order(["t_bad"])
    finally:
        MODULES.pop("t_bad", None)
