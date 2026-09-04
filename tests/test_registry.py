"""Module registry: phase ordering (osint -> passive -> active) and dep rules."""

from __future__ import annotations

import pytest

from recon.models.enums import MODULE_PHASE_RANK, ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import MODULES, load_builtin_modules, resolve_order


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


def test_every_real_module_resolves_and_respects_phase_ranking():
    """resolve_order over the *actual* registered module set - catches a module
    that declares a dependency in a later phase (which the synthetic fixtures
    above cannot). This class of bug must fail here, not at scan time."""
    load_builtin_modules()
    names = sorted(MODULES)
    assert names, "no modules registered"

    # every dependency edge points to the same or an earlier phase
    for name in names:
        for dep in MODULES[name].depends_on:
            if dep not in MODULES:
                continue
            assert MODULE_PHASE_RANK[MODULES[dep].phase] <= MODULE_PHASE_RANK[MODULES[name].phase], (
                f"{name} ({MODULES[name].phase.value}) depends on "
                f"{dep} ({MODULES[dep].phase.value}) - a later phase"
            )

    # the whole set resolves, and the result is phase-ordered
    ordered = resolve_order(names)
    ranks = [MODULE_PHASE_RANK[m.phase] for m in ordered]
    assert ranks == sorted(ranks)
    assert {m.name for m in ordered} == set(names)

    # and each module resolves on its own (pulls its deps, no phase violation)
    for name in names:
        resolve_order([name])
