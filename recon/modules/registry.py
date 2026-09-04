"""Module registry + dependency-aware, passive-first ordering."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from recon.models.enums import MODULE_PHASE_RANK, ModulePhase
from recon.modules.base import ReconModule

MODULES: dict[str, ReconModule] = {}


def register(cls: type[ReconModule]) -> type[ReconModule]:
    instance = cls()
    if not instance.name:
        raise ValueError(f"{cls.__name__} has no name")
    if instance.name in MODULES:
        raise ValueError(f"duplicate module name: {instance.name}")
    MODULES[instance.name] = instance
    return cls


def get_module(name: str) -> ReconModule:
    return MODULES[name]


def iter_modules() -> Iterator[ReconModule]:
    yield from MODULES.values()


def resolve_order(names: Iterable[str]) -> list[ReconModule]:
    """Topological sort of the requested modules by ``depends_on``, with all
    passive modules ordered ahead of all active ones.

    Missing dependencies are pulled in automatically. Raises on a cycle.
    """
    wanted: set[str] = set()

    def _pull(n: str, *, required: bool) -> None:
        if n in wanted:
            return
        if n not in MODULES:
            if required:
                raise KeyError(f"unknown module: {n}")
            return  # optional dependency not installed - skip quietly
        wanted.add(n)
        for dep in MODULES[n].depends_on:
            _pull(dep, required=False)

    for name in names:
        _pull(name, required=True)

    # A module may not depend on one in a later phase - that would break the
    # osint -> passive -> checkpoint -> active ordering.
    for n in wanted:
        for dep in MODULES[n].depends_on:
            if MODULE_PHASE_RANK[MODULES[dep].phase] > MODULE_PHASE_RANK[MODULES[n].phase]:
                raise ValueError(
                    f"{MODULES[n].phase.value} module {n!r} depends on "
                    f"{MODULES[dep].phase.value} module {dep!r} (later phase)"
                )

    def _toposort(subset: set[str]) -> list[str]:
        out: list[str] = []
        visiting: set[str] = set()

        def _visit(n: str) -> None:
            if n in out:
                return
            if n in visiting:
                raise ValueError(f"dependency cycle involving {n}")
            visiting.add(n)
            for dep in sorted(MODULES[n].depends_on):
                if dep in subset:
                    _visit(dep)
            visiting.discard(n)
            out.append(n)

        for n in sorted(subset):
            _visit(n)
        return out

    by_phase: dict[ModulePhase, set[str]] = {p: set() for p in ModulePhase}
    for n in wanted:
        by_phase[MODULES[n].phase].add(n)
    ordered: list[str] = []
    for phase in sorted(ModulePhase, key=lambda p: MODULE_PHASE_RANK[p]):
        ordered += _toposort(by_phase[phase])
    return [MODULES[n] for n in ordered]


def load_builtin_modules() -> None:
    """Import module packages so their ``@register`` decorators fire."""
    from recon.modules import active, osint, passive  # noqa: F401
