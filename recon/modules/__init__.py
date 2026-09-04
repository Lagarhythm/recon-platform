"""Recon modules.

Every module writes ONLY to the Evidence table, via ``ModuleContext``. The
Correlation Engine is the sole writer of Asset. A module never calls another
module and never touches scope-enforcement or audit logic directly - the
context and the shared HTTP client mediate all of that.
"""

from recon.modules.base import (
    ModuleContext,
    ModulePhaseType,
    ReconModule,
    ScanCancelled,
)
from recon.modules.registry import MODULES, get_module, iter_modules

__all__ = [
    "ReconModule",
    "ModuleContext",
    "ModulePhaseType",
    "ScanCancelled",
    "MODULES",
    "get_module",
    "iter_modules",
]
