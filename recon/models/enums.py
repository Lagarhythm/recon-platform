"""Shared enumerations for the data model.

Stored as plain strings in the DB (native_enum=False at the column) so that
adding a value later is a code change, not a migration on every backend.
"""

from __future__ import annotations

import enum

import sqlalchemy as sa


def enum_col(enum_cls: type[enum.Enum]) -> sa.Enum:
    """A VARCHAR-backed enum column that stores the ``.value`` string and hands
    back an enum member on read.

    ``native_enum=False`` keeps it portable (plain VARCHAR on every backend);
    ``values_callable`` stores ``"active"`` rather than ``"ACTIVE"``;
    ``create_constraint=False`` skips the CHECK so adding an enum value later
    is a code change, not a migration.
    """
    return sa.Enum(
        enum_cls,
        native_enum=False,
        create_constraint=False,
        length=32,
        values_callable=lambda cls: [m.value for m in cls],
    )


class EngagementStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    SERVICE = "service"
    FINDING = "finding"
    # OSINT phase - intelligence about an organisation, not a scannable target.
    ORGANIZATION = "organization"
    PERSON = "person"
    EMAIL = "email"
    REPOSITORY = "repository"
    NETBLOCK = "netblock"
    DOCUMENT = "document"
    SOCIAL = "social"


class InterestLevel(str, enum.Enum):
    """Independent of confidence. Confidence answers 'does this asset exist';
    interest answers 'should the analyst care'."""

    INFORMATIONAL = "informational"
    NOTABLE = "notable"
    HIGH_VALUE = "high_value"


class ScopeStatus(str, enum.Enum):
    IN_SCOPE = "in_scope"
    FLAGGED = "flagged"
    EXCLUDED = "excluded"
    # Outbound request to a third-party OSINT source (crt.sh, a public
    # resolver) that is not itself an engagement target.
    NOT_APPLICABLE = "n/a"


class FindingPolarity(str, enum.Enum):
    """Positive discovery vs. recorded absence of a control (negative evidence)."""

    PRESENT = "present"
    ABSENT = "absent"


class RelationshipType(str, enum.Enum):
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    DISCOVERED_VIA = "discovered_via"
    SUBDOMAIN_OF = "subdomain_of"
    SERVES = "serves"
    # OSINT
    OWNS = "owns"
    EMPLOYED_BY = "employed_by"
    AUTHORED = "authored"


class ScanRunStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"          # operator-initiated or checkpoint hold
    AWAITING_CHECKPOINT = "awaiting_checkpoint"  # passive done, active pending sign-off


class ModulePhase(str, enum.Enum):
    OSINT = "osint"        # third-party sources only, no target contact; runs first
    PASSIVE = "passive"
    ACTIVE = "active"


#: phase ordering rank - a module may not depend on a higher-ranked phase
MODULE_PHASE_RANK: dict[ModulePhase, int] = {
    ModulePhase.OSINT: 0,
    ModulePhase.PASSIVE: 1,
    ModulePhase.ACTIVE: 2,
}


class ModuleRunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"       # already completed in a prior run (resumability)


class WindowStatus(str, enum.Enum):
    NO_WINDOW = "no_window"
    WITHIN = "within"
    BEFORE = "before"
    AFTER = "after"
