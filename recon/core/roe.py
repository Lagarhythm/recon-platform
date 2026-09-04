"""Rules of Engagement: schema, loader, validator, canonical hashing.

The RoE file is the single source of truth for both scope and evasion
behaviour for an engagement. It is loaded at engagement creation, snapshotted,
and re-validated before every scan run.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from enum import Enum
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(\*\.)?([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_PLAIN_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,63}$"
)


class RoEError(ValueError):
    """Raised when an RoE document is structurally or semantically invalid."""


_MAX_ROE_BYTES = 256 * 1024


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses YAML anchors/aliases.

    RoE documents never need them, and forbidding them removes the
    'billion laughs' alias-bomb DoS entirely (the blow-up happens when a
    shared anchored node is expanded during construction).
    """

    def compose_node(self, parent, index):  # noqa: ANN001
        if self.check_event(yaml.events.AliasEvent):
            raise RoEError("YAML anchors/aliases are not allowed in an RoE document")
        return super().compose_node(parent, index)


def _safe_load(raw_yaml: str) -> Any:
    if len(raw_yaml.encode("utf-8", errors="ignore")) > _MAX_ROE_BYTES:
        raise RoEError(f"RoE document exceeds {_MAX_ROE_BYTES // 1024} KB limit")
    try:
        return yaml.load(raw_yaml, Loader=_NoAliasSafeLoader)
    except RoEError:
        raise
    except yaml.YAMLError as exc:
        raise RoEError(f"RoE is not valid YAML: {exc}") from exc


class RotationStrategy(str, Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"


class AuthorizedWindow(BaseModel):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _check_order(self) -> AuthorizedWindow:
        if self.start >= self.end:
            raise ValueError("authorized_window.start must be before .end")
        return self


class EngagementMeta(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client: str = Field(min_length=1, max_length=200)
    authorized_window: AuthorizedWindow | None = None


class ScopeList(BaseModel):
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def _valid_domain_patterns(cls, v: list[str]) -> list[str]:
        for d in v:
            if not _HOSTNAME_RE.match(d.strip().lower()):
                raise ValueError(f"invalid domain pattern: {d!r}")
        return [d.strip().lower() for d in v]

    @field_validator("hosts")
    @classmethod
    def _valid_hosts(cls, v: list[str]) -> list[str]:
        for h in v:
            if not _PLAIN_HOST_RE.match(h.strip().lower()):
                raise ValueError(f"invalid host: {h!r} (wildcards not allowed here)")
        return [h.strip().lower() for h in v]

    @field_validator("cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        normalized = []
        for c in v:
            try:
                net = ipaddress.ip_network(c.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR: {c!r} ({exc})") from exc
            normalized.append(str(net))
        return normalized


class Scope(BaseModel):
    in_scope: ScopeList = Field(default_factory=ScopeList)
    excluded: ScopeList = Field(default_factory=ScopeList)

    @property
    def is_empty(self) -> bool:
        return not (self.in_scope.domains or self.in_scope.cidrs or self.in_scope.hosts)


class RateLimits(BaseModel):
    max_requests_per_second: float = Field(default=10, gt=0, le=1000)
    max_concurrent_connections: int = Field(default=20, gt=0, le=1000)


class Jitter(BaseModel):
    enabled: bool = True
    min_ms: int = Field(default=100, ge=0, le=120_000)
    max_ms: int = Field(default=1500, ge=0, le=120_000)

    @model_validator(mode="after")
    def _order(self) -> Jitter:
        if self.min_ms > self.max_ms:
            raise ValueError("jitter.min_ms must be <= jitter.max_ms")
        return self


class Evasion(BaseModel):
    jitter: Jitter = Field(default_factory=Jitter)
    user_agents: list[str] = Field(default_factory=list)
    rotation_strategy: RotationStrategy = RotationStrategy.ROUND_ROBIN

    @field_validator("user_agents")
    @classmethod
    def _sane_uas(cls, v: list[str]) -> list[str]:
        return [ua.strip() for ua in v if ua.strip()]


class LLMPolicy(BaseModel):
    """Per-engagement control on shipping recon data to the remote LLM endpoint."""

    analysis_enabled: bool = False


class OSINTPolicy(BaseModel):
    """Company / organisation OSINT. When enabled, an engagement may omit
    ``scope`` entirely (OSINT-only) - the OSINT modules only query third-party
    public sources, never the target's own infrastructure.

    ``seed_domains`` are pivot points for the OSINT modules; they are NOT added
    to scan scope. To also scan a domain, list it under ``scope.in_scope``.
    """

    enabled: bool = False
    company: str = Field(default="", max_length=200)
    seed_domains: list[str] = Field(default_factory=list)
    github_org: str | None = None

    @field_validator("seed_domains")
    @classmethod
    def _valid_seed_domains(cls, v: list[str]) -> list[str]:
        out = []
        for d in v:
            d = d.strip().lower().strip(".")
            if d and not _PLAIN_HOST_RE.match(d):
                raise ValueError(f"invalid seed domain: {d!r}")
            if d:
                out.append(d)
        return out

    @model_validator(mode="after")
    def _has_a_pivot(self) -> OSINTPolicy:
        if self.enabled and not (self.company or self.seed_domains or self.github_org):
            raise ValueError(
                "osint.enabled requires a company name, seed_domains, or github_org"
            )
        return self


class RoEConfig(BaseModel):
    engagement: EngagementMeta
    scope: Scope = Field(default_factory=Scope)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    evasion: Evasion = Field(default_factory=Evasion)
    llm: LLMPolicy = Field(default_factory=LLMPolicy)
    osint: OSINTPolicy = Field(default_factory=OSINTPolicy)

    @model_validator(mode="after")
    def _has_a_target(self) -> RoEConfig:
        if self.scope.is_empty and not self.osint.enabled:
            raise ValueError(
                "engagement needs an in-scope target (scope.in_scope) or "
                "osint.enabled with a company / seed_domains"
            )
        return self


def _hash_data(data: Any) -> str:
    canonical = json.dumps(data or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_hash(raw_yaml: str) -> str:
    """Format-insensitive hash of an RoE document.

    Parses the YAML and re-serialises it deterministically so that whitespace,
    comment, and key-order changes do not alter the hash - only a semantic
    change to the scope/evasion does.
    """
    return _hash_data(_safe_load(raw_yaml))


def load_roe(raw_yaml: str) -> tuple[RoEConfig, str]:
    """Parse and validate an RoE document. Returns (config, canonical_hash)."""
    data: Any = _safe_load(raw_yaml)  # size- and alias-guarded, single parse
    if not isinstance(data, dict):
        raise RoEError("RoE root must be a mapping")
    try:
        config = RoEConfig.model_validate(data)
    except RoEError:
        raise
    except Exception as exc:  # pydantic ValidationError -> friendlier surface
        raise RoEError(str(exc)) from exc
    return config, _hash_data(data)
