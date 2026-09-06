"""Same-run target resolution for active modules.

The P1 assessment found two pipeline defects that both come down to *how an
active module learns what to act on*:

* **P0-2** - an active module read the correlated Asset graph, but correlation
  only runs at the passive->active checkpoint pause and at end of run. With the
  checkpoint pre-authorised (``scan start --yes-active``) there is no pause, so a
  passive dependency's output never reaches its dependent active module in the
  same run.
* **P0-1** - a CIDR-only RoE produced no targets at all and the run still went
  green, indistinguishable from a clean scan.

``resolve_targets`` is the single seam that fixes both. It builds an active
module's target set from **current-run Evidence** (which carries
``scan_run_id`` + ``source_module``) plus RoE-declared hosts/domains, optionally
folding in prior correlated Assets - and it applies scope and safe-form
filtering centrally, so an EXCLUDED target or a crafted "``-oX /etc/x``" string
can never reach an active module's argv. When it returns nothing eligible the
caller marks the run ``SKIPPED`` / ``zero_eligible_targets`` instead of a
misleading green ``COMPLETED``.

The Correlation Engine stays the only writer of ``Asset``; this module only
reads.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select

from recon.models.asset import Asset
from recon.models.enums import AssetType, FindingPolarity, ScopeStatus
from recon.models.evidence import Evidence

if TYPE_CHECKING:
    from recon.modules.base import ModuleContext

# --- accepted logical target types ---------------------------------------
IP = "ip"
HOSTNAME = "hostname"
URL = "url"
_ACCEPT_TYPES = frozenset({IP, HOSTNAME, URL})

# --- source provenance kinds -------------------------------------------
SRC_ROE_HOST = "roe_host"
SRC_ROE_DOMAIN = "roe_domain"
SRC_ROE_CIDR = "roe_cidr"
SRC_CURRENT_DNS = "current_run_dns"
SRC_CURRENT_DISCOVERY = "current_run_discovery"
SRC_CURRENT_WEB = "current_run_web"
SRC_PRIOR_ASSET = "prior_asset"

# --- disposition reasons for excluded candidates -----------------------
EXC_EXPLICIT = "excluded_explicit"          # RoE EXCLUDED - never touched
EXC_OUT_OF_SCOPE = "excluded_out_of_scope"  # FLAGGED and no run override
EXC_UNSAFE_FORM = "unsafe_form"             # not a bare IP / hostname / URL root
EXC_UNACCOUNTED_CIDR = "unaccounted_cidr"   # in-scope CIDR with no host discovery

_HOSTNAME_RE = re.compile(r"^(?![-.])[A-Za-z0-9_.-]{1,253}(?<![-.])$")

# subject_types in Evidence that can name a scannable target
_TARGET_SUBJECT_TYPES = ("dns_record", "domain", "subdomain", "ip", "url", "endpoint",
                         "http_endpoint", "live_host")


# ======================================================================
# safe-form helpers - promoted from port_scan / dir_fuzz so every active
# module validates target shape the same way, applied centrally below.
# ======================================================================
def is_safe_target(value: str) -> bool:
    """A plain single IP or hostname - never an argv option, a shell metachar,
    or an over-broad network. Rejects ``-oX``, ``--script=...``, ``0.0.0.0/0``.
    Networks are allowed only up to /24 (v4) / /120 (v6) - an asset value is
    always a single host, so anything larger is a crafted value."""
    value = value.strip()
    if not value or value.startswith("-"):
        return False
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.version == 4:
            return net.prefixlen >= 24
        return net.prefixlen >= 120
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(value))


def safe_url_root(value: str) -> bool:
    """An ``http(s)://host[:port]/`` root with a safe host and no funny business."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    if any(c in value for c in (" ", "\t", "\n", "\r", "`", "$", "|", ";", "&")):
        return False
    return is_safe_target(parts.hostname)


def normalize_url_root(value: str) -> str:
    parts = urlsplit(value)
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, "/", "", ""))


# ======================================================================
# candidate + resolution types
# ======================================================================
@dataclass(frozen=True)
class TargetCandidate:
    value: str                      # normalized: bare IP, hostname, or URL root
    target_type: str                # IP | HOSTNAME | URL
    source_kind: str                # SRC_*
    source_module: str | None       # emitting module ("dns", "host_discovery", ...)
    source_evidence_id: str | None
    scan_run_id: str | None         # run that produced it; None for RoE / prior asset
    scope_status: ScopeStatus
    exclusion_reason: str | None = None
    resolved_ips: tuple[str, ...] = ()
    #: CONTRACT-PENDING (Security P0-1 gate §3): this becomes a structured
    #: ``LivenessAttestation``, not a bool. P0-2 consumers must NOT branch on
    #: it - it is provenance only for now. port_scan ignores it.
    verified_live: bool = False


@dataclass
class TargetResolution:
    eligible: list[TargetCandidate] = field(default_factory=list)
    excluded: list[TargetCandidate] = field(default_factory=list)

    def values(self) -> list[str]:
        return [c.value for c in self.eligible]

    def accounting(self, *, max_provenance: int = 25) -> dict:
        """Bounded, operator-safe summary for ``coverage_metadata`` and the run
        page. Values only (already in-scope, so safe to show); never raw
        evidence blobs."""
        by_disposition: Counter[str] = Counter()
        by_disposition["scanned"] = len(self.eligible)
        for c in self.excluded:
            by_disposition[c.exclusion_reason or "excluded_other"] += 1
        return {
            "eligible": len(self.eligible),
            "by_source": dict(Counter(c.source_kind for c in self.eligible)),
            "by_disposition": dict(by_disposition),
            "provenance": [
                {
                    "value": c.value,
                    "source_kind": c.source_kind,
                    "source_module": c.source_module,
                }
                for c in self.eligible[:max_provenance]
            ],
        }


# ======================================================================
# resolution
# ======================================================================
def _base_domain(pattern: str) -> str:
    p = pattern.strip().lower().rstrip(".")
    return p[2:] if p.startswith("*.") else p


def _canon_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _canon_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


class _RawCandidate:
    __slots__ = ("value", "target_type", "source_kind", "source_module",
                 "source_evidence_id", "scan_run_id", "resolved_ips", "verified_live")

    def __init__(self, value, target_type, source_kind, *, source_module=None,
                 source_evidence_id=None, scan_run_id=None, resolved_ips=(),
                 verified_live=False):  # noqa: ANN001
        self.value = value
        self.target_type = target_type
        self.source_kind = source_kind
        self.source_module = source_module
        self.source_evidence_id = source_evidence_id
        self.scan_run_id = scan_run_id
        self.resolved_ips = tuple(resolved_ips)
        self.verified_live = verified_live


def _evidence_source_kind(module: str | None, subject_type: str) -> str:
    if module == "host_discovery":
        return SRC_CURRENT_DISCOVERY
    if subject_type in ("url", "endpoint", "http_endpoint"):
        return SRC_CURRENT_WEB
    return SRC_CURRENT_DNS


def _raw_from_evidence(ev: Evidence) -> list[_RawCandidate]:
    st = ev.subject_type
    raw = ev.raw_data or {}
    kind = _evidence_source_kind(ev.source_module, st)
    verified = ev.source_module == "host_discovery" or bool(raw.get("nmap_state") == "up")
    out: list[_RawCandidate] = []

    if st == "dns_record":
        rtype = str(raw.get("rtype", "")).upper()
        name = _canon_host(raw.get("name") or ev.subject_value)
        if name:
            out.append(_RawCandidate(name, HOSTNAME, kind, source_module=ev.source_module,
                                     source_evidence_id=ev.id, scan_run_id=ev.scan_run_id))
        if rtype in ("A", "AAAA"):
            ip = _canon_ip(str(raw.get("value", "")))
            if ip:
                out.append(_RawCandidate(ip, IP, kind, source_module=ev.source_module,
                                         source_evidence_id=ev.id, scan_run_id=ev.scan_run_id))
                if out and out[0].target_type == HOSTNAME:
                    out[0].resolved_ips = (ip,)
        return out

    if st in ("domain", "subdomain", "live_host"):
        host = _canon_host(ev.subject_value)
        if host:
            rips = raw.get("resolved_ip") or raw.get("resolved_ips")
            rips = (rips,) if isinstance(rips, str) else tuple(rips or ())
            out.append(_RawCandidate(host, HOSTNAME, kind, source_module=ev.source_module,
                                     source_evidence_id=ev.id, scan_run_id=ev.scan_run_id,
                                     resolved_ips=rips, verified_live=verified))
        return out

    if st == "ip":
        ip = _canon_ip(ev.subject_value)
        if ip:
            out.append(_RawCandidate(ip, IP, kind, source_module=ev.source_module,
                                     source_evidence_id=ev.id, scan_run_id=ev.scan_run_id,
                                     verified_live=verified))
        return out

    if st in ("url", "endpoint", "http_endpoint"):
        if safe_url_root(ev.subject_value):
            out.append(_RawCandidate(normalize_url_root(ev.subject_value), URL, kind,
                                     source_module=ev.source_module,
                                     source_evidence_id=ev.id, scan_run_id=ev.scan_run_id))
        return out

    return out


def _raw_from_asset(a: Asset) -> _RawCandidate | None:
    if a.type is AssetType.IP:
        ip = _canon_ip(a.value)
        return _RawCandidate(ip, IP, SRC_PRIOR_ASSET) if ip else None
    if a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return _RawCandidate(_canon_host(a.value), HOSTNAME, SRC_PRIOR_ASSET)
    if a.type is AssetType.URL:
        if safe_url_root(a.value):
            return _RawCandidate(normalize_url_root(a.value), URL, SRC_PRIOR_ASSET)
    return None


async def resolve_targets(
    ctx: "ModuleContext",
    *accept_types: str,
    include_prior_assets: bool = False,
) -> TargetResolution:
    """Build an active module's target set for THIS scan run.

    ``accept_types`` is any of ``"ip"``, ``"hostname"``, ``"url"``. Sources, in
    order of trust:

    * RoE ``in_scope.hosts`` / ``in_scope.domains`` - always.
    * Current-run Evidence (``Evidence.scan_run_id == ctx.scan_run_id``) - the
      P0-2 fix: a dependency's same-run output is visible without waiting for
      correlation.
    * Prior correlated in-scope Assets (``include_prior_assets``, default off) -
      already scope-classified and confidence-scored by the Correlation Engine;
      tagged ``prior_asset`` so their inclusion shows in the run's provenance
      rather than entering silently.
    * RoE ``in_scope.cidrs`` with no covering host-discovery evidence become
      ``unaccounted_cidr`` entries in ``excluded`` - they drive the
      ``zero_eligible_targets`` no-input outcome until P0-1's ``host_discovery``
      module fills them in.

    Every candidate is scope-classified (EXCLUDED always dropped; FLAGGED
    dropped unless the run has an out-of-scope override) and safe-form checked
    centrally here.
    """
    accept = set(accept_types) or set(_ACCEPT_TYPES)
    unknown = accept - _ACCEPT_TYPES
    if unknown:
        raise ValueError(f"resolve_targets: unknown accept type(s) {sorted(unknown)}")

    roe = ctx.roe
    scope = ctx.scope
    allow_oos = ctx.allow_out_of_scope

    raws: list[_RawCandidate] = []

    # --- RoE-declared targets ----------------------------------------
    for h in roe.scope.in_scope.hosts:
        raws.append(_RawCandidate(_canon_host(h), HOSTNAME, SRC_ROE_HOST))
    for d in roe.scope.in_scope.domains:
        raws.append(_RawCandidate(_base_domain(d), HOSTNAME, SRC_ROE_DOMAIN))

    # --- current-run Evidence --------------------------------------
    rows = (
        await ctx._scalars(  # noqa: SLF001 - ctx exposes this for us
            select(Evidence).where(
                Evidence.engagement_id == ctx.engagement.id,
                Evidence.scan_run_id == ctx.scan_run_id,
                Evidence.is_error.is_(False),
                Evidence.polarity == FindingPolarity.PRESENT,
                Evidence.subject_type.in_(_TARGET_SUBJECT_TYPES),
            )
        )
    )
    for ev in rows:
        raws.extend(_raw_from_evidence(ev))

    # --- prior correlated Assets ---------------------------------
    if include_prior_assets:
        assets = (
            await ctx._scalars(  # noqa: SLF001
                select(Asset).where(
                    Asset.engagement_id == ctx.engagement.id,
                    Asset.type.in_(
                        [AssetType.IP, AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL]
                    ),
                )
            )
        )
        for a in assets:
            rc = _raw_from_asset(a)
            if rc is not None:
                raws.append(rc)

    # --- classify + filter each candidate ---------------------------
    # dedupe by (target_type, value); a current-run source outranks a prior
    # asset, an eligible outranks an excluded.
    best: dict[tuple[str, str], TargetCandidate] = {}
    excluded: dict[tuple[str, str], TargetCandidate] = {}

    def _rank(c: TargetCandidate) -> tuple[int, int]:
        cur = 0 if c.source_kind.startswith("current_run") else (
            1 if c.source_kind.startswith("roe_") else 2
        )
        return (0 if c.exclusion_reason is None else 1, cur)

    for rc in raws:
        if rc.target_type not in accept:
            continue
        value = rc.value
        if not value:
            continue

        is_url = rc.target_type == URL
        form_ok = safe_url_root(value) if is_url else is_safe_target(value)
        if not form_ok:
            cand = TargetCandidate(
                value=value, target_type=rc.target_type, source_kind=rc.source_kind,
                source_module=rc.source_module, source_evidence_id=rc.source_evidence_id,
                scan_run_id=rc.scan_run_id, scope_status=ScopeStatus.FLAGGED,
                exclusion_reason=EXC_UNSAFE_FORM, resolved_ips=rc.resolved_ips,
            )
            _stash(excluded, cand, _rank)
            continue

        decision = scope.classify(value, resolved_ips=list(rc.resolved_ips) or None)
        status = decision.status
        exclusion_reason: str | None = None
        if status is ScopeStatus.EXCLUDED:
            exclusion_reason = EXC_EXPLICIT
        elif status is ScopeStatus.FLAGGED and not allow_oos:
            exclusion_reason = EXC_OUT_OF_SCOPE

        cand = TargetCandidate(
            value=value, target_type=rc.target_type, source_kind=rc.source_kind,
            source_module=rc.source_module, source_evidence_id=rc.source_evidence_id,
            scan_run_id=rc.scan_run_id, scope_status=status,
            exclusion_reason=exclusion_reason, resolved_ips=rc.resolved_ips,
            verified_live=rc.verified_live,
        )
        if exclusion_reason is None:
            _stash(best, cand, _rank)
        else:
            _stash(excluded, cand, _rank)

    # --- unaccounted in-scope CIDRs ------------------------------
    if IP in accept:
        discovered_nets = [
            ipaddress.ip_network(f"{c.value}/32" if ":" not in c.value else f"{c.value}/128",
                                 strict=False)
            for c in best.values() if c.target_type == IP
        ]
        for cidr in roe.scope.in_scope.cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            covered = any(
                dn.version == net.version and dn.subnet_of(net) for dn in discovered_nets
            )
            if not covered:
                key = (SRC_ROE_CIDR, cidr)
                excluded[key] = TargetCandidate(
                    value=cidr, target_type="cidr", source_kind=SRC_ROE_CIDR,
                    source_module=None, source_evidence_id=None, scan_run_id=None,
                    scope_status=ScopeStatus.IN_SCOPE,
                    exclusion_reason=EXC_UNACCOUNTED_CIDR,
                )

    eligible_values = set(best.keys())
    return TargetResolution(
        eligible=sorted(best.values(), key=lambda c: (c.target_type, c.value)),
        excluded=sorted(
            (c for k, c in excluded.items() if k not in eligible_values),
            key=lambda c: (c.exclusion_reason or "", c.value),
        ),
    )


def _stash(store: dict, cand: TargetCandidate, rank) -> None:  # noqa: ANN001
    key = (cand.target_type, cand.value)
    cur = store.get(key)
    if cur is None or rank(cand) < rank(cur):
        store[key] = cand
