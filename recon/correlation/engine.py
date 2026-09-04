"""Correlation Engine - the only writer of Asset.

Takes the flat stream of Evidence a scan produced and folds it into the Asset
Graph: deduplicated entities, a confidence score from how many independent
sources agree, an interest level, a scope decision, and the relationships
between them. Idempotent - safe to run repeatedly (after the passive phase and
again at the end of a run).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.scope import ScopeManager, extract_host
from recon.models.asset import Asset, AssetRelationship
from recon.models.engagement import Engagement
from recon.models.enums import (
    AssetType,
    FindingPolarity,
    InterestLevel,
    RelationshipType,
    ScopeStatus,
)
from recon.models.evidence import Evidence

# subject_type -> the AssetType it materialises as
_SUBJECT_ASSET: dict[str, AssetType] = {
    "domain": AssetType.DOMAIN,
    "subdomain": AssetType.SUBDOMAIN,
    "ip": AssetType.IP,
    "url": AssetType.URL,
    "endpoint": AssetType.URL,
    "http_endpoint": AssetType.URL,
    "service": AssetType.SERVICE,
    # OSINT
    "organization": AssetType.ORGANIZATION,
    "person": AssetType.PERSON,
    "email": AssetType.EMAIL,
    "repository": AssetType.REPOSITORY,
    "netblock": AssetType.NETBLOCK,
    "document": AssetType.DOCUMENT,
    "social": AssetType.SOCIAL,
}

# OSINT asset types are intel about an org, never a scannable target.
_OSINT_ASSET_TYPES = frozenset({
    AssetType.ORGANIZATION, AssetType.PERSON, AssetType.EMAIL,
    AssetType.REPOSITORY, AssetType.NETBLOCK, AssetType.DOCUMENT, AssetType.SOCIAL,
})

# subject_types that describe an existing asset rather than being one
_ATTRIBUTE_TYPES = {
    "http_header",
    "security_header",
    "tls_cert",
    "cookie",
    "form",
    "tech",
    "robots",
    "sitemap",
    "http_method",
    "redirect",
    "title",
}

import re as _re

# Bump an asset to NOTABLE when one of these appears as a *token* in its value
# (a whole hostname label or path segment / filename) - not a loose substring,
# so "/skills/devsecops-engineer/..." doesn't get flagged for "dev".
_INTEREST_RE = _re.compile(
    r"(?:^|[/._\-])("
    r"admin|adminer|administrator|login|signin|logout|internal|intranet|"
    r"staging|preprod|uat|vpn|jenkins|gitlab|gitea|"
    r"phpmyadmin|grafana|kibana|jira|confluence|backup|backups|"
    r"legacy|deprecated|actuator|swagger|graphql|api|apis|private|secret|"
    r"upload|uploads|phpinfo|server-status|healthz|debug|portal|dashboard|"
    r"wp-admin|wp-login|\.git|\.svn|\.env|\.htpasswd|\.sql|\.bak"
    r")(?:$|[/._\-])",
    _re.IGNORECASE,
)

_NEGATIVE_INTEREST = {
    "dnssec": InterestLevel.NOTABLE,
    "spf": InterestLevel.NOTABLE,
    "dmarc": InterestLevel.NOTABLE,
    "security_header": InterestLevel.NOTABLE,
    "caa": InterestLevel.INFORMATIONAL,
}


@dataclass
class CorrelationSummary:
    assets_created: int = 0
    assets_updated: int = 0
    relationships_created: int = 0
    findings_created: int = 0
    evidence_processed: int = 0
    skipped_evidence: int = 0
    by_type: dict[str, int] = field(default_factory=dict)


def _canon_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _canon_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip().lower()


def _canon_url(value: str) -> str:
    value = str(value).strip()
    try:
        parts = urlsplit(value)
        scheme = (parts.scheme or "http").lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        # malformed URL (bad port, broken IPv6 literal) - fall back to raw
        return value.lower()[:1024]
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, host, path, parts.query, ""))


def _canon(asset_type: AssetType, value: str) -> str:
    if asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return _canon_host(value)
    if asset_type is AssetType.IP:
        return _canon_ip(value)
    if asset_type is AssetType.URL:
        return _canon_url(value)
    if asset_type in (AssetType.SERVICE, AssetType.EMAIL):
        return value.strip().lower()
    if asset_type is AssetType.NETBLOCK:
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError:
            return value.strip().lower()
    if asset_type is AssetType.ORGANIZATION:
        return " ".join(value.split()).lower()
    return value.strip()


def _confidence(distinct_sources: int) -> float:
    if distinct_sources <= 0:
        return 0.0
    return min(1.0, 0.5 + 0.25 * (distinct_sources - 1))


class CorrelationEngine:
    #: batch size for streaming engagement evidence through correlation. A
    #: large engagement's rows are consumed in these batches rather than
    #: materialised all at once (PRD Section 9: correlation memory).
    _EVIDENCE_CHUNK = 500

    async def correlate(
        self, session: AsyncSession, engagement: Engagement
    ) -> CorrelationSummary:
        scope = ScopeManager(_roe_of(engagement))
        summary = CorrelationSummary()

        # Phase A: stream every non-error evidence row in chunks and fold it
        # into the grouping. Streaming (not a single ``.scalars().all()``) means
        # the DB result is consumed in bounded batches instead of buffering the
        # whole engagement in memory at once.
        # (type, canonical_value) -> list[Evidence]
        groups: dict[tuple[AssetType, str], list[Evidence]] = defaultdict(list)
        # canonical_value(host/url) -> list[attribute Evidence]
        attributes: dict[str, list[Evidence]] = defaultdict(list)
        # explicit + derived relationship hints: (src_type, src_val, rel, tgt_type, tgt_val)
        rel_hints: set[tuple[str, str, str, str, str]] = set()

        summary.evidence_processed = await self._collect_evidence(
            session, engagement.id, groups, attributes, rel_hints, summary
        )

        # resolved-IP map for scope classification of hostnames
        resolved: dict[str, list[str]] = defaultdict(list)
        for (stype, sval, rel, ttype, tval) in rel_hints:
            if rel == RelationshipType.RESOLVES_TO.value and ttype == "ip":
                resolved[sval].append(tval)

        asset_ids: dict[tuple[AssetType, str], str] = {}

        for (atype, value), evs in groups.items():
            try:
                asset, created = await self._upsert_asset(
                    session, engagement.id, atype, value, evs, scope, resolved
                )
            except Exception:
                summary.skipped_evidence += len(evs)
                continue
            asset_ids[(atype, value)] = asset.id
            for ev in evs:
                ev.asset_id = asset.id
            summary.by_type[atype.value] = summary.by_type.get(atype.value, 0) + 1
            if atype is AssetType.FINDING:
                summary.findings_created += 1 if created else 0
            if created:
                summary.assets_created += 1
            else:
                summary.assets_updated += 1

        # attach attribute evidence to its parent asset
        for parent_ref, evs in attributes.items():
            parent_id = self._match_attribute_parent(parent_ref, asset_ids)
            if parent_id is None:
                # materialise a minimal parent so the evidence is not orphaned
                atype, cval = self._infer_parent_type(parent_ref)
                asset, _ = await self._upsert_asset(
                    session, engagement.id, atype, cval, [], scope, resolved
                )
                asset_ids[(atype, cval)] = asset.id
                parent_id = asset.id
            for ev in evs:
                ev.asset_id = parent_id

        summary.relationships_created = await self._materialise_relationships(
            session, engagement.id, rel_hints, asset_ids, scope, resolved
        )

        await session.flush()
        return summary

    # --- evidence collection (streamed) ----------------------------
    async def _collect_evidence(
        self, session, engagement_id, groups, attributes, rel_hints, summary
    ) -> int:  # noqa: ANN001
        """Stream the engagement's non-error evidence in bounded batches and
        route each row into the grouping. Returns the number of rows consumed.

        Streaming is fully consumed before ``correlate`` issues any further DB
        work (asset upserts), which is required on an AsyncSession.
        """
        stmt = (
            select(Evidence)
            .where(
                Evidence.engagement_id == engagement_id,
                Evidence.is_error.is_(False),
            )
            .order_by(Evidence.id)  # stable order for deterministic batching
        )
        processed = 0
        # ``stream_scalars().yield_per(N)`` buffers the result in chunks from the
        # driver instead of materialising the whole engagement into memory at
        # once (SQLAlchemy async does not support the synchronous yield_per).
        stream = await session.stream_scalars(
            stmt.execution_options(yield_per=self._EVIDENCE_CHUNK)
        )
        try:
            async for ev in stream:
                processed += 1
                try:
                    self._route_evidence(ev, groups, attributes, rel_hints, summary)
                except Exception:  # one malformed row must not sink the whole graph
                    summary.skipped_evidence += 1
        finally:
            await stream.close()
        return processed

    # --- evidence routing -----------------------------------------
    def _route_evidence(self, ev, groups, attributes, rel_hints, summary) -> None:  # noqa: ANN001
        st = ev.subject_type
        # explicit relationship hints travel in raw_data
        for hint in (ev.raw_data or {}).get("relationships", []) or []:
            try:
                rel_hints.add(
                    (
                        _asset_type_for(st).value if _asset_type_for(st) else st,
                        _canon(_asset_type_for(st) or AssetType.FINDING, ev.subject_value),
                        str(hint["type"]),
                        str(hint["target_type"]),
                        _canon(_type_from_name(hint["target_type"]), str(hint["target_value"])),
                    )
                )
            except (KeyError, TypeError):
                continue

        if ev.polarity is FindingPolarity.ABSENT:
            key = (AssetType.FINDING, f"{st}:{_canon_host(ev.subject_value)}")
            groups[key].append(ev)
            return

        if st == "secret":
            groups[(AssetType.FINDING, f"secret:{ev.subject_value}")].append(ev)
            return

        if st == "dns_record":
            self._derive_dns_relationships(ev, groups, rel_hints)
            return

        if st in _ATTRIBUTE_TYPES:
            raw = ev.raw_data or {}
            ref = raw.get("url") or raw.get("host") or ev.subject_value
            ref = str(ref)
            attributes[_canon_url(ref) if "://" in ref else _canon_host(ref)].append(ev)
            return

        atype = _SUBJECT_ASSET.get(st)
        if atype is None:
            groups[(AssetType.FINDING, f"{st}:{ev.subject_value}")].append(ev)
            return
        groups[(atype, _canon(atype, ev.subject_value))].append(ev)

        # a subdomain implies its parent domain + a subdomain_of edge
        if atype is AssetType.SUBDOMAIN:
            host = _canon_host(ev.subject_value)
            parent = (ev.raw_data or {}).get("parent")
            if not parent and host.count(".") >= 2:
                parent = host.split(".", 1)[1]
            if parent:
                rel_hints.add(
                    ("subdomain", host, RelationshipType.SUBDOMAIN_OF.value,
                     "domain", _canon_host(parent))
                )

    def _derive_dns_relationships(self, ev, groups, rel_hints) -> None:  # noqa: ANN001
        d = ev.raw_data or {}
        name = _canon_host(d.get("name", ev.subject_value))
        rtype = str(d.get("rtype", "")).upper()
        target = str(d.get("value", "")).strip()
        if not name or not target:
            return
        name_type = "subdomain" if name.count(".") >= 2 else "domain"
        groups[(AssetType(name_type), name)].append(ev)
        if rtype in ("A", "AAAA"):
            groups[(AssetType.IP, _canon_ip(target))].append(ev)
            rel_hints.add((name_type, name, RelationshipType.RESOLVES_TO.value,
                           "ip", _canon_ip(target)))
        elif rtype == "CNAME":
            tgt = _canon_host(target)
            groups[(AssetType.SUBDOMAIN if tgt.count(".") >= 2 else AssetType.DOMAIN, tgt)].append(ev)
            rel_hints.add((name_type, name, RelationshipType.RESOLVES_TO.value,
                           "subdomain", tgt))
        elif rtype == "MX":
            host = _canon_host(target.split()[-1]) if target else ""
            if host:
                groups[(AssetType.SUBDOMAIN if host.count(".") >= 2 else AssetType.DOMAIN, host)].append(ev)
                rel_hints.add((name_type, name, RelationshipType.SERVES.value,
                               "subdomain", host))

    # --- asset upsert -------------------------------------------
    async def _upsert_asset(
        self, session, engagement_id, atype, value, evs, scope, resolved
    ):  # noqa: ANN001
        existing = (
            await session.execute(
                select(Asset).where(
                    Asset.engagement_id == engagement_id,
                    Asset.type == atype,
                    Asset.value == value,
                )
            )
        ).scalar_one_or_none()

        distinct_sources = len({e.source_module for e in evs}) if evs else 0
        confidence = _confidence(distinct_sources) if evs else 0.3
        interest = self._interest(atype, value, evs)
        scope_status = self._classify(atype, value, scope, resolved)
        times = [e.discovered_at for e in evs if e.discovered_at]

        if existing is None:
            asset = Asset(
                engagement_id=engagement_id,
                type=atype,
                value=value,
                confidence_score=confidence,
                interest_level=interest,
                in_scope_status=scope_status,
            )
            if times:
                asset.first_seen = min(times)
                asset.last_seen = max(times)
            session.add(asset)
            await session.flush()
            return asset, True

        existing.confidence_score = max(existing.confidence_score, confidence)
        existing.interest_level = _max_interest(existing.interest_level, interest)
        existing.in_scope_status = scope_status
        if times:
            existing.last_seen = max([existing.last_seen, *times])
            existing.first_seen = min([existing.first_seen, *times])
        return existing, False

    def _interest(self, atype, value, evs) -> InterestLevel:  # noqa: ANN001
        hints = [
            (e.raw_data or {}).get("interest") for e in evs if (e.raw_data or {}).get("interest")
        ]
        best = InterestLevel.INFORMATIONAL
        for h in hints:
            try:
                best = _max_interest(best, InterestLevel(h))
            except ValueError:
                continue
        if atype is AssetType.FINDING and value.startswith("secret:"):
            return InterestLevel.HIGH_VALUE
        if atype is AssetType.FINDING:
            stype = value.split(":", 1)[0]
            best = _max_interest(best, _NEGATIVE_INTEREST.get(stype, InterestLevel.NOTABLE))
        if atype is AssetType.SERVICE:
            best = _max_interest(best, InterestLevel.NOTABLE)
        if atype in (AssetType.EMAIL, AssetType.DOCUMENT, AssetType.NETBLOCK):
            best = _max_interest(best, InterestLevel.NOTABLE)
        if _INTEREST_RE.search(value.lower()):
            best = _max_interest(best, InterestLevel.NOTABLE)
        return best

    def _classify(self, atype, value, scope, resolved) -> ScopeStatus:  # noqa: ANN001
        if atype is AssetType.FINDING or atype in _OSINT_ASSET_TYPES:
            return ScopeStatus.NOT_APPLICABLE
        if atype is AssetType.IP:
            return scope.classify(value).status
        if atype is AssetType.URL:
            host = extract_host(value)
            return scope.classify(host, resolved_ips=resolved.get(host, [])).status
        return scope.classify(value, resolved_ips=resolved.get(_canon_host(value), [])).status

    # --- attribute parent resolution ---------------------------
    def _match_attribute_parent(self, ref, asset_ids):  # noqa: ANN001
        if "://" in ref:
            key = (AssetType.URL, _canon_url(ref))
            if key in asset_ids:
                return asset_ids[key]
            ref = extract_host(ref)
        for atype in (AssetType.SUBDOMAIN, AssetType.DOMAIN, AssetType.IP):
            key = (atype, _canon(atype, ref))
            if key in asset_ids:
                return asset_ids[key]
        return None

    def _infer_parent_type(self, ref) -> tuple[AssetType, str]:  # noqa: ANN001
        if "://" in ref:
            return AssetType.URL, _canon_url(ref)
        host = _canon_host(ref)
        try:
            ipaddress.ip_address(host)
            return AssetType.IP, host
        except ValueError:
            pass
        return (AssetType.SUBDOMAIN if host.count(".") >= 2 else AssetType.DOMAIN), host

    # --- relationships ----------------------------------------
    async def _materialise_relationships(
        self, session, engagement_id, rel_hints, asset_ids, scope, resolved
    ) -> int:  # noqa: ANN001
        created = 0
        for (stype, sval, rel, ttype, tval) in rel_hints:
            try:
                rel_enum = RelationshipType(rel)
            except ValueError:
                continue
            src_id = await self._resolve_asset_id(
                session, engagement_id, stype, sval, asset_ids, scope, resolved
            )
            tgt_id = await self._resolve_asset_id(
                session, engagement_id, ttype, tval, asset_ids, scope, resolved
            )
            if not src_id or not tgt_id or src_id == tgt_id:
                continue
            exists = (
                await session.execute(
                    select(AssetRelationship.id).where(
                        AssetRelationship.source_asset_id == src_id,
                        AssetRelationship.target_asset_id == tgt_id,
                        AssetRelationship.relationship_type == rel_enum,
                    )
                )
            ).scalar_one_or_none()
            if exists:
                continue
            session.add(
                AssetRelationship(
                    engagement_id=engagement_id,
                    source_asset_id=src_id,
                    target_asset_id=tgt_id,
                    relationship_type=rel_enum,
                )
            )
            created += 1
        return created

    async def _resolve_asset_id(
        self, session, engagement_id, type_name, value, asset_ids, scope, resolved
    ):  # noqa: ANN001
        atype = _type_from_name(type_name)
        cval = _canon(atype, value)
        if (atype, cval) in asset_ids:
            return asset_ids[(atype, cval)]
        asset, _ = await self._upsert_asset(
            session, engagement_id, atype, cval, [], scope, resolved
        )
        asset_ids[(atype, cval)] = asset.id
        return asset.id


def _asset_type_for(subject_type: str) -> AssetType | None:
    return _SUBJECT_ASSET.get(subject_type)


def _type_from_name(name: str) -> AssetType:
    try:
        return AssetType(name)
    except ValueError:
        return AssetType.FINDING


_INTEREST_RANK = {
    InterestLevel.INFORMATIONAL: 0,
    InterestLevel.NOTABLE: 1,
    InterestLevel.HIGH_VALUE: 2,
}


def _max_interest(a: InterestLevel, b: InterestLevel) -> InterestLevel:
    return a if _INTEREST_RANK[a] >= _INTEREST_RANK[b] else b


def _roe_of(engagement: Engagement):
    from recon.core.roe import RoEConfig

    return RoEConfig.model_validate(engagement.roe_config)
