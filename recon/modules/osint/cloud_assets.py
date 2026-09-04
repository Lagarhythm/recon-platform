"""Cloud storage exposure discovery (OSINT).

Candidate bucket/container names are derived from the engagement's public
identity, then queried only at cloud-provider metadata/listing endpoints.
Object bodies are never requested or retained.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.osint._common import org_targets
from recon.modules.registry import register

_SUFFIXES = ("assets", "static", "media", "uploads", "backup", "backups", "files")
_MAX_CANDIDATES = 200


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def candidate_names(company: str, domains: list[str]) -> list[str]:
    """Generate conservative DNS-compatible public storage names."""
    roots: set[str] = set()
    if company:
        roots.add(_slug(company))
    for domain in domains:
        roots.add(_slug(domain))
        roots.add(domain.lower().replace(".", "-"))
    names: set[str] = set()
    for root in roots:
        root = root.strip("-")
        if not 3 <= len(root) <= 55:
            continue
        names.add(root)
        names.update(f"{root}-{suffix}" for suffix in _SUFFIXES)
    return sorted(name for name in names if 3 <= len(name) <= 63)[:_MAX_CANDIDATES]


@register
class CloudAssetsModule(ReconModule):
    name = "cloud_assets"
    phase = ModulePhase.OSINT
    depends_on = ()
    description = "Check derived public S3, GCS, and Azure storage names without reading objects"
    max_runtime_seconds = 15 * 60

    async def run(self, ctx: ModuleContext) -> None:
        company, domains = org_targets(ctx)
        candidates = candidate_names(company, domains)
        if not candidates:
            await ctx.progress("cloud_assets: no company or domain candidates")
            return
        await ctx.progress(f"cloud_assets: checking {len(candidates)} candidate name(s)")
        for index, name in enumerate(candidates, start=1):
            ctx.check_alive()
            await self._s3(ctx, name)
            await self._gcs(ctx, name)
            await self._azure(ctx, name)
            await ctx.progress(f"cloud_assets: {name}", current=index, total=len(candidates))

    async def _check(self, ctx: ModuleContext, *, provider: str, name: str, url: str) -> None:
        """Perform one metadata/list operation; 200 is publicly listable.

        A provider's 401/403 means the named resource may exist but is not
        publicly listable.  It is deliberately an informational finding, not
        a claim that its contents are accessible.
        """
        try:
            response = await ctx.http.request("GET", url, is_target=False, timeout=30.0)
        except Exception as exc:  # noqa: BLE001 - one provider must not stop the scan
            await ctx.add_error(
                subject_value=f"{provider}:{name}",
                summary=f"{provider} storage check failed: {type(exc).__name__}",
                raw_data={"source": provider, "url": url, "error": str(exc)[:300]},
            )
            return
        if response.status_code == 200:
            await ctx.add_evidence(
                subject_type="finding", subject_value=f"cloud_storage:{provider}:{name}",
                raw_data={"source": provider, "provider": provider, "name": name,
                          "status": response.status_code, "access": "listable",
                          "interest": "high_value"},
                summary=f"publicly listable {provider} storage: {name}",
            )
        elif response.status_code in (401, 403):
            await ctx.add_evidence(
                subject_type="finding", subject_value=f"cloud_storage:{provider}:{name}",
                raw_data={"source": provider, "provider": provider, "name": name,
                          "status": response.status_code, "access": "exists_not_listable",
                          "interest": "notable"},
                summary=f"non-listable {provider} storage candidate: {name}",
            )

    async def _s3(self, ctx: ModuleContext, name: str) -> None:
        # max-keys=1 returns at most a key name, never its object body.
        await self._check(ctx, provider="s3", name=name,
                          url=f"https://{name}.s3.amazonaws.com/?list-type=2&max-keys=1")

    async def _gcs(self, ctx: ModuleContext, name: str) -> None:
        # The JSON list endpoint is capped at one metadata item, never media.
        encoded = quote(name, safe="")
        await self._check(ctx, provider="gcs", name=name,
                          url=f"https://storage.googleapis.com/storage/v1/b/{encoded}/o?maxResults=1")

    async def _azure(self, ctx: ModuleContext, name: str) -> None:
        # Azure's container list operation returns XML metadata, capped to one.
        await self._check(ctx, provider="azure", name=name,
                          url=f"https://{name}.blob.core.windows.net/?restype=container&comp=list&maxresults=1")
