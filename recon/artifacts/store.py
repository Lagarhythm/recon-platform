"""Content-addressed artifact store.

Large raw outputs a scan captures (screenshots, HTTP bodies, nmap XML, clone
logs) are written to disk under ``artifacts_dir/<engagement_id>/<sha256>`` and
referenced by an :class:`~recon.models.artifact.Artifact` row. Content
addressing dedupes identical payloads automatically.

The store writes the file and returns an *unsaved* ``Artifact`` ORM object; the
caller adds it to its own session (module context / orchestrator session), the
same single-writer pattern as evidence and audit rows. This avoids cross-session
SQLite lock contention.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from recon.config import get_settings
from recon.models.artifact import Artifact

logger = logging.getLogger("recon.artifacts")


class ArtifactStore:
    """File-side writer + manifest builder for captured blobs."""

    def __init__(self, base_dir: Path | None = None, soft_cap_bytes: int | None = None) -> None:
        settings = get_settings()
        self._base = (base_dir or settings.artifacts_dir).resolve()
        self._soft_cap = soft_cap_bytes if soft_cap_bytes is not None else settings.artifact_soft_cap_bytes

    # --- public -----------------------------------------------------
    def store_bytes(
        self,
        engagement_id: str,
        data: bytes,
        *,
        kind: str,
        content_type: str | None = None,
        asset_id: str | None = None,
    ) -> Artifact:
        """Write ``data`` content-addressed under the engagement and return an
        unsaved ``Artifact`` row referencing it.

        Raises a warning (logged, not fatal) when the engagement crosses its
        soft cap - the write is not aborted, per PRD Section 9.
        """
        if not data:
            raise ValueError("refusing to store an empty artifact")

        digest = hashlib.sha256(data).hexdigest()
        rel = f"{engagement_id}/{digest}"
        abs_path = self._base / engagement_id / digest

        # Content-addressed: same bytes -> same path. Write once.
        if not abs_path.exists():
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            # atomic-ish: write to temp then rename so a crash never leaves a
            # half-written blob under a content-addressable name
            tmp = abs_path.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(abs_path)

        self._warn_if_over_cap(engagement_id)

        return Artifact(
            engagement_id=engagement_id,
            asset_id=asset_id,
            kind=kind,
            path=rel,
            sha256=digest,
            content_type=content_type,
            bytes=len(data),
        )

    def absolute_path(self, path: str) -> Path:
        """Resolve an ``Artifact.path`` (relative to the artifacts base) to an
        absolute file path, preventing path traversal outside the base."""
        base = self._base.resolve()
        target = (base / path).resolve()
        if not target.is_relative_to(base):
            raise ValueError(f"artifact path escapes the artifact store: {path!r}")
        return target

    # --- internal --------------------------------------------------
    def _warn_if_over_cap(self, engagement_id: str) -> None:
        eng_dir = self._base / engagement_id
        if not eng_dir.is_dir() or self._soft_cap <= 0:
            return
        total = sum(f.stat().st_size for f in eng_dir.iterdir() if f.is_file())
        if total > self._soft_cap:
            logger.warning(
                "engagement %s artifact store is %.1f GiB (soft cap %.1f GiB) - "
                "large bodies should be moved to an external store or purged",
                engagement_id, total / (1024**3), self._soft_cap / (1024**3),
            )
