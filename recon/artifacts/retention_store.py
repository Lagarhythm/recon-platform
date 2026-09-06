"""Content-addressed store for retention bundles (P0-1 / B2).

Separate from :class:`~recon.artifacts.store.ArtifactStore` on purpose: an
``Artifact`` is engagement-owned (``engagement_id`` non-null, ``ondelete=CASCADE``,
path ``artifacts_dir/<engagement_id>/<sha256>``), so an engagement purge would
cascade its row and orphan the blob. A retention bundle must *outlive* the
engagement it documents, so it is written here - under ``settings.retention_dir``
(``data_dir/retention/``), a sibling of ``artifacts/`` with no per-engagement
dimension - and referenced by a :class:`~recon.models.authz.RetentionArtifact`
row that has no FK to any engagement.

Durability: the blob is written to a temp file, ``fsync``-ed, atomically renamed
to its final content-addressed name, and the parent directory is ``fsync``-ed so
the rename survives a crash. ``purge_engagement`` writes and *reads back +
verifies* the bundle before it deletes any forensic row.
"""

from __future__ import annotations

import hashlib
import logging
import os
from contextlib import suppress
from pathlib import Path

from recon.config import get_settings
from recon.models.authz import RetentionArtifact

logger = logging.getLogger("recon.retention")

RETENTION_BUNDLE_KIND = "audit_retention_bundle"


class RetentionArtifactError(RuntimeError):
    """A retention blob could not be written, read back, or verified."""


class RetentionArtifactStore:
    """File-side writer + verifier for retention bundles."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base = (base_dir or get_settings().retention_dir).resolve()
        self._base.mkdir(parents=True, exist_ok=True)

    # --- public ---------------------------------------------------------
    def store_bytes(self, data: bytes, *, kind: str = RETENTION_BUNDLE_KIND) -> RetentionArtifact:
        """Write ``data`` content-addressed and durably, then return an *unsaved*
        ``RetentionArtifact`` row referencing it. Raises ``RetentionArtifactError``
        if the write or the immediate read-back verification fails; on failure no
        partial file is left under a content-addressable name.
        """
        if not data:
            raise RetentionArtifactError("refusing to store an empty retention bundle")

        digest = hashlib.sha256(data).hexdigest()
        final = self._base / digest
        tmp = self._base / f".{digest}.{os.getpid()}.tmp"

        if not final.exists():
            try:
                with open(tmp, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, final)
                self._fsync_dir(self._base)
            except OSError as exc:
                with suppress(OSError):
                    tmp.unlink()
                raise RetentionArtifactError(f"retention bundle write failed: {exc}") from exc
            finally:
                if tmp.exists():
                    with suppress(OSError):
                        tmp.unlink()

        # Read back + verify before the caller commits anything.
        readback = final.read_bytes()
        actual = hashlib.sha256(readback).hexdigest()
        if actual != digest:
            raise RetentionArtifactError(
                f"retention bundle verification failed: wrote {digest}, read {actual}"
            )

        return RetentionArtifact(
            kind=kind,
            sha256=digest,
            byte_size=len(data),
            stored_path=digest,
        )

    def open_bytes(self, artifact: RetentionArtifact) -> bytes:
        """Return the bytes for ``artifact`` and re-verify the SHA-256. Raises
        ``RetentionArtifactError`` if the file is missing or does not match."""
        path = self.absolute_path(artifact.stored_path)
        if not path.is_file():
            raise RetentionArtifactError(
                f"retention bundle {artifact.sha256} missing at {path}"
            )
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != artifact.sha256:
            raise RetentionArtifactError(
                f"retention bundle {artifact.sha256} corrupt: on-disk sha {actual}"
            )
        return data

    def absolute_path(self, stored_path: str) -> Path:
        """Resolve a ``RetentionArtifact.stored_path`` under the retention base,
        rejecting any path that escapes it."""
        target = (self._base / stored_path).resolve()
        if not target.is_relative_to(self._base):
            raise RetentionArtifactError(
                f"retention path escapes the store: {stored_path!r}"
            )
        return target

    def open_bytes_by_sha(self, sha256: str) -> bytes:
        """Return the bytes for a bundle identified only by its SHA-256,
        re-verifying the digest. Raises ``RetentionArtifactError`` if missing or
        corrupt."""
        path = self.absolute_path(sha256)
        if not path.is_file():
            raise RetentionArtifactError(f"retention bundle {sha256} missing at {path}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise RetentionArtifactError(f"retention bundle {sha256} corrupt")
        return data

    def exists(self, sha256: str) -> bool:
        return (self._base / sha256).is_file()

    def sweep_orphans(self, known_sha256: set[str]) -> list[str]:
        """Delete retention blobs with no ``AuditRetentionExport`` row - the
        bounded recovery for a purge that wrote a bundle then rolled back before
        committing the export. Returns the SHAs removed. Never touches a blob in
        ``known_sha256``."""
        removed: list[str] = []
        for entry in self._base.iterdir():
            if not entry.is_file() or entry.name.startswith("."):
                continue
            if entry.name in known_sha256:
                continue
            with suppress(OSError):
                entry.unlink()
                removed.append(entry.name)
        if removed:
            logger.info("swept %d orphan retention blob(s)", len(removed))
        return removed

    # --- internal ------------------------------------------------------
    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
