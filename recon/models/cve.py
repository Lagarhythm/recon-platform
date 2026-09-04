"""The local CVE index (PRD Section 11.9, Section 8.3) - reference data, not
engagement-scoped, refreshed out-of-band by ``recon cve refresh`` (see
``recon.orchestrator.cve_index``). ``cve_correlate`` reads this at scan time;
nothing that runs inside a scan writes to it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from recon.models.base import Base, DateTimeUTC, TimestampMixin, utcnow


class CVERecord(Base):
    """One NVD/CISA-KEV record. ``cve_id`` is the natural primary key - a
    refresh upserts by id, never duplicates."""

    __tablename__ = "cve_record"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)

    published: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    last_modified: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)

    #: flattened CPE match ranges: [{"cpe": "cpe:2.3:a:...", "part": "a",
    #: "vendor": ..., "product": ..., "version_start": ..., "version_end": ...,
    #: "vulnerable": true}, ...]
    cpe_matches: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)

    cvss_v31_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v31_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: CISA Known Exploited Vulnerabilities catalog membership
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: [{"url": ..., "source": ..., "tags": [...]}, ...]
    references: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)


class CVEIndexMeta(TimestampMixin, Base):
    """Singleton row describing the last ``recon cve refresh``. Queried by
    ``.id == "singleton"``, never listed."""

    __tablename__ = "cve_index_meta"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="singleton")

    #: "kev_high" (CISA KEV union NVD CVSS>=7, the default) or "full"
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    last_refreshed: Mapped[datetime] = mapped_column(DateTimeUTC, default=utcnow, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: CISA KEV catalog's own "catalogVersion" field, when available - lets an
    #: operator tell "did the KEV catalog actually change" from record_count
    #: alone being a coincidence.
    feed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
