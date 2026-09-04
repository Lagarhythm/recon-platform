"""Shared soft-404 cluster filter.

Probing many candidate paths on the same host often gets an identical
``(status, length, words, lines)`` response for a large chunk of them - a
catch-all handler (custom error page, SPA fallback route) rather than real
hits. Any result whose signature repeats more than ``cluster_threshold``
times across the batch it was found in is dropped.

Originally ``dir_fuzz``'s ffuf-result filter; ``exposure_checks`` reuses it
per-host over its much smaller curated path list.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


def filter_soft_404(
    results: list[dict[str, Any]], *, cluster_threshold: int = 12
) -> list[dict[str, Any]]:
    sig = Counter(
        (r.get("status"), r.get("length"), r.get("words"), r.get("lines"))
        for r in results
    )
    return [
        r for r in results
        if sig[(r.get("status"), r.get("length"), r.get("words"), r.get("lines"))]
        <= cluster_threshold
    ]
