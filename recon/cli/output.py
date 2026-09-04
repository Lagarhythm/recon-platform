"""Human-readable tables + ``--json`` output, and the CLI's exit-code contract."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping
from typing import Any

# PRD Section 12 exit codes.
EXIT_OK = 0
EXIT_USER_ERROR = 1
EXIT_MODULE_FAILURES = 2
EXIT_AUTH = 3
EXIT_SCAN_FAILED = 4


class CliError(Exception):
    """A CLI-level failure carrying the exit code to return."""

    def __init__(self, message: str, exit_code: int = EXIT_USER_ERROR) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def emit_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, default=str, sort_keys=False)
    sys.stdout.write("\n")


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def table(rows: Iterable[Mapping[str, Any]], columns: list[str] | None = None) -> str:
    rows = list(rows)
    if not rows:
        return "(none)"
    columns = columns or list(rows[0].keys())
    widths = {c: len(c) for c in columns}
    rendered: list[list[str]] = []
    for row in rows:
        cells = [_cell(row.get(c)) for c in columns]
        rendered.append(cells)
        for c, cell in zip(columns, cells):
            widths[c] = max(widths[c], len(cell))
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    sep = "  ".join("-" * widths[c] for c in columns)
    body = "\n".join(
        "  ".join(cell.ljust(widths[c]) for c, cell in zip(columns, cells))
        for cells in rendered
    )
    return f"{header}\n{sep}\n{body}"


def kv(data: Mapping[str, Any]) -> str:
    width = max((len(str(k)) for k in data), default=0)
    return "\n".join(f"{str(k).rjust(width)} : {_cell(v)}" for k, v in data.items())


def print_result(data: Any, *, as_json: bool, table_columns: list[str] | None = None) -> None:
    """Render a command result: raw JSON, or a table (list) / kv block (dict)."""
    if as_json:
        emit_json(data)
        return
    if isinstance(data, list):
        print(table(data, table_columns))
    elif isinstance(data, Mapping):
        print(kv(data))
    else:
        print(_cell(data))
