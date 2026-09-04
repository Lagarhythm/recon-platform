"""Render report data to HTML / PDF / JSON."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TPL_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TPL_DIR)),
    autoescape=select_autoescape(["html"]),
)


def _urlhost(value: str) -> str:
    v = str(value or "")
    if "://" in v:
        try:
            return (urlsplit(v).hostname or v).lower()
        except ValueError:
            return v
    # "host:port/tcp" style service value, or a bare host
    return v.split("/")[0].split(":")[0].strip().lower() or v


def _urlpath(value: str) -> str:
    v = str(value or "")
    if "://" not in v:
        return v
    try:
        p = urlsplit(v)
        out = p.path or "/"
        if p.query:
            out += "?" + p.query
        return out
    except ValueError:
        return v


def _pct(x: Any) -> int:
    try:
        return round(float(x) * 100)
    except (TypeError, ValueError):
        return 0


def _deurl(value: Any) -> str:
    """Percent-decode a URL / path for display (keeps it readable in tables)."""
    try:
        return unquote(str(value or ""))
    except (TypeError, ValueError):
        return str(value or "")


_env.filters["urlhost"] = _urlhost
_env.filters["urlpath"] = _urlpath
_env.filters["deurl"] = _deurl
_env.filters["pct"] = _pct


def _sections(data: dict[str, Any]) -> dict[str, Any]:
    """Group the flat report data into the sections the template renders."""
    assets = data.get("assets", [])
    by_type: dict[str, list] = {}
    for a in assets:
        by_type.setdefault(a.get("type", "?"), []).append(a)

    def rank(a: dict) -> int:
        return {"high_value": 0, "notable": 1}.get(a.get("interest"), 2)

    osint_types = ("organization", "person", "email", "repository", "netblock",
                   "social", "document")
    # the "Findings" section is real findings only - genuine `finding` assets
    # plus anything high-value. Notable domains/urls/etc. are covered in their
    # own typed sections, so listing them again as "findings" is just noise.
    findings = sorted(
        (f for f in data.get("findings", [])
         if f.get("type") == "finding" or f.get("interest") == "high_value"),
        key=rank,
    )

    web_by_host: dict[str, list] = {}
    for u in sorted(by_type.get("url", []), key=lambda a: (rank(a), a["value"])):
        web_by_host.setdefault(_urlhost(u["value"]), []).append(u)

    svc_by_host: dict[str, list] = {}
    for s in by_type.get("service", []):
        svc_by_host.setdefault(_urlhost(s["value"]), []).append(s)

    email_formats = [
        f["value"].split(":", 1)[1] for f in data.get("findings", [])
        if str(f.get("value", "")).startswith("email_format:")
    ]

    neg = data.get("negative_findings", [])
    neg_by_control: dict[str, list] = {}
    for n in neg:
        # "X header missing on https://h/" -> group by the control name
        summ = n.get("summary", "")
        key = summ.split(" missing")[0].split(" not ")[0].split(" for ")[0][:60] or "other"
        neg_by_control.setdefault(key, []).append(n)

    hosts = sorted(
        by_type.get("domain", []) + by_type.get("subdomain", []),
        key=lambda a: (a["value"].count("."), a["value"]),
    )
    return {
        "by_type": by_type,
        "type_counts": Counter({k: len(v) for k, v in by_type.items()}),
        "has_osint": any(by_type.get(t) for t in osint_types),
        "findings_by_interest": [
            ("high_value", [f for f in findings if f.get("interest") == "high_value"]),
            ("notable", [f for f in findings if f.get("interest") == "notable"]),
            ("informational", [f for f in findings
                               if f.get("interest") not in ("high_value", "notable")]),
        ],
        "hosts": hosts,
        "ips": by_type.get("ip", []),
        "email_formats": email_formats,
        "web_by_host": web_by_host,
        "svc_by_host": svc_by_host,
        "neg_by_control": dict(sorted(neg_by_control.items())),
    }


class PdfUnavailable(RuntimeError):
    """weasyprint's native libraries are not installed on this host."""


def render_html(data: dict[str, Any]) -> str:
    return _env.get_template("report.html").render(**data, sect=_sections(data))


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=False, default=str)


def render_csv(data: dict[str, Any]) -> str:
    """One row per asset - the flat view scripts and spreadsheets want. Findings
    are assets too (``type == finding``), so they are included."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["type", "value", "confidence", "interest", "scope",
         "first_seen", "last_seen", "modules", "evidence"]
    )
    for a in data.get("assets", []):
        modules = sorted({e.get("module", "") for e in a.get("evidence", []) if e.get("module")})
        summaries = " | ".join(
            e.get("summary", "") for e in a.get("evidence", []) if e.get("summary")
        )
        writer.writerow([
            a.get("type", ""),
            a.get("value", ""),
            a.get("confidence", ""),
            a.get("interest", ""),
            a.get("scope", ""),
            a.get("first_seen", "") or "",
            a.get("last_seen", "") or "",
            ",".join(modules),
            summaries,
        ])
    return buf.getvalue()


def render_pdf(data: dict[str, Any]) -> bytes:
    try:
        from weasyprint import HTML  # noqa: PLC0415
    except (ImportError, OSError) as exc:  # missing pango/cairo/gobject
        raise PdfUnavailable(
            "PDF export needs WeasyPrint's native libraries (pango, cairo, "
            "gdk-pixbuf). On Debian/Ubuntu: apt install libpango-1.0-0 "
            "libpangocairo-1.0-0 libgdk-pixbuf-2.0-0. Use the HTML report "
            "meanwhile."
        ) from exc
    html = _env.get_template("report.html").render(
        **data, sect=_sections(data), pdf=True
    )
    return HTML(string=html).write_pdf()
