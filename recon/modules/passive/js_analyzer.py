"""JavaScript Analyzer (passive).

Parses crawled JS bundles (and inline page scripts) for HTTP endpoints,
route/parameter names, third-party library fingerprints, and leaked secrets.
It never generates traffic of its own beyond fetching the JS URLs the crawler
already found; secret matches are always redacted before they are stored.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register
from recon.net.http_client import ReconRequestError, ScopeViolation

_MAX_SCAN_BYTES = 2_000_000

_JS_CT_HINTS = ("javascript", "ecmascript", "text/jsx")
_NON_JS_CT_HINTS = (
    "text/html",
    "application/json",
    "text/css",
    "image/",
    "video/",
    "audio/",
    "font/",
    "application/xml",
    "text/xml",
)
_JS_MARKERS = (
    "function",
    "=>",
    "var ",
    "const ",
    "let ",
    "require(",
    "import ",
    "export ",
    "window.",
    "document.",
    "webpack",
    "!function",
    "(function",
)

_ASSET_EXT = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".webm",
    ".mp3",
    ".pdf",
)

# --- endpoint patterns -------------------------------------------------
_ABS_URL_RE = re.compile(r"""https?://[^\s"'`<>()\[\]{},;]+""")
_FETCH_RE = re.compile(r"""\bfetch\(\s*['"`]([^'"`]+)['"`]""")
_AXIOS_RE = re.compile(
    r"""\baxios\.(get|post|put|delete|patch|head)\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_AJAX_RE = re.compile(
    r"""\$\.ajax\(\s*\{[^}]*?\burl\s*:\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE | re.DOTALL,
)
_XHR_OPEN_RE = re.compile(
    r"""\.open\(\s*['"`](GET|POST|PUT|DELETE|PATCH|HEAD)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_QUOTED_PATH_RE = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}:~]+)['"`]""")
_PATH_PREFIX_RE = re.compile(
    r"^/(api|v\d+|rest|graphql|gql|rpc|auth|oauth|sso|login|logout|users?|"
    r"accounts?|admin|internal|service|services|public|session|token|"
    r"webhook|callback|_next|_api)\b",
    re.IGNORECASE,
)

# --- param patterns --------------------------------------------------
_PARAMS_OBJ_RE = re.compile(r"\bparams\s*:\s*\{([^{}]*)\}", re.DOTALL)
_JSON_STRINGIFY_RE = re.compile(r"JSON\.stringify\(\s*\{([^{}]*)\}", re.DOTALL)
_OBJ_KEY_RE = re.compile(r"""['"]?([A-Za-z_$][\w$-]*)['"]?\s*:""")
_QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][\w\-]{0,40})=")

# --- secret patterns ----------------------------------------------
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"
)
_AWS_SECRET_RE = re.compile(
    r"""(?i)(?:aws_?secret_?access_?key|secret_?access_?key|aws_?secret)"""
    r"""['"]?\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]"""
)
_GENERIC_SECRET_RE = re.compile(
    r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"""
    r"""secret[_-]?key|token|password|passwd|pwd|secret|bearer)\b"""
    r"""\s*[:=]\s*['"]([^'"\s]{20,120})['"]"""
)
_PLACEHOLDER_HINTS = (
    "your",
    "example",
    "changeme",
    "placeholder",
    "xxxx",
    "test",
    "dummy",
    "sample",
    "redacted",
    "process.env",
    "import.meta",
    "${",
    "<%",
    "{{",
)

# --- tech fingerprints -------------------------------------------
_TECH_SIGNS: tuple[tuple[str, tuple[str, ...], re.Pattern | None], ...] = (
    (
        "React",
        ("React.createElement", "__REACT_DEVTOOLS", "react-dom", "_reactRootContainer"),
        re.compile(r"""React(?:\.version)?\s*[:=]\s*['"]([0-9][0-9.]+)['"]"""),
    ),
    (
        "Vue",
        ("__VUE__", "Vue.config", "Vue.component", "createApp("),
        re.compile(r"""Vue(?:\.version)?\s*[:=]\s*['"]([0-9][0-9.]+)['"]"""),
    ),
    (
        "Angular",
        ("angular.module", "ng-version", "@angular/", "platformBrowserDynamic"),
        re.compile(r"""(?:ng-version|angular.{0,20}version)['"]?\s*[:=]?\s*['"]([0-9][0-9.]+)['"]"""),
    ),
    (
        "jQuery",
        ("jQuery.fn.jquery", "jquery", "jQuery v"),
        re.compile(r"""jQuery[ v:=]+['"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"""),
    ),
    (
        "webpack",
        ("webpackJsonp", "__webpack_require__", "webpackChunk", "__webpack_modules__"),
        None,
    ),
)


def _mask(secret: str) -> str:
    if len(secret) <= 8:
        return "..."
    return f"{secret[:4]}...{secret[-4:]}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


def _looks_like_js(body: str) -> bool:
    sample = body[:8192]
    return sum(1 for m in _JS_MARKERS if m in sample) >= 2


def _is_pathlike(path: str) -> bool:
    if len(path) < 3 or "//" in path or " " in path:
        return False
    low = path.lower().split("?")[0]
    if low.endswith(_ASSET_EXT):
        return False
    if not any(ch.isalpha() for ch in path):
        return False
    if _PATH_PREFIX_RE.match(path):
        return True
    return path.count("/") >= 2


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)]}\\'\"")


class _FileFindings:
    """Accumulates one JS file's results, keeping evidence emission ordered."""

    def __init__(self) -> None:
        self.endpoints: dict[tuple[str, str, str], None] = {}
        self.params: set[str] = set()
        self.secret_values: set[str] = set()

    def add_endpoint(self, value: str, method: str, kind: str) -> None:
        value = value.strip()
        if not value:
            return
        # first classification for a value wins (call-based before scan-based)
        for k in list(self.endpoints):
            if k[0] == value:
                return
        self.endpoints[(value, method.upper(), kind)] = None


@register
class JSAnalyzerModule(ReconModule):
    name = "js_analyzer"
    phase = ModulePhase.PASSIVE
    depends_on = ("crawler",)
    description = "Parse crawled JS for endpoints, params, tech, and leaked secrets"

    async def run(self, ctx: ModuleContext) -> None:
        targets = await self._collect_targets(ctx)
        if not targets:
            await ctx.progress("no JS sources to analyze")
            return

        total = len(targets)
        await ctx.progress(
            f"analyzing {total} JS source(s)", current=0, total=total
        )

        for done, (source_file, inline_code) in enumerate(targets, start=1):
            ctx.check_alive()
            if inline_code is None:
                text = await self._fetch_js(ctx, source_file)
                if text is None:
                    await ctx.progress(
                        f"analyzed {done}/{total}", current=done, total=total
                    )
                    continue
            else:
                text = inline_code[:_MAX_SCAN_BYTES]

            await self._analyze(ctx, text, source_file)
            await ctx.progress(
                f"analyzed {done}/{total}", current=done, total=total
            )

    # --- inputs ------------------------------------------------------
    async def _collect_targets(self, ctx: ModuleContext) -> list[tuple[str, str | None]]:
        seen_urls: set[str] = set()
        targets: list[tuple[str, str | None]] = []

        for url in await ctx.known_values("js_file"):
            if url and url not in seen_urls:
                seen_urls.add(url)
                targets.append((url, None))

        for url in await ctx.known_values("url"):
            if not url:
                continue
            path = url.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith((".js", ".mjs")) and url not in seen_urls:
                seen_urls.add(url)
                targets.append((url, None))

        seen_inline: set[tuple[str, str]] = set()
        for ev in await ctx.known_evidence("inline_js"):
            raw = ev.raw_data or {}
            code = raw.get("code")
            page = raw.get("url") or ev.subject_value or "inline"
            if not code or not isinstance(code, str):
                continue
            key = (page, code)
            if key in seen_inline:
                continue
            seen_inline.add(key)
            targets.append((page, code))

        return targets

    # --- fetching --------------------------------------------------
    async def _fetch_js(self, ctx: ModuleContext, url: str) -> str | None:
        try:
            resp = await ctx.http.get(url)
        except (ScopeViolation, ReconRequestError) as exc:
            await ctx.add_error(
                subject_value=url,
                summary=f"JS fetch failed: {type(exc).__name__}",
                raw_data={"url": url, "error": str(exc)},
            )
            return None

        if resp.status_code >= 400:
            await ctx.add_error(
                subject_value=url,
                summary=f"JS fetch returned HTTP {resp.status_code}",
                raw_data={"url": url, "status": resp.status_code},
            )
            return None

        ct = (resp.headers.get("content-type") or "").lower()
        try:
            body = resp.text or ""
        except Exception:  # noqa: BLE001 - undecodable body
            body = ""
        if len(body) > _MAX_SCAN_BYTES:
            body = body[:_MAX_SCAN_BYTES]

        is_js_ct = any(h in ct for h in _JS_CT_HINTS)
        is_non_js_ct = bool(ct) and not is_js_ct and any(h in ct for h in _NON_JS_CT_HINTS)
        if is_non_js_ct and not _looks_like_js(body):
            await ctx.progress(f"skipping non-JS content at {url} ({ct})")
            return None

        return body

    # --- analysis -------------------------------------------------
    async def _analyze(self, ctx: ModuleContext, text: str, source_file: str) -> None:
        ff = _FileFindings()
        self._scan_endpoints(text, ff)
        self._scan_params(text, ff)

        for (value, method, kind) in ff.endpoints:
            await ctx.add_evidence(
                subject_type="endpoint",
                subject_value=value,
                raw_data={"source_file": source_file, "method": method, "kind": kind},
                summary=f"{method} {value} referenced in {source_file}",
            )

        if ff.params:
            await ctx.add_evidence(
                subject_type="js_params",
                subject_value=source_file,
                raw_data={
                    "source_file": source_file,
                    "params": sorted(ff.params)[:200],
                },
                summary=f"{len(ff.params)} candidate API param(s) in {source_file}",
            )

        await self._scan_secrets(ctx, text, source_file, ff)
        await self._scan_tech(ctx, text, source_file)

    def _scan_endpoints(self, text: str, ff: _FileFindings) -> None:
        for m in _FETCH_RE.finditer(text):
            ff.add_endpoint(m.group(1), "GET", "fetch")
        for m in _AXIOS_RE.finditer(text):
            ff.add_endpoint(m.group(2), m.group(1), "fetch")
        for m in _AJAX_RE.finditer(text):
            ff.add_endpoint(m.group(1), "GET", "fetch")
        for m in _XHR_OPEN_RE.finditer(text):
            ff.add_endpoint(m.group(2), m.group(1), "fetch")

        for m in _ABS_URL_RE.finditer(text):
            ff.add_endpoint(_clean_url(m.group(0)), "GET", "absolute")

        for m in _QUOTED_PATH_RE.finditer(text):
            path = m.group(1)
            if _is_pathlike(path):
                ff.add_endpoint(path, "GET", "path")

    def _scan_params(self, text: str, ff: _FileFindings) -> None:
        for block_re in (_PARAMS_OBJ_RE, _JSON_STRINGIFY_RE):
            for m in block_re.finditer(text):
                for km in _OBJ_KEY_RE.finditer(m.group(1)):
                    name = km.group(1)
                    if name and not name.isdigit():
                        ff.params.add(name)
        for m in _QUERY_PARAM_RE.finditer(text):
            ff.params.add(m.group(1))
        ff.params.discard("http")
        ff.params.discard("https")

    async def _scan_secrets(
        self, ctx: ModuleContext, text: str, source_file: str, ff: _FileFindings
    ) -> None:
        ordered: list[tuple[str, re.Pattern, int]] = [
            ("aws_access_key", _AWS_ACCESS_KEY_RE, 0),
            ("google_api_key", _GOOGLE_API_KEY_RE, 0),
            ("slack_token", _SLACK_TOKEN_RE, 0),
            ("github_token", _GITHUB_TOKEN_RE, 0),
            ("jwt", _JWT_RE, 0),
            ("private_key", _PRIVATE_KEY_RE, 0),
            ("aws_secret_key", _AWS_SECRET_RE, 1),
        ]
        for kind, pattern, group in ordered:
            for m in pattern.finditer(text):
                secret = m.group(group) if group else m.group(0)
                await self._emit_secret(ctx, text, source_file, ff, kind, secret, m.start())

        for m in _GENERIC_SECRET_RE.finditer(text):
            value = m.group(1)
            if value in ff.secret_values:
                continue
            low = value.lower()
            if any(h in low for h in _PLACEHOLDER_HINTS):
                continue
            if value.startswith(("http://", "https://", "/")):
                continue
            if self._matched_specific(value):
                continue
            if _entropy(value) <= 3.5:
                continue
            await self._emit_secret(
                ctx, text, source_file, ff, "generic_secret", value, m.start(1)
            )

    @staticmethod
    def _matched_specific(value: str) -> bool:
        for pattern in (
            _AWS_ACCESS_KEY_RE,
            _GOOGLE_API_KEY_RE,
            _SLACK_TOKEN_RE,
            _GITHUB_TOKEN_RE,
            _JWT_RE,
            _PRIVATE_KEY_RE,
        ):
            if pattern.search(value):
                return True
        return False

    async def _emit_secret(
        self,
        ctx: ModuleContext,
        text: str,
        source_file: str,
        ff: _FileFindings,
        kind: str,
        secret: str,
        pos: int,
    ) -> None:
        if not secret or secret in ff.secret_values:
            return
        ff.secret_values.add(secret)
        masked = _mask(secret)
        a = max(0, pos - 30)
        b = min(len(text), pos + len(secret) + 30)
        context = text[a:b].replace(secret, masked)
        await ctx.add_evidence(
            subject_type="secret",
            subject_value=f"{kind}:{source_file}",
            raw_data={
                "kind": kind,
                "match_redacted": masked,
                "source_file": source_file,
                "context": context,
                "interest": "high_value",
            },
            summary=f"Possible {kind} in {source_file}",
        )

    async def _scan_tech(self, ctx: ModuleContext, text: str, source_file: str) -> None:
        sample = text if len(text) <= _MAX_SCAN_BYTES else text[:_MAX_SCAN_BYTES]
        low = sample.lower()
        for name, needles, version_re in _TECH_SIGNS:
            if not any(n.lower() in low for n in needles):
                continue
            version = None
            if version_re is not None:
                vm = version_re.search(sample)
                if vm:
                    version = vm.group(1)
            await ctx.add_evidence(
                subject_type="tech",
                subject_value=name,
                raw_data={
                    "url": source_file,
                    "name": name,
                    "version": version,
                    "evidence": "js",
                },
                summary=f"{name}{' ' + version if version else ''} fingerprinted in {source_file}",
            )
