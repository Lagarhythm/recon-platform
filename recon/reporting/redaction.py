"""Redaction pass for client-facing output (PRD Section 7.5, lite).

``internal`` mode: nothing removed - the full working record.
``client`` mode: recursively walks the entire report and, for every string it
finds, scrubs local filesystem paths and anything matching a known
secret/credential pattern; drops values under known raw-body keys entirely;
removes request metadata and the stored RoE YAML.

The same filter gates what is sent to the remote LLM (recon data leaving the
host goes through client-grade redaction).
"""

from __future__ import annotations

import copy
import enum
import re
from typing import Any

_REDACTED = "[redacted]"

# Local filesystem paths (anchored on real root dirs so URL paths are kept).
_UNIX_FS = re.compile(
    r"(?<![\w.\-])/(?:etc|opt|home|root|var|usr|tmp|srv|mnt|media|private|bin|"
    r"sbin|boot|dev|proc|sys|lib|lib64|Users|data|app)(?:/[\w.\- ]+)+/?"
)
_WIN_FS = re.compile(r"[A-Za-z]:\\(?:[\w.\- ]+\\?)+")

# Dict keys whose value is dropped when it looks credential-ish (substring match
# on the lower-cased key). Complements _DROP_KEYS (exact match).
_SENSITIVE_KEY_SUBSTR = (
    "token", "secret", "password", "passwd", "pwd", "apikey", "api_key",
    "api-key", "credential", "privatekey", "private_key", "session", "cookie",
    "bearer", "authorization", "auth_", "_auth", "passphrase",
)

# Known secret / credential shapes.
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{6,}"),                               # AWS access key id
    re.compile(r"ASIA[0-9A-Z]{6,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{10,}"),                        # Google API key
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),                  # Slack
    re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}"),                     # GitHub
    re.compile(r"eyJ[0-9A-Za-z_\-]{6,}\.eyJ[0-9A-Za-z_\-]{6,}\.[0-9A-Za-z_\-]{6,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Za-z_]{3,}\b"),                       # loose AWS-ish
    # key = value style leaks
    re.compile(
        r"(?i)\b(?:api[_-]?token|api[_-]?key|access[_-]?key|secret[_-]?key|"
        r"client[_-]?secret|password|passwd|pwd|bearer|authorization)\b\s*[=:]\s*\S+"
    ),
]

# raw_data / evidence keys whose value is dropped entirely in client mode
_DROP_KEYS = {
    "body", "response_body", "request_body", "raw_response", "raw_request",
    "content", "html", "code", "context", "match", "banner_raw", "stderr",
    "stdout", "argv", "request_metadata", "raw_data_full", "cookie", "set-cookie",
}


class RedactionMode(str, enum.Enum):
    INTERNAL = "internal"
    CLIENT = "client"


def _scrub_paths(text: str) -> str:
    text = _UNIX_FS.sub(_REDACTED, text)
    text = _WIN_FS.sub(_REDACTED, text)
    return text


def _scrub_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub(_REDACTED, text)
    return text


def _scrub_string(text: str) -> str:
    return _scrub_secrets(_scrub_paths(text))


def _walk(node: Any) -> Any:
    if isinstance(node, str):
        return _scrub_string(node)
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for k, v in node.items():
            kl = str(k).lower()
            if kl in _DROP_KEYS or any(s in kl for s in _SENSITIVE_KEY_SUBSTR):
                out[k] = _REDACTED
            else:
                out[k] = _walk(v)
        return out
    if isinstance(node, (list, tuple)):
        return [_walk(v) for v in node]
    return node


def redact_report(data: dict[str, Any], mode: RedactionMode) -> dict[str, Any]:
    if mode is RedactionMode.INTERNAL:
        return data
    out = copy.deepcopy(data)
    out.get("engagement", {}).pop("roe_yaml", None)
    out = _walk(out)
    out.setdefault("meta", {})["redaction"] = "client"
    return out
