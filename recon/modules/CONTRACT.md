# Recon module contract

A module is a subclass of `recon.modules.base.ReconModule`, decorated with
`@recon.modules.registry.register`, that does one job and writes its findings
**only** through the `ModuleContext` passed to `run()`.

## Hard rules

1. **Never write to the DB directly.** No `session.add(Asset(...))`, no direct
   `Evidence(...)` inserts. Use `ctx.add_evidence` / `ctx.add_negative` /
   `ctx.add_error`. The Correlation Engine is the only writer of `Asset`.
2. **Never make a raw outbound request.** HTTP goes through `ctx.http`
   (audited, rate-limited, scope-gated). Non-HTTP outbound (a DNS query) must
   be wrapped with `ctx.audit_action(...)`.
3. **Call `ctx.check_alive()` frequently** - at every request boundary and
   every loop iteration. It raises `ScanCancelled` when the operator cancels
   or the kill switch fires; let it propagate.
4. **Per-target failures use `ctx.add_error(...)` and keep going.** Only raise
   for a whole-module failure (bad config, dependency missing).
5. Emit **negative evidence** for absent controls (`ctx.add_negative`).

## `ModuleContext` API

```python
ctx.engagement            # ORM Engagement (read only)
ctx.roe                   # RoEConfig (pydantic) - scope, rate_limits, evasion
ctx.scope                 # ScopeManager - ctx.scope.classify(target) -> ScopeDecision
ctx.scan_run_id           # str
ctx.module_name           # str

await ctx.add_evidence(
    subject_type=str,          # see canonical types below
    subject_value=str,         # the thing (a hostname, URL, "host:port", ...)
    raw_data=dict,             # JSON-serialisable; module-specific detail
    summary=str | None,        # one-line human description
    request_metadata=dict | None,
    polarity=FindingPolarity.PRESENT,   # or .ABSENT
    relationships=[             # optional; Correlation turns these into edges
        {"type": "resolves_to", "target_type": "ip", "target_value": "1.2.3.4"},
    ],
)
await ctx.add_negative(subject_type=..., subject_value=..., summary=..., raw_data=None)
await ctx.add_error(subject_value=..., summary=..., raw_data=None)

vals = await ctx.known_values("subdomain", "domain")   # distinct prior subject values
evs  = await ctx.known_evidence("js_file")             # prior Evidence rows

resp = await ctx.http.get(url)                          # audited httpx.Response
resp = await ctx.http.request("GET", url, is_target=False)   # third-party OSINT (crt.sh)
#   raises ScopeViolation if target is flagged/excluded and no override
#   raises ReconRequestError on network failure

await ctx.audit_action(target="dns:example.com/A", request_detail={...}, response_meta={...})
await ctx.progress("resolving 40 names", count=40)
ctx.check_alive()
```

`ctx.http` config comes from the RoE automatically: rate limit, concurrency
cap, jitter, User-Agent rotation. `follow_redirects=False` and
`verify=False` by default (recon context) - pass `follow_redirects=True`
per call if you need it.

## Canonical subject types

The Correlation Engine understands these and maps them to Asset types /
relationships:

| subject_type | becomes | raw_data of note |
|---|---|---|
| `domain` / `subdomain` | domain / subdomain asset | `{"parent": "example.com"}` |
| `ip` | ip asset | |
| `dns_record` | derives subdomain/ip/domain + edges | `{"name","rtype","value","ttl"}` |
| `url` / `endpoint` / `http_endpoint` | url asset | `{"status": 200, "method": "GET"}` |
| `service` | service asset | subject_value `"host:port"`; `{"port","proto","name","product","version","banner"}` |
| `secret` | **finding**, interest=high_value | `{"kind","match_redacted","location"}` |
| `http_header` `security_header` `tls_cert` `cookie` `form` `tech` `robots` `sitemap` `http_method` `redirect` `title` | **attribute** attached to the parent asset named by `raw_data["url"]` or `raw_data["host"]` | |
| anything with `polarity=ABSENT` | **finding** (missing control) | |
| `js_file` | url asset; also the input the `js_analyzer` reads | `{"url": "..."}` |
| any other type | **finding** | |

Put an `"interest"` key in `raw_data` (`"informational"` / `"notable"` /
`"high_value"`) to steer the asset's interest level.

## Skeleton

```python
from recon.models.enums import ModulePhase
from recon.modules.base import ModuleContext, ReconModule
from recon.modules.registry import register


@register
class MyModule(ReconModule):
    name = "my_module"
    phase = ModulePhase.PASSIVE
    depends_on = ("dns",)          # optional; forces ordering + auto-include
    description = "one line for the scan-setup UI"
    requires_binary = None         # or "nmap" / "ffuf"

    async def run(self, ctx: ModuleContext) -> None:
        for host in await ctx.known_values("subdomain", "domain"):
            ctx.check_alive()
            ...
```

Register the module's import in `recon/modules/passive/__init__.py` (or
`active/__init__.py`).

## Tests

Put tests in `tests/test_module_<name>.py`. Use the `engagement_id` fixture
and a fake/mocked `ModuleContext` or monkeypatch `ctx.http`. Do **not** make
real network calls in tests. Run `uv run pytest tests/test_module_<name>.py`.
