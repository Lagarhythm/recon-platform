# Integrated Reconnaissance Platform

An orchestration and intelligence layer for **authorized** penetration-test
reconnaissance. It wraps proven engines (nmap, ffuf), normalizes their output
into a unified asset model, correlates findings across sources, scores
confidence, and surfaces a prioritized attack surface - optionally assisted by
a remote LLM analyst.

> **Authorized use only.** Every active module is gated by per-engagement Rules
> of Engagement. This tool performs reconnaissance and enumeration; it never
> exploits and never authenticates with discovered credentials.

**→ [`docs/GUIDE.md`](docs/GUIDE.md) is the operator guide** — capabilities, RoE
authoring, every module, the scan workflow, the LLM analyst, config, and
troubleshooting. Start there. [`docs/DEMO.md`](docs/DEMO.md) is a ~10-minute
full-chain walkthrough against `scanme.nmap.org`.

See [`recon-tool-prd.md`](recon-tool-prd.md) for the full requirements.

---

## What it does

- **Engagements** are fully isolated. Scope + evasion come from one validated
  RoE document (YAML/JSON, or a guided form).
- **Scope safety is enforced, not advisory.** Every outbound request is
  classified and written to an append-only audit log with the RoE hash in
  force at the time. Flagged/excluded targets need a conscious per-scan
  override; explicitly excluded targets are never touched by active modules.
- **Passive-first.** All passive modules run and correlation fires before a
  checkpoint; no active module touches the target until the operator signs off.
- **Modules write Evidence; only the Correlation Engine writes Assets.** The
  Asset Graph - deduplicated entities, confidence from independent-source
  count, interest level, relationships - is the deliverable.
- **Kill switch.** One button halts every running module immediately.
- **Reports** in HTML / PDF / JSON, with a redaction pass for client copies.

### Modules

Modules run in phase order: **`osint` → `passive` → checkpoint → `active`**.
OSINT modules contact public third-party sources only, never the target.

| Phase | Module | Engine |
|-------|--------|--------|
| osint | `ct_org` | crt.sh by domain **and** by organisation name - domains + owner org |
| osint | `rdap` | RDAP/WHOIS: registrant org, dates, status, NS + reverse-IP netblock |
| osint | `github_org` | GitHub org: public repos (tech/topics/activity) + public members |
| osint | `git_secrets` | full git-history secret scan of `github_org`-discovered repos (redacted, unverified by default) |
| osint | `wayback` | Internet Archive: historical URLs, dead subdomains, removed documents |
| osint | `passive_subdomains` | aggregates ~8 keyless passive sources (CT, passive-DNS, archives) with per-source confidence |
| osint | `passive_urls` | historical URLs from Wayback, Common Crawl, OTX, urlscan |
| osint | `cloud_assets` | public S3/GCS/Azure bucket existence + listability checks - never reads object contents |
| osint | `search` | search-engine dorking via SearXNG / Google CSE - files, panels, staff, paste/cloud leaks |
| passive | `dns` | dnspython - A/AAAA/CNAME/MX/NS/TXT/SOA/CAA, missing-DNSSEC |
| passive | `ct_subdomains` | crt.sh Certificate Transparency logs |
| passive | `subdomain_permute` | dnsgen/altdns-style permutations of known subdomains, wildcard-filtered |
| passive | `subdomain_recurse` | re-queries passive sources against newly-found subdomains for deeper names |
| passive | `subdomain_takeover` | dangling-CNAME detection against ~30 vendored provider fingerprints |
| passive | `internetdb` | Shodan InternetDB - keyless open ports/CPEs/CVEs per resolved IP |
| passive | `probe_http` | HTTP(S) liveness bridge: status, title, redirect, scheme - feeds crawler/js_analyzer/active phase |
| passive | `http_analyzer` | headers, security headers (present + absent), cookies, TLS, tech |
| passive | `email_security` | SPF/DMARC/DKIM/MTA-STS/TLS-RPT posture per apex domain |
| passive | `tech_fingerprint` | vendored Wappalyzer-style corpus match on headers/cookies/HTML/JS |
| passive | `crawler` | links, forms, params, JS files, robots.txt, sitemap.xml |
| passive | `js_analyzer` | endpoints, params, leaked secrets (redacted), library fingerprints |
| active | `port_scan` | **nmap** - TCP + `-sV`, rate-capped from the RoE |
| active | `dir_fuzz` | **ffuf** - content discovery with soft-404 similarity filtering |
| active | `dns_axfr` | zone-transfer attempts (a finding if one succeeds) |
| active | `subdomain_brute` | wordlist brute-force with wildcard-DNS detection |
| active | `exposure_checks` | curated unauthenticated presence checks (`.git`/`.env`/actuator/swagger/admin panels/backups/GraphQL introspection) |
| active | `scan_diff` | CTEM delta vs. the last completed run's baseline snapshot |
| active | `cve_correlate` | matches service/tech versions against InternetDB, the local CVE index, and OSV.dev |

For **company OSINT**, an engagement's RoE carries an `osint:` block (company
name + `seed_domains`); `scope:` may be omitted entirely for an OSINT-only
engagement. `RECON_OSINT_GITHUB_TOKEN` raises the GitHub API limit 60/hr →
5000/hr.

The `search` dork module needs a backend:

```bash
# self-hosted SearXNG (recommended - free, no key, no ToS issue)
docker run -d --name searxng -p 127.0.0.1:8888:8080 \
  -v ~/searxng:/etc/searxng searxng/searxng
# then in ~/searxng/settings.yml add:  search: {formats: [html, json]}  +  server: {limiter: false}
# and set:
RECON_SEARCH_BACKEND=searxng
RECON_SEARXNG_URL=http://127.0.0.1:8888
```

SearXNG needs a hardened engine set to survive scraping-IP throttling — see
[`docs/GUIDE.md`](docs/GUIDE.md) §7. (A legacy `google_cse` backend also exists
but Google's Custom Search API is closed to new customers and retires Jan 2027.)
With no backend set, `search` no-ops.

## Requirements

- Python 3.12 (managed via [uv](https://docs.astral.sh/uv/))
- **Linux** is the primary deployment target.
  - `nmap` and `ffuf` on `PATH` for the active modules (missing -> that module
    logs an error and skips). nmap SYN scan needs `CAP_NET_RAW`; otherwise it
    falls back to TCP connect.
  - PDF export needs WeasyPrint's native libs:
    `apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0`
    (HTML/JSON reports work without them).

## Quick start

```bash
uv sync
uv run python -m recon init-db
uv run python -m recon serve --reload      # http://127.0.0.1:8000
uv run pytest
```

First launch redirects to `/setup` to create the single operator account.
There is no password recovery - store it in a password manager.

## Configuration

`RECON_`-prefixed env vars or a `.env` file:

| Var | Default | Notes |
|-----|---------|-------|
| `RECON_HOST` / `RECON_PORT` | `127.0.0.1` / `8000` | |
| `RECON_SESSION_IDLE_TIMEOUT_MINUTES` | `60` | sliding session expiry |
| `RECON_SESSION_COOKIE_SECURE` | `false` | set `true` behind HTTPS |
| `RECON_DATABASE_URL` | `sqlite+aiosqlite:///data/recon.db` | SQLAlchemy async URL |
| `RECON_FUZZ_WORDLIST` | bundled `common.txt` | point at SecLists for real work |
| `RECON_LLM_BASE_URL` / `_API_KEY` / `_MODEL` | localhost | OpenAI-compatible endpoint |

## Architecture

- **`recon/orchestrator/`** is the engine's internal API. The dashboard and the
  `recon` CLI are both thin clients over it - no engine changes either way.
- **`recon/modules/`** - each module does one job through `ModuleContext`
  (`CONTRACT.md`). No module writes the DB or makes a raw request directly.
- **`recon/net/http_client.py`** - the single audited, rate-limited,
  scope-gated, redirect-aware outbound HTTP path. Jitter + UA rotation +
  adaptive backoff from the RoE.
- The **Audit Log is append-only** by construction - no update/delete path
  exists anywhere in the code.

## Management commands

```bash
uv run python -m recon serve [--host H] [--port N] [--reload]
uv run python -m recon init-db
uv run python -m recon reset-auth [--yes]
```

### `recon-platform` launcher

`scripts/recon-platform` is a small launcher — symlink it onto your `PATH`
(`ln -s "$PWD/scripts/recon-platform" ~/.local/bin/`) and then, from anywhere:

```bash
recon-platform            # start the dashboard in the background (idempotent)
recon-platform status     # up / down + pid
recon-platform restart    # stop + start
recon-platform stop
recon-platform log        # tail the server log
recon-platform fg         # run in the foreground instead
recon-platform init-db    # anything else is passed through to `python -m recon`
```

Reads `RECON_PLATFORM_DIR` / `RECON_HOST` / `RECON_PORT` if set. Background runs
log to `data/serve.log` and track their pid in `data/serve.pid`.
