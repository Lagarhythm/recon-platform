# Recon-Tool — Operator Guide

The **Integrated Reconnaissance Platform** is an orchestration + intelligence
layer for *authorized* penetration-test reconnaissance. You give it a target and
a Rules-of-Engagement document; it runs a phased pipeline of recon modules,
normalizes everything into one **Asset Graph**, scores confidence, flags the
interesting bits, and produces a report — optionally with an LLM analyst's
assessment on top.

It **never exploits** anything and **never uses discovered credentials**. Every
outbound request is scope-checked and written to an append-only audit log.

- Overview & module table: [`../README.md`](../README.md)
- Requirements / design rationale: [`../recon-tool-prd.md`](../recon-tool-prd.md)
- This doc: how to actually operate it.

---

## 1. Capabilities at a glance

| Area | What you get |
|---|---|
| **Company OSINT** | crt.sh (by domain *and* by org name), RDAP/WHOIS + reverse-IP netblocks, GitHub org/user repos + members, Internet Archive history, search-engine dorking. Third-party sources only — never touches the target. |
| **Passive recon** | DNS records + missing-DNSSEC, CT-log subdomains, HTTP(S) fingerprinting (headers, security headers, cookies, TLS, tech), link/form/JS crawl, JS endpoint + secret extraction. |
| **Active recon** | nmap port/service scan, ffuf content discovery, DNS zone-transfer attempts, subdomain brute-force. All gated behind a manual checkpoint. |
| **Correlation** | Deduplicated entities, confidence from independent-source count, interest levels (high-value / notable / informational), typed relationships. |
| **Safety** | Per-engagement RoE (validated, hashed). Append-only audit log with the RoE hash on every entry. Passive-first checkpoint. Global kill switch. Excluded targets are never touched by active modules. |
| **Reporting** | HTML / PDF / JSON, organized into sections, with an internal vs. client (redacted) mode. |
| **LLM analyst** | Optional. Sends the *client-redacted* graph to an OpenAI-compatible endpoint for a prioritized assessment + recon next-steps. Off until an engagement opts in. |

### What it will **not** do

- Exploit a vulnerability, submit a payload, or brute-force a login.
- Authenticate anywhere with a credential it found.
- Touch a host in the `excluded` list — even with the override flag on.
- Scan a CIDR broader than /24 (IPv4) / /120 (IPv6).
- Send data off-host unless the engagement's `llm.analysis_enabled` is `true`.

---

## 2. Install & run

Requires **Python 3.12** (managed by [uv](https://docs.astral.sh/uv/)), on Linux
for the active modules.

```bash
cd recon-platform
uv sync                                  # install deps
uv run python -m recon init-db           # apply migrations
uv run python -m recon serve             # http://127.0.0.1:8000
```

First visit redirects to **`/setup`** to create the single operator account.
There is no password recovery — put it in a password manager.

**Optional external tools** (a module logs an error and skips if its tool is missing):

- `nmap` — `port_scan`. SYN scan needs `CAP_NET_RAW`; otherwise it falls back to
  TCP connect automatically.
- `ffuf` — `dir_fuzz`.
- WeasyPrint native libs for PDF export:
  `libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0`
  (Arch: `pango`). HTML/JSON reports work without them.

**CLI commands**

```bash
uv run python -m recon serve [--host H] [--port N] [--reload]
uv run python -m recon init-db          # apply DB migrations
uv run python -m recon reset-auth [--yes]   # delete operator accounts (start over at /setup)
uv run python -m recon version
```

Run the test suite with `uv run pytest` (~1 min, ~200 tests).

---

### The operator CLI

Everything the dashboard does is also a `recon` subcommand — a thin client over
the same orchestrator. It runs **in-process** by default (no server needed; it
opens the configured database directly) or against a **running dashboard** with
`--server URL` + an API token.

```bash
uv run python -m recon engagement create --roe path/to/roe.yaml [--name NAME] [--json]
uv run python -m recon engagement list | show <id> | archive <id>
uv run python -m recon engagement purge <id> [--older-than DAYS] [--export-first FILE] [--yes]

uv run python -m recon scan start --engagement <id> \
      --modules dns,ct_subdomains,...   # or --all-passive / --all
      [--allow-out-of-scope] [--wait] [--yes-active]
uv run python -m recon scan status --run <id> [--wait] [--json]
uv run python -m recon scan checkpoint --run <id> --approve   # sign off passive -> active
uv run python -m recon scan resume  --run <id>
uv run python -m recon scan cancel  --run <id>
uv run python -m recon scan list --engagement <id>

uv run python -m recon report  --engagement <id> --format html|pdf|json|csv [--redacted] [--out FILE]
uv run python -m recon diff    --engagement <id> [--since <run-id>]    # asset-graph delta (Wave 2 populates snapshots)
uv run python -m recon analyst --engagement <id>                       # needs llm.analysis_enabled

uv run python -m recon token create --name "laptop-cli"   # prints the token once
uv run python -m recon token list | revoke <id>
```

- `--json` on every command for scripting.
- `--wait` streams the same event bus the dashboard WebSocket uses. **In-process
  there is no background daemon**, so a `scan start` without `--wait` still
  blocks until the run reaches its next stop (completion or the pre-active
  checkpoint); against `--server` it returns immediately and the server keeps
  running the scan.
- **Exit codes:** `0` ok · `1` user error (bad RoE, unknown module) · `2`
  finished with module failures · `3` auth · `4` scan failed.

**Headless bring-up:** set `RECON_BOOTSTRAP_ADMIN_USER` / `RECON_BOOTSTRAP_ADMIN_PASSWORD`
once — the first operator account is created from them on an empty user table
and they are ignored thereafter. Then `recon token create --name ci` for a
bearer token, and point remote clients at `--server` with
`RECON_API_TOKEN` (or `RECON_SERVER_URL` + `RECON_API_TOKEN` in the env).

The REST surface is `/api/v1/*` with `Authorization: Bearer <token>` — the same
endpoints the CLI's `--server` mode calls.

---

## 3. Core concepts

**Engagement** — one isolated job. Owns its RoE, its scans, and its slice of the
Asset Graph. Switch the active engagement from the top nav; every page acts on
whichever engagement is active.

**Rules of Engagement (RoE)** — a YAML (or JSON) document that is the *single
source of truth* for scope and evasion. It's validated and SHA-256 hashed at
engagement creation; the hash is stamped on every audit-log row so you can prove
which ruleset was in force for any request. See §4.

**Phases** run in a fixed order:

```
osint  →  passive  →  [CHECKPOINT]  →  active
```

- **osint** modules contact only public third-party services (crt.sh, RDAP,
  GitHub, archive.org, your search backend). They never send a packet to the
  target, so they need no scan authorization.
- **passive** modules touch the target but only in ways a normal client would
  (DNS lookups, fetching pages, reading JS).
- The **checkpoint** halts the run after passive + correlation. Nothing active
  fires until you review the graph and click **Proceed**.
- **active** modules run scanners (nmap, ffuf) and brute-force.

**Evidence vs. Assets** — modules only ever emit *Evidence* (a raw observation).
The **Correlation Engine** is the sole writer of *Assets*. It dedupes, merges
evidence from multiple modules into one asset, raises confidence when independent
sources agree, assigns an interest level, and builds relationships. The Asset
Graph is the deliverable; Evidence is the paper trail.

**Scope classification** — every outbound request's target is classified:

| Status | Meaning | Active modules |
|---|---|---|
| `in_scope` | matches `scope.in_scope` | scanned normally |
| `flagged` | a subdomain of an in-scope domain that has **no** `*.` wildcard entry, or otherwise ambiguous | skipped unless you tick **Allow flagged/excluded** |
| `excluded` | matches `scope.excluded` | **never touched**, override or not |
| `n/a` | third-party (OSINT calls) | always allowed, rate-limited |

**Audit log** (`/audit`) — append-only by construction; there is no update or
delete path anywhere in the code. Every request: timestamp, module, method +
target, scope decision, response status/size, and the RoE hash.

**Kill switch** — the red **STOP** button in the top nav engages a global
cancellation token. Every running module checks it cooperatively and stops
within a beat. A banner then appears across every page with a **Reset** button;
clear it before you can start another scan.

---

## 4. Writing an RoE

Create an engagement two ways: the guided form at **`/engagements/new`**, or
paste/upload a YAML file. Examples live in [`../engagements/`](../engagements/)
(`example.yaml` is the annotated reference).

### Minimum viable RoE

Scanning engagement:

```yaml
engagement:
  name: "Acme - External Pentest"
  client: "Acme Corp"
  authorized_window:
    start: "2026-09-01T00:00:00Z"
    end: "2026-09-30T23:59:59Z"

scope:
  in_scope:
    domains:
      - "acme.com"
      - "*.acme.com"        # authorises subdomains — see the wildcard note
```

OSINT-only engagement (no scanning, so **no `scope:` block needed**):

```yaml
engagement:
  name: "Acme - OSINT"
  client: "self / research"

osint:
  enabled: true
  company: "Acme Corp"
  seed_domains: ["acme.com"]
  github_org: "acme"        # pin it — see the github_org note in §5
```

### Full schema

```yaml
engagement:
  name: str                 # required
  client: str               # required
  authorized_window:        # optional, but recommended
    start: <ISO-8601 datetime>
    end:   <ISO-8601 datetime>   # must be after start
    enforce: warn | hard        # default warn. NOTE: `hard` is parsed but not yet
                                # wired into the scan gate — out-of-window activity
                                # is currently warned, not blocked (later wave).

scope:                      # required UNLESS osint.enabled
  in_scope:
    domains: [str]          # "acme.com" or "*.acme.com"
    cidrs:   [str]          # "203.0.113.0/24" — max /24 v4, /120 v6
    hosts:   [str]          # "app.acme.com" — no wildcards here
  excluded:
    domains: [str]          # excluded ALWAYS wins over in_scope
    cidrs:   [str]
    hosts:   [str]

rate_limits:
  max_requests_per_second: 10     # 0 < x <= 1000. Also caps nmap --max-rate and ffuf.
  max_concurrent_connections: 20  # 0 < x <= 1000

evasion:
  jitter:
    enabled: true
    min_ms: 100             # 0..120000, min <= max
    max_ms: 1500
  user_agents: [str]        # rotated per request; empty => one default UA
  rotation_strategy: round_robin | random

llm:
  analysis_enabled: false   # true => this engagement's data may be sent to the LLM endpoint

osint:
  enabled: false
  company: str              # searched in crt.sh O=, GitHub, etc.
  seed_domains: [str]       # PIVOT POINTS for OSINT — not added to scan scope
  github_org: str | null    # exact GitHub org/user slug; null => (fragile) search

recon:                      # OPTIONAL — every key has a default; a v1 RoE with no
                            # `recon:` block loads unchanged.
  passive_sources:
    disable: [str]          # names of keyless passive sources to skip
  recursion:
    max_rounds: 2           # subdomain-recursion depth (0..5)
  permutation:
    wordlist: str | null    # path; null => bundled permutation list
    max_candidates: 5000    # 0..200000
  takeover:
    engine: native          # native | subzy | nuclei
  git_secrets:
    clone_depth: full       # full | shallow
    verify: false           # true => trufflehog live verification (opt-in accelerator)
  cve:
    source: local           # local (bundled/refreshable index) | nvd_api (keyless live)
    subset: kev_high        # kev_high (CISA KEV + CVSS>=7) | full
  screenshots:
    enabled: true           # bundled Chromium; self-disables cleanly if absent
  templates:
    engine: native          # native (exposure_checks) | nuclei
    min_severity: low        # info | low | medium | high | critical
    exclude_tags: [intrusive, dos, fuzz]
```

> The `recon:` block is parsed and validated now (Wave 0). The modules that read
> each sub-block land across Waves 1–3; unknown keys/values are rejected at
> engagement creation.

### RoE gotchas

- **The wildcard rule.** `in_scope.domains: ["acme.com"]` authorizes *only*
  `acme.com`. Discovered subdomains like `api.acme.com` become **`flagged`**, and
  active modules skip them. Add `"*.acme.com"` to authorize the subtree. The
  engagement-creation linter warns you about this.
- **`excluded` always wins.** If a host matches both lists, it's excluded.
- **`seed_domains` ≠ scope.** OSINT will enrich a seed domain, but passive/active
  modules won't touch it unless it's *also* under `scope.in_scope.domains`. This
  is deliberate — you can profile a company without authorization to scan it.
- **No `authorized_window`** ⇒ time-window checks are skipped (the linter warns).
- **YAML anchors/aliases are rejected** (alias-bomb defense). 256 KB max.
- Editing the RoE of an existing engagement: recreate the engagement, or (advanced)
  patch `roe_config` + rehash. The guided form doesn't edit in place.

---

## 5. The modules

Pick modules on the **`/scans`** page (checkboxes, grouped by phase), then
**Start scan**. Dependencies are pulled in automatically and the run is ordered
by phase. Each module degrades gracefully: missing input ⇒ it logs "nothing to
do" and the run continues.

### OSINT phase

Needs `osint.enabled: true` with a `company`, `seed_domains`, and/or `github_org`.
All calls are audited as `n/a` scope and rate-limited.

| Module | Needs | What it does | Notes / gotchas |
|---|---|---|---|
| **`ct_org`** | seed_domains and/or company | crt.sh twice: by domain (→ subdomains) and by **organisation name** in the cert `O=` field (→ domains the company owns that you didn't know about). Emits `subdomain`, `domain`, `organization` + `owns`. | crt.sh is genuinely flaky — occasionally returns 0 rows. Just re-run. 12-min cap. |
| **`rdap`** | seed_domains | RDAP/WHOIS per domain: registrant org, registrar, created/updated/expiry dates, status flags, nameservers. Then resolves the A record and reverse-RDAPs the IP → `netblock` (CIDR) + hosting org. | `.org` via PIR is slow (45 s timeout per domain). Flags expiry < 30 days and hold/pendingDelete states as findings. |
| **`github_org`** | `github_org` slug (strongly preferred), or company + seed_domains | Resolves the GitHub account (User *or* Org), enumerates public repos (language, topics, activity, homepage) → `repository` + one org-level `tech_stack` finding. For a real Org, also public members → `person` + `employed_by`. | **Pin `osint.github_org`.** Name search is unreliable: GitHub's relevance ranking often doesn't surface the right account, and a common company name collides with unrelated look-alike orgs. A name-only match is *rejected* whenever seed_domains are set and none corroborate (blog host / email / bio must reference a seed domain). Set `RECON_OSINT_GITHUB_TOKEN` to raise the API limit 60→5000/hr. |
| **`wayback`** | seed_domains | Internet Archive CDX API: every historical URL under each domain. Emits `subdomain` (hosts no longer live), `document` (archived files/dumps), `url` (paths matching an interest pattern: admin, api, backup, .git, …). | Skips framework build noise (`/_next/`, `/static/chunks/`) and standard web plumbing (robots.txt, sitemap.xml, feeds, `.well-known/*`). Caps at 2000 emitted rows. 10-min cap. |
| **`internetdb`** | resolved IPs (from `dns`) | Shodan **InternetDB** (`internetdb.shodan.io`, **keyless, no account**): one GET per in-scope resolved IPv4 → open ports + CPEs (`service` evidence), PTR hostnames (`subdomain`/`domain`), and Shodan's precomputed **known-CVE list** (`cve` findings, `notable`). Zero packets to the target. | IPv4 only; 404 = "Shodan has nothing", not an error. Feeds `cve_correlate` (Wave 2) for free. |
| **`search`** | a search backend configured (see §7) + company/seed_domains | Runs ~14 dork templates through SearXNG or Google CSE: `filetype:` file discovery, `intitle:"index of"`, login/admin panels, `-inurl:www` subdomains, secret-keyword pages, code/paste-site/cloud-storage mentions, LinkedIn staff, social profiles. | No-ops silently if no backend. Company-name dorks (people/social/cloud) require the company string in the result to cut LinkedIn noise. `files`/`config` hits only become `document` assets if the URL actually resolves to a file. Confirmed emails from result snippets only — never guessed addresses. |

### Passive phase

Touch the target as a normal client would. 15-min cap each. Chain order:
`ct_subdomains → dns → probe_http → http_analyzer → crawler → js_analyzer`.

| Module | Needs | What it does | Notes |
|---|---|---|---|
| **`dns`** | `in_scope.domains` | Resolves A/AAAA/CNAME/MX/NS/TXT/SOA/CAA for each apex + known host. Flags missing DNSSEC. Feeds `port_scan`/`dns_axfr`/`subdomain_brute`. | Has a per-resolver circuit breaker; tighter timeouts for apex vs. host record types. |
| **`ct_subdomains`** | `in_scope.domains` | crt.sh CT logs → `subdomain` assets. | 90 s timeout. Overlaps `ct_org` — running both is fine, they dedupe. |
| **`probe_http`** | known hosts (from `dns` / CT / passive sources) | Liveness bridge: probes `https://` then `http://` on every discovered host, follows the audited redirect chain, records final status + page `<title>` + `Server` + scheme → `url` + `service` + `tech` + `redirect` evidence. This is the input filter the crawler / js_analyzer / screenshot / active phase all work from. | `https` answering ends the probe for that host (no redundant `http` hit). Connection refusals are silent; only timeouts get an error row. Distinct from `http_analyzer` (which digs into header/TLS posture). |
| **`http_analyzer`** | hosts (from scope + discovered subdomains) | Probes HTTP+HTTPS: redirect chains, response + security headers (present *and* absent → negative findings), disclosing headers, cookies + flags, TLS cert, tech fingerprint. | Depends on `dns` + `ct_subdomains`. Missing security headers show up in the report's "Missing controls" section. |
| **`crawler`** | in-scope web hosts (or seed URLs) | BFS-crawls each host: links, forms + params, `<script>` src, robots.txt, sitemap.xml. Feeds `js_analyzer` and `dir_fuzz`. | Seeds both http and https; uses whichever scheme actually answered. Won't wander off in-scope hosts. |
| **`js_analyzer`** | JS files (from `crawler`) | Parses each script for API endpoints, params, library fingerprints, and **leaked secrets** (API keys, tokens — redacted in output). | Secret matches are frequently placeholders in minified libs — treat as *notable*, verify by hand. |

### Active phase — behind the checkpoint

Only run after you click **Proceed to active modules**. Scope-gated to
`in_scope` targets; `flagged` needs the override tick; `excluded` never.

| Module | Needs | What it does | Notes / gotchas |
|---|---|---|---|
| **`port_scan`** | `in_scope` hosts/CIDRs + `dns` | **nmap** `-sV --top-ports 1000`, SYN when privileged else `-sT`, `--max-rate` = your RoE rps, `-n -T4`, 5-min host timeout. Collapses names that resolve to the same IP so a box is scanned once. | Missing nmap ⇒ skips. Without a banner nmap prints a port-number *guess* for the service name (e.g. 3001→"nessus") — don't trust unconfirmed service IDs. Bump `rate_limits` for a lab; keep it low for production. |
| **`dir_fuzz`** | web roots + `http_analyzer` | **ffuf** content discovery with soft-404 similarity clustering. Uses a confirmed URL root instead of guessing `https://host/`. | Bundled wordlist is **116 entries** — fast smoke only. Point `RECON_FUZZ_WORDLIST` at SecLists for real work; `RECON_FUZZ_MAX_PATHS` caps it (default 4000). |
| **`dns_axfr`** | `in_scope` apex domains + `dns` | Attempts an AXFR zone transfer against each nameserver. A successful transfer is a **high-value** finding; a refusal is negative evidence. | `dns_record` rows capped at 1000/zone with a `truncated` flag. |
| **`subdomain_brute`** | `in_scope` apex domains + `dns` | Wordlist brute-force of subdomain labels, with wildcard-DNS detection (skips zones that resolve everything). | 20-min cap. Skips apexes that aren't real DNS zones (no SOA/NS) — a `.lan` name pointing at one box won't send it into a resolver-timeout spiral. Every query is rate-limited. |

---

## 6. The workflow, end to end

1. **Create the engagement** — `/engagements/new` or upload a YAML. Read the
   linter advisories it shows you (missing wildcard, LLM enabled, seed domains
   not scoped, no window).
2. **Make it active** — select it in the top nav.
3. **Scan** — `/scans`, tick modules, **Start**. You land on the live run page:
   per-module status + duration, a progress bar (indeterminate for nmap/ffuf),
   and a streaming log. The page updates over a WebSocket — no reloads.
4. **Checkpoint** — when passive finishes, the run pauses. Open `/assets`,
   review what's known. Then **Proceed to active modules** (or **Cancel scan**).
   - Tick **"Allow requests to flagged / excluded targets"** *before starting* if
     you need active modules to hit `flagged` subdomains. `excluded` is still
     never touched.
5. **Correlation** runs automatically after each phase. Browse `/assets` — filter
   by type, interest, or scope; each tile on the dashboard and Assets page links
   to a filtered view. Click an asset for its evidence trail.
6. **(Optional) LLM analyst** — `/reports` → **Run analyst assessment** (see §8).
7. **Report** — `/reports` → download **HTML / PDF / JSON**, **Internal** or
   **Client (redacted)**. Internal includes the analyst assessment and raw
   context; client strips raw bodies, filesystem paths, secret context, and the
   RoE itself.

Resume a paused/interrupted run from its run page — module-level resumability
means completed modules aren't re-run.

---

## 7. Search backend (for the `search` module)

Self-hosted **SearXNG** is the only realistic free backend. As of 2026 the hosted
search APIs have closed their free doors: Google's Custom Search JSON API is shut
to new customers (full retirement Jan 2027) and new Programmable Search Engines
can't search the whole web; Microsoft retired the Bing Search API in Aug 2025;
Brave dropped its free tier in early 2026. SearXNG scrapes public engines
directly — no key, no account.

### Run it

```bash
docker run -d --name searxng --restart unless-stopped \
  -p 127.0.0.1:8888:8080 \
  -v ~/searxng:/etc/searxng \
  searxng/searxng
```

Then in `.env`:

```
RECON_SEARCH_BACKEND=searxng
RECON_SEARXNG_URL=http://127.0.0.1:8888
```

> **Port mapping is fixed at container creation.** You cannot add `-p` to an
> existing container (Docker Desktop's GUI can't either) — `docker rm` it and
> re-run with the flag. The `-v` volume keeps your `settings.yml`. A
> `docker-compose.yml` makes the recreate a one-liner.

### `settings.yml` — hardened for unattended use

The config lives in the mounted volume. Edit it, then `docker restart searxng`.
If the volume is root-owned (or a Docker-Desktop named volume you can't reach on
the host), edit through a throwaway container:

```bash
docker run --rm -i -v <volume-or-path>:/etc/searxng alpine sh -c \
  'cat > /etc/searxng/settings.yml' < settings.yml
```

```yaml
use_default_settings: true

server:
  secret_key: "change-me"
  limiter: false            # the rate limiter blocks API-style (JSON) access
  image_proxy: true

search:
  safe_search: 0
  formats: [html, json]     # JSON is off by default — the module needs it
  suspended_times:          # how long a blocked engine is sidelined, not retried
    SearxEngineAccessDenied: 3600
    SearxEngineCaptcha: 3600
    SearxEngineTooManyRequests: 1800

outgoing:
  request_timeout: 10.0
  max_request_timeout: 20.0
  retries: 1

engines:
  # These answer reliably from a residential IP AND honour site: / filetype: /
  # inurl: / intitle:. Bing + Qwant are independent indexes, so one covers the
  # other when it gets throttled.
  - {name: bing, disabled: false}
  - {name: qwant, disabled: false, timeout: 8.0}
  - {name: mojeek, disabled: false}
  - {name: duckduckgo, disabled: false, timeout: 10.0}
  # Need an API key, or CAPTCHA / rate-limit a single IP within a few queries:
  - {name: google cse, disabled: true}
  - {name: startpage, disabled: true}
  - {name: brave, disabled: true}
```

**Why this set:** the big engines (Google, Startpage, Brave) CAPTCHA or
rate-limit a lone scraping IP within a handful of queries. Bing and Qwant
tolerate it and both support every dork operator the `search` module uses.
DuckDuckGo and Mojeek are kept as bonus sources — they fail often (DDG times out,
Mojeek ignores advanced operators) but cost nothing when they do.

**Check it's working:**

```bash
curl -s 'http://127.0.0.1:8888/search?q=site:github.com+fastapi&format=json' \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); \
      print(len(d["results"]), "results via", sorted({r["engine"] for r in d["results"]}))'
```

Expect ~15–20 results via `['bing', 'qwant']`. `results: []` with
`unresponsive_engines` full of "CAPTCHA" / "too many requests" means the engines
are throttled — wait it out, or add another tolerant engine.

### Legacy: `google_cse` backend

The code still has a `google_cse` backend (`RECON_SEARCH_BACKEND=google_cse` +
`RECON_GOOGLE_CSE_KEY` + `RECON_GOOGLE_CSE_ID`). It only works if you already
hold a pre-2026 whole-web Custom Search Engine, and Google retires the API on
1 Jan 2027. If both those vars are set alongside `RECON_SEARCH_BACKEND=searxng`,
an empty SearXNG result auto-retries against CSE — but assume this path is
unavailable for any new setup.

With `RECON_SEARCH_BACKEND=off` (default) the `search` module no-ops.

---

## 8. LLM analyst

Optional. Takes the correlated graph, sends the **client-redacted** version to an
OpenAI-compatible `/chat/completions` endpoint, and stores a structured
assessment: a summary (with false-positive call-outs), prioritized targets, and
concrete *recon-only* next steps. An exploitation-advice filter strips any
next-step that crosses into credential/exploit territory.

**Two consent gates:**

1. The endpoint must be configured in `.env` (below).
2. The engagement's `llm.analysis_enabled` must be `true` — this is the "recon
   data leaves this host" switch. The creation linter flags it loudly.

**Configuration** (`.env`, gitignored, mode 600):

```
RECON_LLM_BASE_URL=http://localhost:8080/v1   # any OpenAI-compatible endpoint
RECON_LLM_API_KEY=sk-...                       # if the endpoint needs one
RECON_LLM_MODEL=your-model-name
RECON_LLM_TIMEOUT_SECONDS=300
RECON_LLM_MAX_TOKENS=3000      # 0 = let the server decide (some default very low)
```

Works with a local runtime (vLLM, Ollama's `/v1`, llama.cpp server, LM Studio) or
any hosted OpenAI-compatible gateway you're authorized to use. Some gateways
expose the API under `/api` rather than `/v1` — match `RECON_LLM_BASE_URL` to
whatever `<base>/models` responds on. Large models can take 1–5 min per run and
the browser blocks while it waits.

Run it from `/reports` → **Run analyst assessment**. The result shows on that
page and is embedded in the internal report.

---

## 9. Configuration reference

`RECON_`-prefixed env vars, or a `.env` file in the project root.

| Var | Default | Notes |
|---|---|---|
| `RECON_HOST` / `RECON_PORT` | `127.0.0.1` / `8000` | |
| `RECON_SESSION_IDLE_TIMEOUT_MINUTES` | `60` | sliding session expiry |
| `RECON_SESSION_COOKIE_SECURE` | `false` | set `true` behind HTTPS |
| `RECON_DATA_DIR` | `./data` | holds `recon.db`, `reports/`, `artifacts/`, `.secret_key` |
| `RECON_DATABASE_URL` | `sqlite+aiosqlite:///data/recon.db` | SQLAlchemy async URL |
| `RECON_ARTIFACTS_DIR` | `./data/artifacts` | content-addressed blob store |
| `RECON_ARTIFACT_SOFT_CAP_BYTES` | `2147483648` | per-engagement soft cap → warning |
| `RECON_BOOTSTRAP_ADMIN_USER` / `_PASSWORD` | — | one-shot first operator on an empty user table (headless bring-up) |
| `RECON_SERVER_URL` | — | CLI default for `--server` (REST mode) |
| `RECON_API_TOKEN` | — | CLI bearer token for `--server` mode |
| `RECON_FUZZ_WORDLIST` | bundled `common.txt` (116 lines) | point at SecLists |
| `RECON_FUZZ_MAX_PATHS` | `4000` | hard cap on fuzz candidates |
| `RECON_OSINT_GITHUB_TOKEN` | — | raises GitHub API 60→5000/hr |
| `RECON_SEARCH_BACKEND` | `off` | `off` / `searxng` / `google_cse` |
| `RECON_SEARXNG_URL` | — | e.g. `http://127.0.0.1:8888` |
| `RECON_GOOGLE_CSE_KEY` / `_ID` | — | for the `google_cse` backend |
| `RECON_LLM_BASE_URL` / `_API_KEY` / `_MODEL` | localhost | OpenAI-compatible endpoint |
| `RECON_LLM_TIMEOUT_SECONDS` | `120` | |
| `RECON_LLM_MAX_TOKENS` | `3000` | analyst reply cap; `0` = server default |

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| A module shows **"nothing to do"** | It had no input. `dns`/`ct_subdomains` need `in_scope.domains`; `http_analyzer`/`crawler` need hosts; active modules need in-scope targets and a prior `dns` run. A bare-IP scope with no DNS names gives most passive modules nothing — point at named hosts. |
| **`search` did nothing** | No backend. Set `RECON_SEARCH_BACKEND` + the URL/keys (§7). |
| **`github_org` found the wrong org** | Name search is fragile. Set `osint.github_org` to the exact slug. The account may be a User, not an Org — that's supported, just pin it. |
| **`port_scan` / `dir_fuzz` skipped** | `nmap` / `ffuf` not on `PATH`. Arch: `sudo pacman -S nmap ffuf`. |
| **PDF export errors** | WeasyPrint native libs missing (§2). Use HTML/JSON meanwhile. |
| **crt.sh returned nothing** | It's flaky. Re-run the scan; `ct_org`/`ct_subdomains` degrade gracefully. |
| **Analyst: "endpoint unreachable"** | Wrong base URL, or the model server is down. Check `<base_url>/models` responds. |
| **Analyst reply is short** | Raise `RECON_LLM_MAX_TOKENS`; some backends default it very low. |
| **Scan won't start: "kill switch engaged"** | Hit **Reset** on the GLOBAL STOP banner. |
| **Stale page after deleting an engagement** | Hard-refresh; responses are `no-store` but a bfcache hit can linger. |
| **`database is locked`** | Two things writing SQLite at once (e.g. a scan while you run an offline script). Stop one. |
| **Can't log in / lost password** | `uv run python -m recon reset-auth --yes`, then re-do `/setup`. No recovery. |

---

## 11. Architecture (for extending it)

- **`recon/orchestrator/`** — the engine's internal API. The web dashboard is a
  thin client over it; a CLI would be another client with no engine change.
- **`recon/modules/`** — one job per module, all I/O through `ModuleContext`
  (`recon/modules/CONTRACT.md`). A module never writes the DB or makes a raw
  request; it calls `ctx.http.request(...)` and `ctx.add_evidence(...)`.
- **`recon/net/http_client.py`** — the single audited, rate-limited, scope-gated,
  redirect-aware outbound path. Jitter + UA rotation + adaptive backoff, all from
  the RoE. Third-party OSINT calls pass `is_target=False`.
- **`recon/correlation/engine.py`** — the only writer of `Asset`. Canonicalizes
  values, merges evidence, scores confidence, assigns interest, builds relationships.
- **`recon/reporting/`** — `collect` (build one graph) → `redaction` (internal vs
  client, recursive value-based scrub) → `render` (HTML/JSON always, PDF if libs).
- Enum columns are `native_enum=False` VARCHARs — adding an `AssetType` /
  `ModulePhase` / `RelationshipType` value is a code change, **no migration**.
- **Adding a module**: subclass `ReconModule`, set `name` / `phase` /
  `depends_on` / `description`, implement `async def run(self, ctx)`, `@register`
  it, and import it in `recon/modules/<phase>/__init__.py`. Add a
  `tests/test_module_*.py` using `tests/harness.py`'s `FakeHTTP`.
