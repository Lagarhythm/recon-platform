# Program Requirements Document: Integrated Reconnaissance Platform

**Document version:** 1.0
**Status:** Draft — pending open items (see Section 12)
**Audience:** AI coding agent / development team implementing v1

---

## 1. Purpose & Vision

This document specifies the requirements for a modular, authorized-use reconnaissance platform intended for real penetration testing engagements. The tool is not a replacement for best-in-class scanners (nmap, ffuf) — it is an **orchestration and intelligence layer** that wraps proven tools, normalizes their output into a unified asset model, correlates findings across sources, scores confidence based on corroborating evidence, and surfaces a prioritized attack surface to the analyst — optionally assisted by a locally-hosted LLM.

The defining principle: **every finding is an Asset with Evidence, not a line in a log file.**

### 1.1 Non-Goals (explicitly out of scope for v1)

- Exploitation of any kind. This tool performs reconnaissance and enumeration only. It identifies potential vulnerabilities (e.g., outdated software versions) for analyst review — it never attempts to exploit them.
- Reimplementing nmap/ffuf's core scanning logic from scratch. The tool wraps and orchestrates these engines.
- Automated credential use. If recon incidentally surfaces exposed credentials (e.g., in a public repo), the tool flags this for analyst awareness only — it never authenticates with discovered credentials.
- A CLI-first experience. CLI control is planned but deferred past v1 (see Section 11).

---

## 2. Guiding Principles

1. **Scope safety is a first-class requirement, not a feature.** No active module executes against a target without passing scope validation.
2. **Every outbound request is auditable.** This protects both the client and the operator in the event of a dispute during or after an engagement.
3. **Correlation over collection.** Raw tool output is an intermediate artifact, not the deliverable. The Asset Graph is the deliverable.
4. **The LLM analyzes; it does not act.** The LLM layer reads correlated, structured data and produces analysis and prioritization. It has no ability to trigger scans, modify scope, or execute commands.
5. **Multi-engagement by design.** The tool is expected to be reused across many client engagements over its lifetime — data must be cleanly partitioned per engagement from day one.

---

## 3. User & Usage Model

- **Primary user:** A single authenticated analyst (the student/operator) operating the tool during an authorized penetration test.
- **Authentication:** Required. Single-user login (username/password, hashed + salted credential storage) gates all dashboard access. No anonymous access to any engagement data, scan controls, or reports.
- **Interface (v1):** Web dashboard only, built on FastAPI. CLI control is a planned v2 addition (see Section 11) — the engine's internal API should be designed so a CLI can be added later without refactoring the core.
- **Deployment context:** Run by the analyst on a machine with network access to the target environment, per the current engagement's Rules of Engagement (RoE). The LLM is *not* local to this machine — it is hosted remotely (a configurable OpenAI-compatible endpoint) and accessed over the network.

---

## 4. Engagement & Scope Management

### 4.1 Multi-Engagement Model

The tool supports multiple, fully isolated engagements (clients/projects) within a single running instance. The analyst can switch the active engagement from the dashboard. Each engagement has:

- A unique Engagement ID
- Its own RoE configuration
- Its own Asset Graph, Evidence, Scan Runs, and Audit Log — no cross-engagement data leakage
- Its own status (active / paused / completed / archived)

All data model tables (Section 8) are scoped by `engagement_id`.

### 4.2 Rules of Engagement (RoE) Configuration

Each engagement's scope is defined in a structured config (YAML) loaded at engagement creation and re-validated before every scan run:

```yaml
engagement:
  name: "Acme Corp Q1 Pentest"
  client: "Acme Corp"
  authorized_window:
    start: "2026-09-01T00:00:00Z"
    end: "2026-09-14T23:59:59Z"

scope:
  in_scope:
    domains: ["acme.com", "*.acme.com"]
    cidrs: ["203.0.113.0/24"]
  excluded:
    hosts: ["mail.acme.com"]      # e.g., third-party hosted, explicitly excluded
    cidrs: ["203.0.113.128/28"]   # e.g., production payment infra

rate_limits:
  max_requests_per_second: 10
  max_concurrent_connections: 20

evasion:
  jitter:
    enabled: true
    min_ms: 100
    max_ms: 1500
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ..."
  rotation_strategy: "round_robin"   # or "random"
```

Jitter range and the user-agent rotation list are analyst-tunable per engagement, not hardcoded — this file is the single source of truth for both scope and evasion behavior for a given engagement.

### 4.3 Scope Enforcement Behavior

- **Default behavior: flag, do not block.** Any target (passive or active) that falls outside the `in_scope` definition or inside `excluded` is flagged in the Asset record and in the Audit Log, but the request is **not** silently blocked.
- **Override flag:** Running a module against a flagged/out-of-scope target requires an explicit `--allow-out-of-scope` parameter (surfaced in the dashboard as a confirmation step, e.g., "This target is flagged out-of-scope — proceed anyway?"). This is a conscious, per-action override, not a global toggle.
- **Time window enforcement:** If the current time falls outside `authorized_window`, active modules should warn (not silently block) the analyst before proceeding.
- All scope decisions (flagged, overridden, blocked-by-window) are written to the Audit Log with full context.

---

## 5. System Architecture

```
                         ┌─────────────────┐
                         │   Dashboard UI    │
                         │  (FastAPI + WS)   │
                         └────────┬──────────┘
                                  │ REST + WebSocket
                         ┌────────▼──────────┐
                         │   Orchestrator     │
                         │  (Engine API)      │
                         └────────┬──────────┘
                                  │
       ┌─────────────┬───────────┼───────────┬─────────────┐
       ▼             ▼            ▼           ▼             ▼
  Scope/RoE     Passive Recon  Active Recon  Correlation   Audit
   Manager        Modules       Modules       Engine       Logger
                                  │
                     ┌────────────┼────────────┐
                     ▼            ▼             ▼
                  nmap (wrap)  ffuf (wrap)  DNS/HTTP libs
                                  │
                         ┌────────▼──────────┐
                         │   Asset Graph DB   │
                         │     (SQLite)       │
                         └────────┬──────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ▼                            ▼
              LLM Analyst                 Report Generator
           (remote, read-only)          (HTML / PDF / JSON)
```

**Key architectural rule:** every module (passive or active) writes only to the `Evidence` table. Only the Correlation Engine writes to `Asset`. This keeps merge logic centralized instead of scattered across modules.

---

## 6. Functional Modules (v1)

| # | Module | Responsibility |
|---|--------|-----------------|
| 1 | Scope / RoE Manager | Loads and validates RoE config; gates every module invocation; manages engagement switching |
| 2 | DNS Engine | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA enumeration; zone transfer attempts |
| 3 | Subdomain Engine | Certificate Transparency log queries (crt.sh) + configurable wordlist brute-force |
| 4 | Web Crawler | Extracts links, forms, parameters, JS files, images, robots.txt, sitemap.xml, cookies, headers |
| 5 | JS Analyzer | Parses crawled JS bundles for endpoints, routes, and parameter names |
| 6 | Directory/File Fuzzer | Wraps `ffuf`; adds response-similarity filtering (size/word-count/hash comparison) to suppress custom-404 false positives |
| 7 | Port/Service Scanner | Wraps `nmap` (TCP connect, SYN where privileged, common + full-range profiles, `-sV` service detection, banner grabbing) |
| 8 | HTTP Analyzer | Headers, security headers (CSP/HSTS/etc.), TLS/cert details, HTTP methods, redirect chains, tech fingerprinting |
| 9 | Evasion Layer | Cross-cutting: applies jitter and UA rotation (per active RoE config) to all active-module requests |
| 10 | Correlation Engine | Deduplicates Evidence into Asset entities; computes confidence score from independent-source count |
| 11 | LLM Analyst | Sends the current Asset Graph (structured JSON) to the remote LLM endpoint; returns prioritized summary and suggested next recon steps. Read-only — no execution capability |
| 12 | Audit Logger | Records every outbound request: timestamp, module, target, in-scope status, engagement ID |
| 13 | Report Generator | Produces HTML (primary/interactive), PDF (client-deliverable), and JSON (machine-readable export) reports from the Asset Graph |
| 14 | Dashboard | Authenticated web UI: engagement switching, scan control, live progress (WebSocket), Asset Graph browser, report generation |

### 6.1 Deferred to Future Work (documented, not built in v1)

- CLI control surface
- Cloud infrastructure recon (AWS/Azure/GCP fingerprinting)
- Public code repository recon (GitHub/GitLab secret-pattern search)
- CVE correlation against detected service versions
- Email security recon (SPF/DKIM/DMARC)
- Screenshot capture of discovered web services
- Scan diffing over time (re-run and highlight changes)

---

## 7. Elite-Practitioner Additions

*(Flagged separately since these go beyond what was discussed in planning but materially strengthen the tool for real engagement use — recommend for v1 unless resource-constrained, otherwise fast-follow.)*

1. **Passive-first automatic sequencing.** The orchestrator should default to running all passive modules before any active module fires, and should present the analyst a "here's what we know before we touch anything" checkpoint. This mirrors real methodology (OSINT before you make noise) and reduces unnecessary active footprint.
2. **Negative evidence tracking.** If a module actively checks something and finds it *absent* (e.g., DNSSEC not configured, security headers missing), record that as Evidence too — absence of a control is itself a finding, and current design only models positive discoveries.
3. **Finding severity/interest tagging independent of confidence.** Confidence answers "how sure are we this asset exists." A separate `interest_level` field (informational/notable/high-value) lets the analyst and LLM distinguish "we're 100% sure this is a marketing subdomain" from "we're 60% sure this is an exposed admin panel" — conflating the two into one score loses signal.
4. **Session/state resumability.** Real engagements get interrupted (VPN drops, day ends, target goes down). Scan Runs should be resumable from last-completed-module rather than restarting an engagement's full recon from zero.
5. **Export redaction mode.** Client-facing PDF reports should support a redaction pass (e.g., strip internal file paths, exclude raw HTTP request/response bodies) separate from the full internal JSON export — client deliverables and internal working data have different sensitivity levels.
6. **Rate-limit backoff on target-side signals.** If the target starts returning 429s or connection resets increase, the Evasion Layer should auto-back-off temporarily rather than requiring the analyst to notice and intervene manually.

---

## 8. Data Model

All tables include `engagement_id` as a partition key.

```
Engagement
  id, name, client_name, roe_config (stored snapshot), 
  authorized_window_start, authorized_window_end,
  status (active/paused/completed/archived), created_at

Asset
  id, engagement_id, type (domain/subdomain/ip/url/service/finding),
  value, confidence_score, interest_level,
  in_scope_status (in_scope/flagged/excluded),
  first_seen, last_seen

AssetRelationship
  id, engagement_id, source_asset_id, target_asset_id,
  relationship_type (resolves_to/hosts/discovered_via/subdomain_of/serves)

Evidence
  id, engagement_id, asset_id, source_module,
  raw_data (JSON), discovered_at, request_metadata

ScanRun
  id, engagement_id, roe_config_snapshot, modules_run (list),
  status (running/completed/failed/paused), started_at, completed_at

AuditLogEntry
  id, engagement_id, timestamp, module, target,
  in_scope_status, request_detail, override_used (bool)

User
  id, username, password_hash, created_at, last_login
```

---

## 9. Non-Functional Requirements

- **Security:** Authenticated dashboard access only (Section 3). Passwords hashed with a strong modern algorithm (e.g., bcrypt/argon2) — never stored in plaintext. Session tokens expire after inactivity.
- **Auditability:** The Audit Log is append-only from the application's perspective — no UI path to edit or delete entries. This is the tool's legal/dispute-resolution record.
- **Performance:** Network-I/O-bound modules use async concurrency (`asyncio`/`aiohttp`); target throughput is limited primarily by the RoE's configured rate limit, not the tool's own overhead.
- **Portability:** SQLite as the default datastore keeps the tool deployable on a single analyst machine with no external DB dependency; schema should be ORM-based (SQLAlchemy) to allow a future Postgres migration without a rewrite.
- **LLM connectivity:** The LLM client points at a configurable remote OpenAI-compatible endpoint. This should be a single config value — swapping endpoints (e.g., to a different local model later) must not require code changes.
- **Resilience:** Network failures against a single target/module should not crash a Scan Run — failures are logged as Evidence-level errors and the run continues.

---

## 10. Reporting

Three output formats, generated from the same underlying Asset Graph:

1. **HTML** — primary interactive report; asset graph browsing, evidence drill-down, filterable by confidence/interest level.
2. **PDF** — client-deliverable format; supports the redaction mode described in Section 7.5.
3. **JSON** — full machine-readable export of the Asset Graph, Evidence, and metadata, for archival or feeding into other tooling.

---

## 11. Roadmap Beyond v1

- CLI control surface (same Orchestrator API the dashboard uses, so no engine changes needed — just a new client)
- Modules listed in Section 6.1
- Multi-analyst support with role-based access (if the tool moves from single-operator to team use)

---

## 12. Open Questions / Items Requiring Confirmation

These should be resolved (or explicitly deferred) before implementation begins:

1. **Password/auth mechanism specifics** — is a simple local username/password sufficient, or is there a preference for something like an environment-variable-seeded initial admin account, given this may run on a laptop carried between engagements?
2. **RoE authorized-window enforcement strictness** — Section 4.3 currently specifies a *warning*, not a block, when outside the authorized time window. Confirm this matches intent (vs. a hard block, matching the general "flag not block" philosophy) or whether time-window violations should be treated more strictly than target-scope violations.
3. **PDF generation library/approach** — no preference has been specified; will default to a standard HTML-to-PDF pipeline unless you want to weigh in.
4. **Retention/deletion policy** — should completed/archived engagements have a data retention period, or persist indefinitely until manually deleted? (Relevant for client data-handling obligations in a real engagement.)
5. **Elite-practitioner additions (Section 7)** — confirm which of these six get promoted into v1 build scope vs. logged as fast-follow/future work.

---

*End of v1 Program Requirements Document.*
