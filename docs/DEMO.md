# Demo runbook — full-chain scan of the Nmap Project

A ~10-minute walkthrough that exercises all three phases (OSINT → passive →
active), the RoE / checkpoint / audit safety model, the correlated Asset Graph,
and the LLM analyst — against a target that is unambiguously legal to scan.

**Target:** `scanme.nmap.org` — the host the Nmap Project runs specifically for
people to practise against ("do not scan it more than a few dozen times a day").
OSINT is done on `nmap.org` and never sends a packet to it. `nmap.org` itself is
excluded from scanning.

RoE: [`../engagements/nmap-demo.yaml`](../engagements/nmap-demo.yaml).

---

## Before class

Run the scan once so you have a populated engagement to walk through — a live
scan mid-class is at the mercy of the classroom network, crt.sh, and
archive.org. You can still *start* a fresh scan in front of the room to show the
live OSINT log streaming, then switch to the prepared one.

1. `uv run python -m recon serve` → log in.
2. **Engagements → New → Advanced (raw YAML)** → paste `nmap-demo.yaml` → Create.
   Note the linter advisories it prints (they're talking points, see below).
3. Make it the active engagement (top nav).
4. **Scans** → tick: `ct_org`, `github_org`, `rdap`, `wayback`, `dns`,
   `ct_subdomains`, `http_analyzer`, `crawler`, `js_analyzer`, `port_scan`,
   `dir_fuzz` → **Start**.
   - Skip `search` (needs SearXNG, and its output is noisier than it's worth for
     a demo). `dns_axfr` / `subdomain_brute` will just no-op here — include them
     only if you want to show a module reporting "nothing applicable."
5. At the checkpoint, review `/assets`, then **Proceed to active modules**.
6. Let it finish (~5–8 min total). Confirm `/reports` renders and run the
   **analyst assessment** so it's cached.

Expected shape (numbers vary run to run):

| | |
|---|---|
| Assets | ~130 |
| OSINT | orgs `nmap`, `linode`; 7 repos (`nmap/nmap`, `npcap`, `ncrack`, …); 3 public members (`fyodor`, `cldrn`, `hsluoyz`); netblocks `50.116.0.0/18` + `2600:3c00::/24` (Linode); subdomains `issues.` / `svn.` from CT |
| Active | `scanme.nmap.org` @ `45.33.32.156` — **22** ssh OpenSSH 6.6.1p1, **80** Apache 2.4.7, **9929** nping-echo, **31337** tcpwrapped |
| Findings | ~13 finding assets + ~11 "missing control" negatives (no CSP/HSTS/X-Frame-Options on scanme's Apache) |
| Audit | ~80 requests, every one classified + hashed |

---

## The walkthrough

**1. Frame it (30s).** "Authorized-recon orchestration. Three phases, one
correlated asset graph, an LLM analyst on top. Everything is gated by a
Rules-of-Engagement file and written to an append-only audit log."

**2. The RoE (1 min).** Open `nmap-demo.yaml`:
- `osint:` block — company + seed domain. "This authorizes third-party lookups,
  not scanning."
- `scope.in_scope.hosts: [scanme.nmap.org]` — "the only thing active modules will
  touch."
- `scope.excluded` — `nmap.org`, `www.nmap.org`. "Explicit deny. Even if I tick
  the override box, excluded hosts are never scanned."
- The linter advisory *"seed_domains are pivot points only … passive/active
  won't touch them"* — "the tool tells me my OSINT seed isn't in scan scope.
  That's the design."
- The linter advisory *"llm.analysis_enabled is TRUE … data will be sent to the
  configured endpoint"* — "consent gate. Off by default."

**3. OSINT phase (2 min).** Start the scan (or switch to the prepared one).
Watch the live log: `ct_org` hitting crt.sh, `github_org` resolving the `nmap`
org, `wayback` pulling the CDX index. Then open `/assets`:
- `organization` → Nmap, plus **Linode** (discovered as the *hosting* org via
  reverse-RDAP on the netblock — "the tool figured out where they host").
- `repository` → the 7 nmap repos. `person` → 3 public GitHub members.
- `subdomain` → `issues.nmap.org`, `svn.nmap.org` — from Certificate
  Transparency, not from touching nmap.org.
- "None of this sent a packet to an nmap server."

**4. The checkpoint (30s).** "Passive is done, correlation ran, and the scan
**stopped**. Nothing active fires until I approve." Show the panel → **Proceed**.

**5. Active phase (1.5 min).** `port_scan` runs nmap against scanme → the four
famous ports. `dir_fuzz` runs ffuf. Show a module's live progress bar.

**6. The Asset Graph (2 min) — the payoff.** `/assets`:
- Filter to `interest = high_value / notable`.
- Click the `45.33.32.156:80` **service** asset → its evidence trail: nmap said
  "Apache httpd 2.4.7", http_analyzer confirmed it from the `Server:` header —
  two independent sources, so confidence is higher.
- Show a **finding**: missing security headers on scanme's Apache, with the
  header list.
- "Modules only ever write *evidence*. One component — the correlation engine —
  turns evidence into assets, dedupes, and scores confidence."

**7. Audit log (45s).** `/audit`. Filter by module. "Every outbound request:
timestamp, method, target, the scope decision, and the SHA-256 of the RoE that
was in force. Append-only — there is no edit or delete path in the code. If a
client asks *exactly what did you send my server*, this is the answer."

**8. Report + analyst (1.5 min).** `/reports`:
- Show the **analyst assessment** — the org profile, prioritized targets, and
  recon-only next steps (an exploitation filter strips anything that crosses the
  line).
- Download the PDF. Toggle **Internal** vs **Client (redacted)** — "the client
  copy strips raw response bodies, filesystem paths, secret context, and the RoE
  itself."
- Point at the "Documents & exposed files" section — mostly archived Nmap-book
  PDFs. "Not a finding. But the same Wayback mechanism is how you find the
  `backup.sql` someone forgot to delete three years ago."

**9. Kill switch (15s).** Point at the red **STOP** button. "One click halts
every running module. Then a banner blocks every page until you reset it."

---

## If asked "why not just run nmap?"

nmap tells you port 80 is open. This tells you port 80 is an Apache 2.4.7 box in
Linode's `50.116.0.0/18`, run by a project whose GitHub org has 7 repos and
whose CT logs leak an `issues.` and an `svn.` subdomain — correlated, confidence-
scored, with every request you made logged against a signed RoE, and a written
brief at the end. It's the orchestration and the paper trail, not the scan.
