# Engagement RoE files

Rules-of-Engagement documents for the reconnaissance platform. Each one defines
scope + evasion + OSINT policy for a single engagement; it is validated,
snapshotted, and SHA-256 hashed when the engagement is created.

- **`example.yaml`** — the annotated reference. Copy it, edit scope, create an
  engagement from it (`/engagements/new` → upload, or paste the YAML).

Your real engagement files do **not** belong in version control — `.gitignore`
excludes everything here except `example.yaml` and this README. Keep them
wherever you keep engagement paperwork.

See [`../docs/GUIDE.md`](../docs/GUIDE.md) §4 for the full RoE schema.
