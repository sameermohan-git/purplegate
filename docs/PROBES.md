# Probes reference

Every probe wraps a widely-used OSS scanner (or is a small custom check) and
normalizes its output into the internal findings schema
(`config/schemas/findings.schema.json`).

The Action does not re-implement any scanner. If you disagree with a finding,
tune the underlying tool's config.

## `secrets`

Wraps **gitleaks** + **trufflehog** (`--only-verified`).

- `gitleaks` finds candidates fast; high-entropy detectors + regex.
- `trufflehog` re-scans candidates and **verifies live credentials** against the
  provider's API. Verified hits are Critical; unverified high-entropy matches are High.
- Scans current tree AND history back to `probes.secrets.history_commits` (default 200).
- Custom patterns from `secrets.patterns` in your config are merged into the gitleaks rule set.

**Common false positives:** test-fixture tokens like `sk_test_...` — mark with
`# pragma: allowlist secret` in the source, or add a finding to your allowlist.

## `sast`

Wraps **Semgrep CE** with curated rule packs:
- `p/python`, `p/javascript` — language defaults.
- `p/fastapi`, `p/flask` — framework-specific auth gaps, CORS, path-param injection.
- `p/owasp-top-ten`.
- Our custom pack — FastAPI `Depends()` without any auth dep from your config, SQL migrations without RLS, unsafe `subprocess` with user input.

We deliberately skip Bandit (high false-positive rate on `subprocess`); the
Semgrep `p/python` pack covers equivalent CWEs with fewer FPs.

## `deps`

Three scanners, merged and deduped:
- **osv-scanner** (Google) — OSV feed, primary source of truth.
- **pip-audit** (PyPA) — secondary for Python.
- **npm audit** — secondary for JS/TS.

Severity maps directly from upstream CVSS: Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0.

**Reachability:** we do NOT currently filter by whether the vulnerable function
is reached. Every CVE in a declared dep appears as a finding. Use your
allowlist for known-unreachable false positives.

## `iac`

- **Checkov** for Terraform / GitHub Actions / Kubernetes / CloudFormation.
- Custom Semgrep pack for Supabase:
  - `CREATE TABLE public.X` without `ENABLE ROW LEVEL SECURITY` → Critical.
  - Table with RLS but no `CREATE POLICY` for at least SELECT → High.
  - Optional: if `SUPABASE_DB_URL` env is set, queries `pg_tables` for live catalog drift.

## `workflows`

- **zizmor** (zizmorcore) — the standout tool for GitHub Actions supply-chain flaws.
  - Template injection in `run:` steps.
  - `pull_request_target` with untrusted input.
  - Missing `persist-credentials: false` on `checkout`.
  - Overly broad `permissions:`.
- **actionlint** — syntax + shellcheck inside `run:` + expression hygiene.

## `prompt_injection`

See [`../THREAT_MODEL.md`](../THREAT_MODEL.md#threat-model-inputs) and the main README.
Short form:

- Framework: **promptfoo** with its `owasp:llm` preset.
- Corpora (vendored): Lakera Mosscap, Lakera Gandalf `ignore_instructions`,
  plus `custom_chat.yaml` / `custom_voice.yaml` / `custom_receipt.yaml` shipped in this repo.
- Consumer can supply additional packs via `probes.prompt_injection.custom_packs`.
- Judge: isolated Claude (Sonnet) via Message Batches; G-Eval JSON rubric;
  attacker input is sanitized (code blocks + base64 stripped) before reaching the judge.
- Deterministic: `temperature=0` + fixed seed + cached responses; verdict requires
  ≥ 2/3 agreement across 3 repetitions.

Recall is ≤ 80% on novel attack patterns. This probe is a safety net, not an oracle.

## `mcp`

Static scan only (no runtime testing):
- Parses `.claude/settings*.json`, `claude_desktop_config.json`, and any path listed in `mcp.configs`.
- Flags:
  - Secret literals (API keys, tokens) hardcoded instead of `${ENV_VAR}` indirection → Critical.
  - MCP servers without a tool allowlist → High.
  - MCP servers granted filesystem access to repo root → High.
  - `dangerouslySkip*` / `allowAllTools` patterns → High.
  - MCP SDK dependencies pinned to versions < known patched (feed: `vulnerablemcp.info` + GHSA) → Critical/High per advisory.

Does NOT start any MCP server or send live tool calls.

## `sbom`

**Syft** — generates SPDX + CycloneDX for the consumer repo and, when run with a
`Dockerfile:` input, for the built image.

SBOM findings are informational; the severity gate ignores them. The SBOMs are
attached as artifacts for downstream consumption (compliance, vulnerability
correlation, etc.).

## `headers`

Optional. Runs only when `target-url` is provided.

- Fetches `/`, `/api/v1/health`, and any path in `probes.headers.sample_paths`.
- Checks CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options.
- Severity: Missing CSP → Medium; suboptimal Referrer-Policy → Low.

## Probes we explicitly don't include (and why)

| Tool | Reason |
|---|---|
| **Bandit** | Covered by Semgrep `p/python` with fewer FPs. |
| **SonarQube Community** | Heavy, Java-biased, opaque telemetry; not a fit for an OSS GitHub Action. |
| **tfsec** | Deprecated, absorbed into Trivy. We use Checkov for IaC. |
| **Grype** | Overlaps with osv-scanner; Grype is better paired with Trivy for container scanning, which is out of scope for v1. |
| **HarmBench / AdvBench** (as CI corpora) | MIT-licensed but contain toxic content. Fine for lab research, inappropriate as a CI dependency. |
