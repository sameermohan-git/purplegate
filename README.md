# agent-redblue-ci

Red-team / blue-team security audit for agentic-AI apps, packaged as a reusable GitHub Action.
Built for FastAPI + React + Supabase + iOS repos like SaveScoutAI, but stack-agnostic.

**Status: v0 scaffold** — not yet published. Repo layout and contracts are stable;
probe implementations are being filled in behind a `status` field in each finding.

## What it does

One Action wraps a curated set of battle-tested scanners plus a prompt-injection
probe, produces SARIF + Markdown + JSON, posts a PR comment, and fails the build
on Critical/High findings. It does NOT re-implement the scanners; it orchestrates,
normalizes output, and gates on severity.

| Probe | Wraps | Catches |
|---|---|---|
| `secrets` | [gitleaks](https://github.com/gitleaks/gitleaks) + [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` | Committed API keys, private keys, `.env*` leaks |
| `sast` | [Semgrep CE](https://github.com/semgrep/semgrep) with curated rule packs | FastAPI auth gaps, SQLi, unsafe `subprocess`, XSS |
| `deps` | [osv-scanner](https://github.com/google/osv-scanner) + pip-audit + npm audit | Known CVEs, merged + deduped |
| `iac` | [Checkov](https://github.com/bridgecrewio/checkov) + custom Semgrep rules | Missing RLS, misconfigured IaC, workflows |
| `workflows` | [zizmor](https://github.com/zizmorcore/zizmor) + [actionlint](https://github.com/rhysd/actionlint) | `pull_request_target` injection, template injection, missing `persist-credentials` |
| `prompt_injection` | [promptfoo](https://github.com/promptfoo/promptfoo) + Lakera corpora + isolated LLM judge | Off-topic leaks, generic advice, system-prompt extraction, jailbreaks, OWASP LLM Top 10 |
| `mcp` | Static scan | Secrets in MCP configs, missing tool allowlists, vulnerable MCP SDK versions |
| `sbom` | [Syft](https://github.com/anchore/syft) | SPDX + CycloneDX inventory (informational) |
| `headers` | HTTP fetch (optional) | Missing CSP, HSTS, X-Frame-Options when `target-url` is provided |

Findings are mapped to **OWASP LLM Top 10 v2025**, **OWASP Top 10 for Agentic Applications 2026**,
and **MITRE ATLAS v5.4.0** technique IDs in SARIF `ruleId` fields.

## Supply-chain posture

We don't ship a dependency that could trojan your build. Hard rules:

1. **Docker container action** — every tool is pre-vendored in the published image,
   pinned by SHA in the Dockerfile. No `pip install` or `npm install` at runtime.
2. **SHA-pin every third-party `uses:`** in our own CI, never tag-pin.
3. **Signed releases** — Sigstore attestation via `actions/attest-build-provenance`,
   cosign keyless image signature, SLSA L3 provenance.
4. **SBOM on every release** via Syft.
5. **OSSF Scorecard** runs on our repo on every push; target ≥ 8/10.
6. **Third-party audit gate** — new upstream deps require OSSF Scorecard ≥ 7.

See [`docs/SUPPLY_CHAIN.md`](docs/SUPPLY_CHAIN.md) for the full policy and how to
verify our releases yourself.

### Consumers should pin us by SHA or digest

```yaml
- uses: sameermohan-git/agent-redblue-ci@<40-char-sha>   # or @sha256:<digest>
```

Verify provenance before first use:
```
gh attestation verify oci://ghcr.io/sameermohan-git/agent-redblue-ci:vX.Y.Z \
  --repo sameermohan-git/agent-redblue-ci
```

### Projects we explicitly avoid and why

| Project | Reason |
|---|---|
| `tj-actions/*` | CVE-2025-30066 (Mar 2025, force-push compromise). Use `dorny/paths-filter` pinned by SHA. |
| `reviewdog/action-setup`, `-shellcheck`, `-staticcheck`, `-ast-grep`, `-typos`, `-composite-template` | CVE-2025-30154 (Mar 2025, same incident). |
| `aquasecurity/trivy-action` by tag | Tags force-pushed Mar 2026. Trivy binary is fine; we invoke it directly from our vendored image. |
| `tfsec` | Deprecated, absorbed into Trivy. |
| `protectai/rebuff` | Archived May 2025. |

## Quickstart (for consumers)

1. Add the workflow:

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on:
  pull_request:
  schedule: [{ cron: '0 6 * * *' }]
  workflow_dispatch: {}

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@<sha>   # recommended
        with: { egress-policy: audit }
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: sameermohan-git/agent-redblue-ci@<sha>
        with:
          config: .agent-redblue/config.yml
          fail-on: high
          llm-provider: anthropic
          llm-api-key: ${{ secrets.AUDIT_ANTHROPIC_KEY }}
```

2. Add a config file at `.agent-redblue/config.yml` — see [`docs/CONFIG.md`](docs/CONFIG.md).
3. Add an (initially empty) allowlist at `.agent-redblue/allowlist.yml` — see [`docs/SUPPRESSIONS.md`](docs/SUPPRESSIONS.md).

## Action inputs

See [`action.yml`](action.yml). Most important:

- `config` — path to consumer config YAML (default `.agent-redblue/config.yml`)
- `fail-on` — `critical | high | medium | low | none` (default `high`)
- `llm-provider` — `anthropic | openai | azure | none` (default `none`; disables the prompt-injection probe)
- `llm-api-key` — provider key; pass via `${{ secrets.* }}`
- `target-url` — deployed staging URL for live prompt-injection + headers probes
- `include-probes` / `exclude-probes` — comma-separated probe names

## Threat model + non-goals

See [`THREAT_MODEL.md`](THREAT_MODEL.md). Short version:
**this Action catches a specific, documented class of issues.** It does not replace a
penetration test, a human code review, or production-runtime monitoring. The
prompt-injection probe recall is ≤ 80% on novel attack patterns — mitigated by
corpus updates, not by claims.

## Repo layout

```
action.yml              # thin wrapper: runs the Docker image
Dockerfile              # reproducible multi-stage build, every tool pinned by SHA
src/
  orchestrator.py       # runs selected probes, aggregates findings
  probes/               # one module per probe; each wraps + normalizes
  blueteam/             # severity adjuster + hardening registry
  judge/                # isolated LLM-as-judge for prompt_injection
  report/               # SARIF + Markdown + gate
  taxonomy/             # vendored OWASP + ATLAS YAML
  payloads/             # vendored Lakera corpora + custom attack packs
tests/
  unit/                 # pytest per probe
  fixtures/             # vuln_* + clean_app fixtures for self-test
config/
  defaults.yml
  schemas/              # JSON schemas for consumer config + findings
docs/                   # QUICKSTART, PROBES, CONFIG, SEVERITY, SUPPRESSIONS, SUPPLY_CHAIN, TAXONOMY
.github/workflows/      # self-test, release, scorecard, audit-consumer
```

## Contributing / security

See [`SECURITY.md`](SECURITY.md) for coordinated disclosure. Pull requests welcome once the v1 scaffold is cut.

## License

MIT. See [`LICENSE`](LICENSE).
