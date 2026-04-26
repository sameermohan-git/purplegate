# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0-alpha.10] - 2026-04-25

### Changed
- **Renamed signed-SBOM bundle file extension `.cosign.bundle` → `.sigstore`.** Same file format (Sigstore new-bundle), same content (signature + Fulcio cert + Rekor inclusion proof in one JSON), same verification command. The rename is purely so that **OSSF Scorecard's Signed-Releases check recognizes the artifacts** — Scorecard's recognized-extension list is `.sig`, `.asc`, `.intoto.jsonl`, `.sigstore`, `.dsse`, and `.cosign.bundle` is not on it. With alpha.10's new naming, Signed-Releases should lift off 0/10 over the next few releases.
- README + `docs/SUPPLY_CHAIN.md` verification commands updated to reference `<file>.sigstore`.

## [0.1.0-alpha.9] - 2026-04-25

### Fixed
- **SBOM signing step in `release.yml` failed under cosign 4.x.** `cosign-installer@v4.1.1` ships cosign 4.x, which defaults to `--new-bundle-format=true`. In that mode `--output-signature` and `--output-certificate` are silently ignored, and cosign expects `--bundle <file>` instead — so the alpha.7 / alpha.8 release runs erred at this step with `create bundle file: open : no such file or directory`. The build job failed before the "Attach SBOMs to release" step ran, so neither alpha.7 nor alpha.8 produced a GitHub Release page (the images themselves did publish + sign + attest correctly).
- Switched both `cosign sign-blob` commands to `--bundle <file>.cosign.bundle`, the Sigstore new-bundle format that packs signature + Fulcio certificate + Rekor inclusion proof in a single self-contained JSON. Updated README and `docs/SUPPLY_CHAIN.md` with the corresponding `cosign verify-blob --bundle ... --new-bundle-format` verification command.

## [0.1.0-alpha.8] - 2026-04-25

### Fixed
- **`action.yml` expression-context errors that prevented loading on consumers** (alpha.6 / alpha.7).
  - The `llm-api-key.description` field contained a literal `${{ secrets.* }}` reference. GitHub's action-parser evaluates `${{ … }}` inside description fields as expressions, and the action context does not expose the `secrets` namespace — so the parser rejected the file outright with `Unrecognized named-value: 'secrets'`. Description rephrased to plain text.
  - `runs.env.GITHUB_TOKEN: ${{ github.token }}` referenced the `github` context, which is unavailable to Docker container action `env:` blocks. Replaced with a new `github-token` input that consumers must pass via `with: github-token: ${{ secrets.GITHUB_TOKEN }}`.

### Migration notes
- **Required.** Consumers must add `github-token: ${{ secrets.GITHUB_TOKEN }}` to their `with:` block. Without it, SARIF upload to Code Scanning and PR comments are skipped (the gate itself still runs).
- alpha.6 and alpha.7 should be considered yanked — they fail to load at workflow startup. Pin to alpha.8 or later.

## [0.1.0-alpha.7] - 2026-04-25 [yanked]

> Yanked: carries the same `action.yml` expression-context bug as alpha.6. Image build, signatures, and SBOMs are valid; the action is unusable. Use alpha.8.

### Added
- **Signed SBOMs** — `sbom.spdx.json` and `sbom.cdx.json` are now signed via `cosign sign-blob` keyless. Both `.sig` and `.pem` (Fulcio-issued certificate) attach to every GitHub Release alongside the JSON files. Verifiable with `cosign verify-blob`.
- **CodeQL static analysis** workflow (`.github/workflows/codeql.yml`) — runs on every PR, push to `main`, and weekly cron. Queries: `security-extended`. Findings flow to Security → Code scanning. Closes the OSSF Scorecard SAST 0/10 check.

### Changed
- **Dockerfile base images pinned by sha256 digest** — `debian:12-slim` and both `python:3.12.7-slim-bookworm` stages are now pinned to a specific multi-arch index digest. Renovate will propose digest bumps.
- **`release.yml` permissions scoped at job level** — top-level is now `contents: read`. The `build` job opts in to the four write scopes it actually needs (`contents`, `packages`, `id-token`, `attestations`). The `verify` job is `contents: read` only. Closes the OSSF Scorecard Token-Permissions 0/10 check.

## [0.1.0-alpha.6] - 2026-04-25

### Fixed
- **GHCR image tag publication for v-prefixed semver tags.** `docker/metadata-action`'s `pattern={{version}}` strips the leading `v` from the git tag and silently rejects `pattern=v{{version}}` for pre-release versions. Switched to `type=ref,event=tag` which emits the raw git tag unchanged. Both `:v0.1.0-alpha.6` and `:0.1.0-alpha.6` now resolve to the same image digest.

## [0.1.0-alpha.5] - 2026-04-25

### Added
- Wired SARIF upload to GitHub Code Scanning, PR-comment reporting (with `<!-- purplegate-report-v1 -->` marker for idempotent updates), and workspace mirror writes to `.purplegate-reports/` for `actions/upload-artifact` consumption.

### Fixed
- `iac` probe regex now correctly matches Supabase RLS `CREATE POLICY` statements with double-quoted policy names containing internal whitespace.
- `deps` probe parses `osv-scanner` JSON regardless of exit code (osv-scanner exits non-zero on benign warnings); `pip-audit` invocation reworked to scan requirements files via `-r <file>`.

## [0.1.0-alpha.4] - 2026-04-25

### Added
- Workspace report writes to `.purplegate-reports/` so consumers can attach the JSON / Markdown / SARIF outputs to their workflow runs via `actions/upload-artifact`.
- Real CVE feed for `mcp` probe — 10 verified GHSA/NVD advisories for known-vulnerable MCP SDK versions.

## [0.1.0-alpha.2] / [0.1.0-alpha.3] - 2026-04-25

### Added
- Reproducible Docker image build via multi-stage Dockerfile (binary-fetcher → python-builder → final runtime). All scanner binaries SHA256-verified against upstream checksums (gitleaks, trufflehog, syft, actionlint) or locally-computed SHA256 (osv-scanner). Python scanners (semgrep, checkov, zizmor, pip-audit) installed into isolated pipx venvs.
- Multi-arch publishing (`linux/amd64` + `linux/arm64`) to `ghcr.io/sameermohan-git/purplegate`.
- `cosign` keyless image signing + `attest-build-provenance` (SLSA L3) attestation on every release.

## [0.1.0-alpha] - 2026-04-24

### Added
- Initial public release: orchestrator + 9 probes + blue-team severity adjuster + SARIF 2.1.0 report + gate.
- Test fixtures (`vuln_fastapi`, `vuln_supabase_sql`, `vuln_workflow`, `clean_app`, `llm_mocks`) + 37-test self-test suite.
- OWASP LLM Top 10 v2025 + OWASP Agentic 2026 + MITRE ATLAS v5.4.0 taxonomy mapping.
- Repo-level workflows: self-test, release, OSSF Scorecard, dog-food audit.
- Docs: README (10 translations), QUICKSTART, SECURITY, THREAT_MODEL, SUPPLY_CHAIN, SUPPRESSIONS.
- LICENSE (MIT) + LICENSE-3RD-PARTY.md (covers AGPL-3.0 trufflehog posture).
