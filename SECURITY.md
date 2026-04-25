# Security Policy

## Reporting a vulnerability

If you find a vulnerability in `purplegate` — whether in our probe implementations,
our Docker image, our release pipeline, or a logic bug that causes us to miss or
misreport findings — please report it privately.

**Email:** `privacy@kardoxa.com`
**GitHub Security Advisories:** https://github.com/sameermohan-git/purplegate/security/advisories/new

Do not open public GitHub issues for security reports.

## Response SLA

- **Acknowledgement:** within 72 hours.
- **Triage:** within 7 days, with severity assessment (CVSS v3.1).
- **Fix + coordinated disclosure:** within 30 days for Critical, 60 for High, 90 for Medium.
- **CVE requests** filed via GHSA for Medium+ issues.

## Scope

In scope:
- This repository's source (`src/`, `Dockerfile`, `action.yml`, workflows).
- The published container image(s) at `ghcr.io/sameermohan-git/purplegate`.
- Our released Actions tags/digests.

Out of scope (report to upstream instead):
- Vulnerabilities in wrapped tools (gitleaks, trufflehog, Semgrep, osv-scanner, Checkov, zizmor, promptfoo, Syft). Please report to their respective projects.
- Vulnerabilities in GitHub Actions platform.
- Vulnerabilities in LLM providers (Anthropic, OpenAI, Azure).

## Supported versions

Only the latest `vN` major tag and the `main` branch are actively maintained.

**Yanked tags** (do not use):

| Tag | Reason |
|-----|--------|
| `v0.1.0-alpha.6`, `v0.1.0-alpha.7` | `action.yml` expression-context bug — fail to load on consumers. Pin to `v0.1.0-alpha.9` or later. |
| `v0.1.0-alpha.8` | Image and action are functional, but the SBOM signing step failed under cosign 4.x's new bundle format, so no GitHub Release page was created and no signed SBOMs were attached. Use `v0.1.0-alpha.9` for full release artifacts. |

## Disclosure policy

- We credit reporters in release notes unless they request otherwise.
- We publish a post-mortem for any Critical or High issue that affected released versions.
- Supply-chain incidents (e.g. compromised dependency) are disclosed within 48 hours of confirmation.

## Our own supply-chain hygiene

- Every third-party `uses:` is pinned by 40-character commit SHA.
- Renovate/Dependabot proposes SHA bumps; reviewers verify each new SHA against an upstream signed release before merge.
- Dockerfile base images pinned by sha256 multi-arch index digest.
- Releases are signed (Sigstore) and accompanied by signed SBOMs (SPDX + CycloneDX, both with `.sig` + `.pem`) and SLSA L3 build provenance.
- `release.yml` permissions are scoped at job level — top-level is `contents: read`.
- CodeQL static analysis runs on every PR + push to `main`.
- OSSF Scorecard runs on every push; live score badge in the README.

See [`docs/SUPPLY_CHAIN.md`](docs/SUPPLY_CHAIN.md) for the full policy and how to verify our releases yourself.
