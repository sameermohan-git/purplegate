<div align="center">

<a href="docs/TRANSLATIONS.md">🇨🇳 中文</a> &middot;
<a href="docs/TRANSLATIONS.md">🇯🇵 日本語</a> &middot;
<a href="docs/TRANSLATIONS.md">🇰🇷 한국어</a> &middot;
<a href="docs/TRANSLATIONS.md">🇧🇷 Português</a> &middot;
<a href="docs/TRANSLATIONS.md">🇪🇸 Español</a> &middot;
<a href="docs/TRANSLATIONS.md">🇩🇪 Deutsch</a> &middot;
<a href="docs/TRANSLATIONS.md">🇫🇷 Français</a> &middot;
<a href="docs/TRANSLATIONS.md">🇷🇺 Русский</a> &middot;
<a href="docs/TRANSLATIONS.md">🇮🇳 हिन्दी</a> &middot;
<a href="docs/TRANSLATIONS.md">🇹🇷 Türkçe</a>

<br />
<br />

<img src="assets/logo.png" alt="purplegate" width="220" />

<br />
<br />

<img src="https://img.shields.io/badge/RED%20TEAM-8%20PROBES-d32f2f?style=for-the-badge&labelColor=424242" alt="8 probes" />
<img src="https://img.shields.io/badge/BLUE%20TEAM-DEFENSE%20SCAN-1976d2?style=for-the-badge&labelColor=424242" alt="blue team" />
<img src="https://img.shields.io/badge/TAXONOMY-OWASP%20%2B%20ATLAS-7b1fa2?style=for-the-badge&labelColor=424242" alt="OWASP + ATLAS" />
<img src="https://img.shields.io/badge/PYTHON-3.12%2B-3776ab?style=for-the-badge&labelColor=424242&logo=python&logoColor=white" alt="Python 3.12+" />

<br />

<img src="https://img.shields.io/badge/RUNTIME-DOCKER-2496ed?style=for-the-badge&labelColor=424242&logo=docker&logoColor=white" alt="docker" />
<img src="https://img.shields.io/badge/SUPPLY%20CHAIN-COSIGN%20SIGNED-2e7d32?style=for-the-badge&labelColor=424242" alt="cosign signed" />
<img src="https://img.shields.io/badge/REPORT-SARIF%202.1.0-f57c00?style=for-the-badge&labelColor=424242" alt="SARIF 2.1.0" />
<img src="https://img.shields.io/badge/SLSA-LEVEL%203-f5a623?style=for-the-badge&labelColor=424242" alt="SLSA L3" />

</div>

# purplegate — Block insecure agentic-AI merges

---

<div align="center">

**Agentic apps merge code that leaks secrets, misses RLS, or accepts prompt injection.**
**purplegate runs red-team probes and a blue-team defense scan on every PR — and fails the build before those merges ship.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions/workflows/self-test.yml"><strong>Live self-test →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/sameermohan-git/purplegate"><img src="https://img.shields.io/ossf-scorecard/github.com/sameermohan-git/purplegate?label=scorecard" alt="scorecard"/></a>
  <img src="https://img.shields.io/badge/latency-%3C4min-blue" alt="latency"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## Why purplegate

Agentic-AI apps are a new class of attack surface. Traditional SAST misses the LLM-specific bugs (prompt injection, system-prompt leakage, cross-user data exposure). Traditional security Actions miss the AI-specific supply chain (MCP servers, vendored SDKs, vulnerable corpora). You need both. purplegate is both.

- **🔴 Red-team** — eight probes covering every class of agentic-app risk: secrets, SAST, dependencies, IaC / RLS, workflow injection, **prompt injection** (isolated Claude-as-judge), MCP config risks, and HTTP security headers.
- **🔵 Blue-team** — a defense scanner that detects runtime guardrails (LLM Guard, Guardrails AI), rate limiters, and allowlisted findings — then **adjusts severity DOWN** on findings that are already mitigated. Severity is never raised above the red-team baseline.
- **🟣 Purple-team gate** — one CI action, one SARIF report. Critical / High findings fail the build by default; Medium / Low report only. Fully configurable.

## What it catches (that others miss)

| Class | Example finding | Tool |
|---|---|---|
| LLM prompt injection | "Who is Trump?" answered despite a finance-app scope guard | isolated Claude judge via promptfoo |
| System-prompt leakage | Attacker extracts your app's instructions via a crafted payload | same judge, 3-rep agreement |
| Cross-user data disclosure | App references another user's transactions when asked | purple-team dedicated probe |
| Missing Supabase RLS | `CREATE TABLE public.transactions` without `ENABLE ROW LEVEL SECURITY` | custom static check |
| Workflow command injection | `${{ github.event.issue.title }}` inside a `run:` step | wraps [zizmor](https://github.com/zizmorcore/zizmor) |
| Live credential in git | a real `sk_live_...` committed today | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| Vulnerable MCP SDK | pinned version missing the Apr 2026 Anthropic MCP RCE fix | vendored advisory feed |
| Generic advice leak | "RRSPs are generally good" from a finance app that should only answer about user data | judge rubric v1 |

Every finding maps to **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026**, and **MITRE ATLAS v5.4.0** — surfaced in SARIF `ruleId` so GitHub Code Scanning + downstream SIEM tools filter by framework.

## Quickstart

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [pull_request, workflow_dispatch]
permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@<sha>
        with: { egress-policy: audit }
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: sameermohan-git/purplegate@<sha>
        with:
          config: .purplegate/config.yml
          fail-on: high
          llm-provider: anthropic
          llm-api-key: ${{ secrets.AUDIT_ANTHROPIC_KEY }}
          target-url: ${{ secrets.STAGING_API_URL }}
```

Then add `.purplegate/config.yml` — see [`docs/CONFIG.md`](docs/CONFIG.md) for the full schema. Full walkthrough in [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Architecture

```
┌─ Consumer repo ─────────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ purplegate Docker image
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ isolated    │
                        │   │                       Claude judge│
                        │   ├─ mcp            (static scan)     │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Blue-team defense scanner            │
                        │   (severity adjuster — never raises)  │
                        ├───────────────────────────────────────┤
                        │  Report (SARIF + Markdown + JSON)     │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Supply-chain posture

This tool's single most important property is that **it does not become the attack vector it's meant to defend against** — so consumers don't have to trust us, they can verify:

- **Docker container action.** Every scanner pinned by SHA in `Dockerfile`; no `pip install` / `npm install` at runtime.
- **Every third-party `uses:` pinned by 40-char commit SHA** — never by tag. Mar 2025 (tj-actions) and Mar 2026 (trivy-action) taught us why.
- **Signed releases.** Sigstore attestation via `actions/attest-build-provenance` + cosign keyless + SLSA L3 provenance + SBOM (Syft).
- **Scorecard ≥ 8/10** target; drops below 7 block releases.
- **Verify before first use:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

Full policy in [`docs/SUPPLY_CHAIN.md`](docs/SUPPLY_CHAIN.md). Threat model in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Severity & gating

| Severity | Default gate | Examples |
|---|---|---|
| 🔴 Critical | **Fails CI** | Verified live credential · public table without RLS · workflow command injection · vulnerable MCP SDK · verified system-prompt extraction |
| 🟠 High | **Fails CI** | Route without auth · generic-advice leak · CVE ≥ 7.0 · missing runtime LLM guardrails |
| 🟡 Medium | Reports only | Missing CSP · unpinned non-MCP dep |
| 🟢 Low | Reports only | Suboptimal Referrer-Policy |

Override via the `fail-on:` input. Allowlist entries need a reason, an `acknowledged_by`, and an `expires` within 365 days — see [`docs/SUPPRESSIONS.md`](docs/SUPPRESSIONS.md).

## Avoid list

Baked into the tool because supply-chain choices are security choices:

| Project | Reason |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (Mar 2025 force-push compromise) |
| `aquasecurity/trivy-action` **by tag** | Mar 2026 tag force-push. The Trivy binary is fine; we invoke it directly from our vendored image. |
| `tfsec` | Deprecated, absorbed into Trivy — use Checkov. |
| `protectai/rebuff` | Archived May 2025. |
| HarmBench / AdvBench corpora **in CI** | MIT but contain toxic content. |

## Roadmap

- [x] v0.1 — scaffold: orchestrator + 9 probes + blue-team + SARIF + gate
- [x] v0.2 — 37-test fixture suite + self-test CI
- [ ] v0.3 — pinned Dockerfile binaries + signed GHCR image
- [ ] v0.4 — promptfoo integration with `owasp:llm` preset + Lakera Mosscap/Gandalf corpora
- [ ] v0.5 — Checkov wire-up + live Supabase catalog drift check
- [ ] v0.6 — Consumer-specific SARIF suppression helpers
- [ ] v1.0 — Marketplace publish, Scorecard ≥ 8, SLSA L3 signed, docs complete

## Contributing

PRs welcome once v1.0 is cut; until then we're stabilising the interface. Security issues → [`SECURITY.md`](SECURITY.md). Probe additions → open an issue first to discuss severity + taxonomy mapping.

## License

MIT. See [`LICENSE`](LICENSE).

---

<div align="center">
  <sub>An open-source project from <a href="https://kardoxa.com">Kardoxa Labs</a>. Built for agentic apps that take security seriously.</sub>
</div>
