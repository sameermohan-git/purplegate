<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<a href="README.ko.md">🇰🇷 한국어</a> &middot;
<a href="README.pt.md">🇧🇷 Português</a> &middot;
<a href="README.es.md">🇪🇸 Español</a> &middot;
<a href="README.de.md">🇩🇪 Deutsch</a> &middot;
<a href="README.fr.md">🇫🇷 Français</a> &middot;
<a href="README.ru.md">🇷🇺 Русский</a> &middot;
<strong>🇮🇳 हिन्दी</strong> &middot;
<a href="README.tr.md">🇹🇷 Türkçe</a>

<br />
<br />

<img src="../../assets/logo.png" alt="purplegate" width="220" />

<br />
<br />

<img src="https://img.shields.io/badge/RED%20TEAM-8%20PROBES-d32f2f?style=for-the-badge&labelColor=424242" alt="8 probes" />
<img src="https://img.shields.io/badge/BLUE%20TEAM-DEFENSE%20SCAN-1976d2?style=for-the-badge&labelColor=424242" alt="blue team" />
<img src="https://img.shields.io/badge/TAXONOMY-OWASP%20%2B%20ATLAS-7b1fa2?style=for-the-badge&labelColor=424242" alt="OWASP + ATLAS" />
<img src="https://img.shields.io/badge/PYTHON-3.12%2B-3776ab?style=for-the-badge&labelColor=424242&logo=python&logoColor=white" alt="Python 3.12+" />

<br />

<img src="https://img.shields.io/badge/RUNTIME-DOCKER-2496ed?style=for-the-badge&labelColor=424242&logo=docker&logoColor=white" alt="docker" />
<img src="https://img.shields.io/badge/REPORT-SARIF%202.1.0-f57c00?style=for-the-badge&labelColor=424242" alt="SARIF 2.1.0" />
<img src="https://img.shields.io/badge/SIGNED-COSIGN%20KEYLESS-2e7d32?style=for-the-badge&labelColor=424242&logo=sigstore&logoColor=white" alt="cosign keyless signed" />
<img src="https://img.shields.io/badge/PROVENANCE-SLSA%20L3-f5a623?style=for-the-badge&labelColor=424242" alt="SLSA Level 3" />
<img src="https://img.shields.io/badge/SBOM-SPDX%20%2B%20CYCLONEDX%20(SIGNED)-1565c0?style=for-the-badge&labelColor=424242" alt="SBOM SPDX + CycloneDX (signed)" />

<br />

<a href="https://scorecard.dev/viewer/?uri=github.com/sameermohan-git/purplegate"><img src="https://api.securityscorecards.dev/projects/github.com/sameermohan-git/purplegate/badge" alt="OSSF Scorecard" /></a>
<a href="https://github.com/sameermohan-git/purplegate/actions/workflows/codeql.yml"><img src="https://github.com/sameermohan-git/purplegate/actions/workflows/codeql.yml/badge.svg" alt="CodeQL" /></a>
<a href="https://github.com/sameermohan-git/purplegate/actions/workflows/self-test.yml"><img src="https://github.com/sameermohan-git/purplegate/actions/workflows/self-test.yml/badge.svg" alt="self-test" /></a>

</div>

# purplegate — असुरक्षित agentic-AI merges को ब्लॉक करें

---

<div align="center">

**Agentic ऐप्स ऐसा code merge कर देती हैं जो secrets leak करता है, RLS भूल जाता है, या prompt injection स्वीकार कर लेता है।**
**purplegate हर PR पर red-team probes और blue-team defense scan चलाता है — और वे merges production में जाने से पहले build को fail करा देता है।**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>Live self-test →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## purplegate क्यों

Agentic-AI ऐप्स एक नई तरह की attack surface हैं। पारंपरिक SAST LLM-specific bugs (prompt injection, system prompt leak, cross-user data exposure) को miss कर जाता है। पारंपरिक security Actions AI-specific supply chain (MCP servers, vendored SDKs, vulnerable corpora) को miss करते हैं। आपको दोनों चाहिए। purplegate दोनों है।

- **🔴 Red-team** — आठ probes agentic ऐप के हर तरह के risk को cover करते हैं: secrets, SAST, dependencies, IaC / RLS, workflow injection, **prompt injection** (isolated Claude-as-judge), MCP configuration risks, और HTTP security headers.
- **🔵 Blue-team** — एक defense scanner जो runtime guardrails (LLM Guard, Guardrails AI), rate limiters, और allowlist entries detect करता है — फिर जो findings पहले से mitigated हैं उनकी **severity नीचे adjust** करता है। Severity कभी भी red-team baseline से ऊपर नहीं जाती।
- **🟣 Purple-team gate** — एक CI action, एक SARIF report। Default में Critical / High findings build को fail करते हैं; Medium / Low सिर्फ report होते हैं। पूरी तरह configurable।

## यह क्या catch करता है (जो दूसरे miss करते हैं)

| वर्ग | उदाहरण finding | Tool |
|---|---|---|
| LLM prompt injection | "Who is Trump?" एक finance ऐप के scope guard के बावजूद जवाब दिया गया | promptfoo के through isolated Claude judge |
| System prompt leak | Attacker सोच-समझकर crafted payload से ऐप की instructions extract कर लेता है | वही judge, 3-repetition consensus |
| Cross-user data disclosure | ऐप दूसरे users की transactions reference करता है | purple-team dedicated probe |
| Supabase RLS गायब | `CREATE TABLE public.transactions` बिना `ENABLE ROW LEVEL SECURITY` | Custom static check |
| Workflow command injection | `${{ github.event.issue.title }}` किसी `run:` step के अंदर | [zizmor](https://github.com/zizmorcore/zizmor) को wrap करता है |
| Git में live credential | आज committed एक असली `sk_live_...` | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| Vulnerable MCP SDK | Pinned version जिसमें April 2026 Anthropic MCP RCE का fix गायब है | Vendored advisory feed |
| Generic advice leak | उस ऐप से "RRSPs are generally good" जो केवल user के अपने data के बारे में जवाब देना चाहिए | Judge rubric v1 |

हर finding **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026**, और **MITRE ATLAS v5.4.0** से map होती है — SARIF `ruleId` में surface होती है ताकि GitHub Code Scanning और downstream SIEM tools framework से filter कर सकें।

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
          # Required since v0.1.0-alpha.8: Docker container actions don't get
          # github.token in env: namespace, so the consumer passes it explicitly.
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

फिर `.purplegate/config.yml` add करें — पूरा schema [`docs/CONFIG.md`](../CONFIG.md) में। पूरा walkthrough [`docs/QUICKSTART.md`](../QUICKSTART.md) में।

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
                        │   (severity adjuster — कभी नहीं बढ़ाता) │
                        ├───────────────────────────────────────┤
                        │  Report (SARIF + Markdown + JSON)     │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Supply-chain posture

इस tool की सबसे अहम property यह है कि **यह खुद वह attack vector न बन जाए जिससे बचाने की कोशिश कर रहा है** — इसलिए consumers को हम पर भरोसा करने की ज़रूरत नहीं; वे verify कर सकते हैं:

- **Docker container action.** हर scanner `Dockerfile` में SHA से pinned; runtime पर कोई `pip install` / `npm install` नहीं।
- **हर third-party `uses:` 40-character commit SHA से pinned** — कभी tag से नहीं। March 2025 (tj-actions) और March 2026 (trivy-action) ने हमें सिखाया क्यों।
- **Signed releases.** `actions/attest-build-provenance` के through Sigstore attestation + cosign keyless + SLSA L3 provenance + SBOM (Syft)।
- **Scorecard ≥ 8/10** target; 7 से नीचे releases को block करता है।
- **पहले use से पहले verify करें:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

पूरी policy [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md) में। Threat model [`THREAT_MODEL.md`](../../THREAT_MODEL.md) में।

## Severity और gate

| Severity | Default gate | उदाहरण |
|---|---|---|
| 🔴 Critical | **CI fail** | Verified live credential · RLS के बिना public table · workflow command injection · vulnerable MCP SDK · verified system prompt extraction |
| 🟠 High | **CI fail** | Auth के बिना route · generic advice leak · CVE ≥ 7.0 · runtime LLM guardrails गायब |
| 🟡 Medium | Reports only | CSP गायब · unpinned non-MCP dep |
| 🟢 Low | Reports only | Suboptimal Referrer-Policy |

`fail-on:` input से override करें। Allowlist entries को reason, acknowledged_by, और 365 दिनों के अंदर `expires` चाहिए — देखें [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md)।

## Avoid list

Tool में built-in है क्योंकि supply-chain choices security choices हैं:

| Project | कारण |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (March 2025 force-push compromise) |
| `aquasecurity/trivy-action` **tag से** | March 2026 tag force-push। Trivy binary खुद ठीक है; हम उसे अपनी vendored image से directly invoke करते हैं। |
| `tfsec` | Deprecated, Trivy में absorbed — Checkov use करें। |
| `protectai/rebuff` | May 2025 में archived। |
| CI में HarmBench / AdvBench corpora | MIT लेकिन toxic content रखते हैं। |

## Roadmap

- [x] v0.1 — scaffold: orchestrator + 9 probes + blue-team + SARIF + gate
- [x] v0.2 — 37-test fixture suite + self-test CI
- [ ] v0.3 — pinned Dockerfile binaries + signed GHCR image
- [ ] v0.4 — promptfoo integration जिसमें `owasp:llm` preset + Lakera Mosscap / Gandalf corpora हों
- [ ] v0.5 — Checkov wire-up + live Supabase catalog drift check
- [ ] v0.6 — Consumer-specific SARIF suppression helpers
- [ ] v1.0 — Marketplace publish, Scorecard ≥ 8, SLSA L3 signed, docs complete

## Contributing

v1.0 cut होने के बाद PRs welcome; तब तक हम interface stabilize कर रहे हैं। Security issues → [`SECURITY.md`](../../SECURITY.md)। Probe additions → पहले एक issue खोलकर severity + taxonomy mapping discuss करें।

## License

MIT. देखें [`LICENSE`](../../LICENSE)।

---

<div align="center">
  <sub><a href="https://kardoxa.com">Kardoxa Labs</a> का एक open-source project। उन agentic ऐप्स के लिए जो security को गंभीरता से लेती हैं।</sub>
</div>
