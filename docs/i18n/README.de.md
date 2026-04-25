<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<a href="README.ko.md">🇰🇷 한국어</a> &middot;
<a href="README.pt.md">🇧🇷 Português</a> &middot;
<a href="README.es.md">🇪🇸 Español</a> &middot;
<strong>🇩🇪 Deutsch</strong> &middot;
<a href="README.fr.md">🇫🇷 Français</a> &middot;
<a href="README.ru.md">🇷🇺 Русский</a> &middot;
<a href="README.hi.md">🇮🇳 हिन्दी</a> &middot;
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
<img src="https://img.shields.io/badge/SBOM-SPDX%20%2B%20CYCLONEDX-1565c0?style=for-the-badge&labelColor=424242" alt="SBOM SPDX + CycloneDX" />

</div>

# purplegate — Unsichere agentic-AI-Merges blockieren

---

<div align="center">

**Agentic-Apps mergen Code, der Secrets leakt, RLS vergisst oder Prompt Injection akzeptiert.**
**purplegate läuft bei jedem PR als Red-Team-Probes und Blue-Team-Defense-Scan — und bricht den Build, bevor diese Merges in die Produktion gelangen.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>Live-Self-Test →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## Warum purplegate

Agentic-AI-Apps sind eine neue Angriffsfläche. Traditionelles SAST übersieht LLM-spezifische Bugs (Prompt Injection, System-Prompt-Leaks, benutzerübergreifende Datenexposition). Traditionelle Security-Actions übersehen die AI-spezifische Supply Chain (MCP-Server, mitgelieferte SDKs, anfällige Korpora). Man braucht beides. purplegate ist beides.

- **🔴 Red Team** — acht Probes decken jede Risikoklasse agentic-AI-spezifischer Anwendungen ab: Secrets, SAST, Dependencies, IaC / RLS, Workflow-Injection, **Prompt Injection** (isolierter Claude-as-Judge), MCP-Konfigurationsrisiken und HTTP-Security-Header.
- **🔵 Blue Team** — ein Defense-Scanner, der Laufzeit-Guardrails (LLM Guard, Guardrails AI), Rate Limiter und Allowlist-Einträge erkennt — und dann **Severity herabsetzt** bei bereits mitigierten Findings. Severity wird nie über die Red-Team-Baseline hinaus angehoben.
- **🟣 Purple-Team-Gate** — eine CI-Action, ein SARIF-Report. Standardmäßig führen Critical- / High-Findings zu einem fehlgeschlagenen Build; Medium / Low berichten nur. Vollständig konfigurierbar.

## Was es fängt (und andere Tools übersehen)

| Klasse | Beispiel-Finding | Tool |
|---|---|---|
| LLM Prompt Injection | "Who is Trump?" wird trotz Scope-Guard einer Finanz-App beantwortet | Isolierter Claude Judge via promptfoo |
| System-Prompt-Leak | Angreifer extrahiert die App-Anweisungen mit ausgefeiltem Payload | Gleicher Judge, 3-Rep-Konsens |
| Benutzerübergreifende Daten | App referenziert die Transaktionen anderer Benutzer | Dedizierte Purple-Team-Probe |
| Fehlendes Supabase RLS | `CREATE TABLE public.transactions` ohne `ENABLE ROW LEVEL SECURITY` | Custom statische Prüfung |
| Workflow Command Injection | `${{ github.event.issue.title }}` innerhalb eines `run:`-Schritts | Umhüllt [zizmor](https://github.com/zizmorcore/zizmor) |
| Live-Credential in Git | Eine echte, heute committete `sk_live_...` | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| Verwundbares MCP SDK | Fixierte Version ohne Anthropic-MCP-RCE-Fix (Apr 2026) | Mitgelieferter Advisory-Feed |
| Allgemeiner-Rat-Leak | "RRSPs are generally good" aus einer App, die nur Benutzerdaten beantworten sollte | Judge Rubric v1 |

Jedes Finding ist auf **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026** und **MITRE ATLAS v5.4.0** abgebildet — im `ruleId` des SARIF-Reports veröffentlicht, sodass GitHub Code Scanning und Downstream-SIEM-Tools nach Framework filtern können.

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

Dann `.purplegate/config.yml` hinzufügen — vollständiges Schema in [`docs/CONFIG.md`](../CONFIG.md). Komplette Walkthrough in [`docs/QUICKSTART.md`](../QUICKSTART.md).

## Architektur

```
┌─ Consumer-Repo ─────────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ purplegate Docker-Image
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ isolierter   │
                        │   │                       Claude Judge │
                        │   ├─ mcp            (statischer Scan) │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Blue-Team Defense-Scanner            │
                        │   (Severity senken — niemals heben)   │
                        ├───────────────────────────────────────┤
                        │  Report (SARIF + Markdown + JSON)     │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Supply-Chain-Haltung

Die wichtigste Eigenschaft dieses Tools ist, **dass es nicht zum Angriffsvektor wird, vor dem es schützen soll** — deshalb müssen Konsumenten uns nicht vertrauen, sondern können verifizieren:

- **Docker Container Action.** Jeder Scanner per SHA im `Dockerfile` fixiert; keine `pip install` / `npm install` zur Laufzeit.
- **Jedes Drittpartei-`uses:` per 40-Zeichen Commit-SHA fixiert** — niemals per Tag. März 2025 (tj-actions) und März 2026 (trivy-action) haben uns den Grund gelehrt.
- **Signierte Releases.** Sigstore-Attestation via `actions/attest-build-provenance` + cosign keyless + SLSA L3 Provenance + SBOM (Syft).
- **Scorecard ≥ 8/10** Zielwert; Abfall unter 7 blockiert Releases.
- **Vor der ersten Nutzung verifizieren:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

Vollständige Policy in [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md). Threat Model in [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Severity und Gate

| Severity | Default-Gate | Beispiele |
|---|---|---|
| 🔴 Critical | **CI schlägt fehl** | Verifiziertes Live-Credential · Public Table ohne RLS · Workflow Command Injection · verwundbares MCP SDK · verifizierte System-Prompt-Extraktion |
| 🟠 High | **CI schlägt fehl** | Route ohne Auth · Allgemeiner-Rat-Leak · CVE ≥ 7.0 · fehlende Laufzeit-LLM-Guardrails |
| 🟡 Medium | Nur Report | Fehlendes CSP · unfixierte Nicht-MCP-Dep |
| 🟢 Low | Nur Report | Suboptimale Referrer-Policy |

Override via `fail-on:`-Input. Allowlist-Einträge benötigen reason, acknowledged_by und `expires` innerhalb 365 Tagen — siehe [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md).

## Avoid-Liste

Im Tool verankert, weil Supply-Chain-Entscheidungen Sicherheitsentscheidungen sind:

| Projekt | Grund |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (Force-Push-Kompromittierung März 2025) |
| `aquasecurity/trivy-action` **per Tag** | Tags im März 2026 force-pushed. Das Trivy-Binary selbst ist in Ordnung; wir rufen es direkt aus unserem eigenen Image auf. |
| `tfsec` | Deprecated, in Trivy eingegliedert — nutze Checkov. |
| `protectai/rebuff` | Im Mai 2025 archiviert. |
| HarmBench / AdvBench Korpora **in CI** | MIT, aber enthalten toxische Inhalte. |

## Roadmap

- [x] v0.1 — Scaffold: Orchestrator + 9 Probes + Blue-Team + SARIF + Gate
- [x] v0.2 — 37-Test-Fixture-Suite + Self-Test CI
- [ ] v0.3 — fixierte Dockerfile-Binaries + signiertes GHCR-Image
- [ ] v0.4 — promptfoo-Integration mit `owasp:llm`-Preset + Lakera-Mosscap- / Gandalf-Korpora
- [ ] v0.5 — Checkov-Anbindung + Live-Drift-Check des Supabase-Katalogs
- [ ] v0.6 — Consumer-spezifische SARIF-Suppression-Helper
- [ ] v1.0 — Marketplace-Veröffentlichung, Scorecard ≥ 8, SLSA L3 signiert, Docs vollständig

## Mitwirken

PRs willkommen nach v1.0-Cut; bis dahin stabilisieren wir das Interface. Security-Issues → [`SECURITY.md`](../../SECURITY.md). Probe-Ergänzungen → zuerst Issue öffnen, um Severity + Taxonomy-Mapping zu diskutieren.

## Lizenz

MIT. Siehe [`LICENSE`](../../LICENSE).

---

<div align="center">
  <sub>Ein Open-Source-Projekt von <a href="https://kardoxa.com">Kardoxa Labs</a>. Gebaut für agentic Apps, die Sicherheit ernst nehmen.</sub>
</div>
