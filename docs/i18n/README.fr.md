<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<a href="README.ko.md">🇰🇷 한국어</a> &middot;
<a href="README.pt.md">🇧🇷 Português</a> &middot;
<a href="README.es.md">🇪🇸 Español</a> &middot;
<a href="README.de.md">🇩🇪 Deutsch</a> &middot;
<strong>🇫🇷 Français</strong> &middot;
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

# purplegate — Bloquez les merges agentic-AI non sécurisés

---

<div align="center">

**Les apps agentic mergent du code qui fuit des secrets, oublie RLS ou accepte la prompt injection.**
**purplegate exécute des sondes red-team et un scan défensif blue-team sur chaque PR — et fait échouer le build avant que ces merges atteignent la production.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>Auto-test en direct →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## Pourquoi purplegate

Les apps agentic-AI sont une nouvelle surface d'attaque. Le SAST traditionnel passe à côté des bugs propres aux LLM (prompt injection, fuite de system prompt, exposition de données inter-utilisateurs). Les Actions de sécurité traditionnelles passent à côté de la supply chain propre à l'IA (serveurs MCP, SDK embarqués, corpora vulnérables). Il vous faut les deux. purplegate, c'est les deux.

- **🔴 Red team** — huit sondes couvrant chaque classe de risque agentic : secrets, SAST, dépendances, IaC / RLS, workflow injection, **prompt injection** (Claude-as-judge isolé), risques de configuration MCP et en-têtes HTTP de sécurité.
- **🔵 Blue team** — un scanner défensif qui détecte les garde-fous runtime (LLM Guard, Guardrails AI), les rate limiters et les entrées en allowlist — puis **abaisse la sévérité** des findings déjà mitigés. La sévérité ne dépasse jamais la ligne de base du red team.
- **🟣 Gate purple-team** — une Action CI, un rapport SARIF. Par défaut, les findings Critical / High font échouer le build ; Medium / Low sont simplement signalés. Entièrement configurable.

## Ce qu'il attrape (et que les autres ratent)

| Classe | Finding exemple | Outil |
|---|---|---|
| LLM prompt injection | "Who is Trump?" répondu malgré le scope guard d'une app financière | Claude judge isolé via promptfoo |
| Fuite de system prompt | Un attaquant extrait les instructions de l'app via un payload travaillé | Même judge, consensus 2 sur 3 |
| Données inter-utilisateurs | L'app référence les transactions d'autres utilisateurs | Sonde purple-team dédiée |
| RLS Supabase absent | `CREATE TABLE public.transactions` sans `ENABLE ROW LEVEL SECURITY` | Vérification statique custom |
| Workflow command injection | `${{ github.event.issue.title }}` dans un bloc `run:` | Enveloppe [zizmor](https://github.com/zizmorcore/zizmor) |
| Credential vivant dans git | Un vrai `sk_live_...` commité aujourd'hui | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| MCP SDK vulnérable | Version épinglée sans le correctif MCP RCE d'Anthropic d'avril 2026 | Flux d'advisories embarqué |
| Fuite de conseil générique | "RRSPs are generally good" depuis une app qui ne doit répondre qu'avec les données de l'utilisateur | Rubric v1 du judge |

Chaque finding est mappé à **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026** et **MITRE ATLAS v5.4.0** — exposé dans le `ruleId` SARIF afin que GitHub Code Scanning et les outils SIEM en aval filtrent par framework.

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

Ajoutez ensuite `.purplegate/config.yml` — schéma complet dans [`docs/CONFIG.md`](../CONFIG.md). Walkthrough complet dans [`docs/QUICKSTART.md`](../QUICKSTART.md).

## Architecture

```
┌─ Dépôt consumer ────────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ Image Docker purplegate
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ Claude      │
                        │   │                       judge isolé │
                        │   ├─ mcp            (scan statique)   │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Scanner défensif blue-team           │
                        │   (ajuste la sévérité — jamais vers le │
                        │    haut)                              │
                        ├───────────────────────────────────────┤
                        │  Rapport (SARIF + Markdown + JSON)    │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Posture supply chain

La propriété la plus importante de cet outil est **qu'il ne devienne pas le vecteur d'attaque qu'il est censé défendre** — les consommateurs n'ont donc pas à nous faire confiance ; ils peuvent vérifier :

- **Docker container action.** Chaque scanner épinglé par SHA dans le `Dockerfile` ; pas de `pip install` / `npm install` à l'exécution.
- **Chaque `uses:` tiers épinglé par SHA de commit de 40 caractères** — jamais par tag. Mars 2025 (tj-actions) et mars 2026 (trivy-action) nous ont appris pourquoi.
- **Releases signées.** Attestation Sigstore via `actions/attest-build-provenance` + cosign keyless + SLSA L3 provenance + SBOM (Syft).
- Cible **Scorecard ≥ 8/10** ; toute baisse sous 7 bloque les releases.
- **Vérifiez avant la première utilisation :**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

Politique complète dans [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md). Threat model dans [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Sévérité et gate

| Sévérité | Gate par défaut | Exemples |
|---|---|---|
| 🔴 Critical | **Échec CI** | Credential vivant vérifié · table publique sans RLS · workflow command injection · MCP SDK vulnérable · extraction de system prompt vérifiée |
| 🟠 High | **Échec CI** | Route sans auth · fuite de conseil générique · CVE ≥ 7.0 · garde-fous LLM runtime absents |
| 🟡 Medium | Signalement uniquement | CSP absent · dép. non-MCP non épinglée |
| 🟢 Low | Signalement uniquement | Referrer-Policy sous-optimale |

Override via l'input `fail-on:`. Les entrées d'allowlist requièrent reason, acknowledged_by et `expires` sous 365 jours — voir [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md).

## Liste à éviter

Intégrée dans l'outil parce que les choix de supply chain sont des choix de sécurité :

| Projet | Raison |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (compromission par force-push de mars 2025) |
| `aquasecurity/trivy-action` **par tag** | Tags force-pushés en mars 2026. Le binaire Trivy lui-même est OK ; nous l'appelons directement depuis notre image embarquée. |
| `tfsec` | Déprécié, absorbé par Trivy — utilisez Checkov. |
| `protectai/rebuff` | Archivé en mai 2025. |
| Corpora HarmBench / AdvBench **en CI** | MIT mais contiennent du contenu toxique. |

## Roadmap

- [x] v0.1 — scaffold : orchestrator + 9 sondes + blue-team + SARIF + gate
- [x] v0.2 — suite de 37 tests de fixtures + self-test CI
- [ ] v0.3 — binaires Dockerfile épinglés + image GHCR signée
- [ ] v0.4 — intégration promptfoo avec preset `owasp:llm` + corpora Lakera Mosscap / Gandalf
- [ ] v0.5 — câblage Checkov + contrôle drift du catalogue Supabase en direct
- [ ] v0.6 — helpers de suppression SARIF spécifiques au consumer
- [ ] v1.0 — publication Marketplace, Scorecard ≥ 8, SLSA L3 signé, docs complètes

## Contribuer

PR bienvenues après la v1.0 ; d'ici là, nous stabilisons l'interface. Problèmes de sécurité → [`SECURITY.md`](../../SECURITY.md). Ajouts de sondes → ouvrez d'abord une issue pour discuter sévérité + mapping de taxonomie.

## Licence

MIT. Voir [`LICENSE`](../../LICENSE).

---

<div align="center">
  <sub>Un projet open source de <a href="https://kardoxa.com">Kardoxa Labs</a>. Conçu pour les apps agentic qui prennent la sécurité au sérieux.</sub>
</div>
