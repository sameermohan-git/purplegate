<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<a href="README.ko.md">🇰🇷 한국어</a> &middot;
<a href="README.pt.md">🇧🇷 Português</a> &middot;
<strong>🇪🇸 Español</strong> &middot;
<a href="README.de.md">🇩🇪 Deutsch</a> &middot;
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

# purplegate — Bloquea merges de agentic-AI inseguros

---

<div align="center">

**Las apps agentic mergean código que filtra secretos, olvida RLS o acepta prompt injection.**
**purplegate ejecuta sondas de red-team y un escaneo defensivo de blue-team en cada PR — y rompe el build antes de que esos merges lleguen a producción.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>Autotest en vivo →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## Por qué purplegate

Las apps agentic-AI son una nueva clase de superficie de ataque. El SAST tradicional no ve los bugs específicos de LLM (prompt injection, filtración de system prompt, exposición de datos entre usuarios). Las Actions de seguridad tradicionales no ven la cadena de suministro específica de AI (servidores MCP, SDKs vendidos, corpora vulnerables). Necesitas ambas. purplegate es ambas.

- **🔴 Red-team** — ocho sondas que cubren toda clase de riesgo agentic: secrets, SAST, dependencias, IaC / RLS, workflow injection, **prompt injection** (Claude-as-judge aislado), riesgos de configuración MCP y cabeceras HTTP de seguridad.
- **🔵 Blue-team** — un escáner defensivo que detecta guardrails en runtime (LLM Guard, Guardrails AI), rate limiters y entradas de allowlist — y **baja la severidad** de findings ya mitigados. La severidad nunca supera la línea base del red-team.
- **🟣 Purple-team gate** — una Action de CI, un reporte SARIF. Por defecto, findings Critical / High rompen el build; Medium / Low solo reportan. Totalmente configurable.

## Lo que detecta (y otras herramientas no)

| Clase | Finding de ejemplo | Herramienta |
|---|---|---|
| LLM prompt injection | "Who is Trump?" respondido a pesar del scope guard de una app financiera | Claude judge aislado vía promptfoo |
| Filtración de system prompt | Atacante extrae las instrucciones de la app con un payload cuidado | Mismo judge, acuerdo 2-de-3 |
| Datos entre usuarios | La app referencia transacciones de otros usuarios | Sonda dedicada del purple-team |
| Supabase RLS ausente | `CREATE TABLE public.transactions` sin `ENABLE ROW LEVEL SECURITY` | Check estático custom |
| Workflow command injection | `${{ github.event.issue.title }}` dentro de un bloque `run:` | Wrapea [zizmor](https://github.com/zizmorcore/zizmor) |
| Credencial viva en git | Un `sk_live_...` real commiteado hoy | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| MCP SDK vulnerable | Versión pineada sin el parche del MCP RCE de Anthropic (abr 2026) | Feed de advisory vendado |
| Filtración de consejo genérico | "RRSPs are generally good" de una app que solo debería contestar sobre datos del usuario | rubric v1 del judge |

Cada finding mapea a **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026** y **MITRE ATLAS v5.4.0** — expuesto en `ruleId` de SARIF para que GitHub Code Scanning y herramientas SIEM downstream filtren por framework.

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

Luego agregá `.purplegate/config.yml` — schema completo en [`docs/CONFIG.md`](../CONFIG.md). Walkthrough completo en [`docs/QUICKSTART.md`](../QUICKSTART.md).

## Arquitectura

```
┌─ Repo consumidor ───────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ Imagen Docker de purplegate
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
                        │   │                       judge aislado│
                        │   ├─ mcp            (scan estático)   │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Escáner defensivo blue-team          │
                        │   (ajusta severidad — nunca sube)     │
                        ├───────────────────────────────────────┤
                        │  Reporte (SARIF + Markdown + JSON)    │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Postura de supply chain

La propiedad más importante de esta herramienta es que **no se convierta en el vector de ataque que pretende defender** — por eso los consumidores no tienen que confiar en nosotros; pueden verificar:

- **Docker container action.** Cada escáner pineado por SHA en el `Dockerfile`; sin `pip install` / `npm install` en runtime.
- **Todo `uses:` de terceros pineado por commit SHA de 40 caracteres** — nunca por tag. Marzo/2025 (tj-actions) y marzo/2026 (trivy-action) nos enseñaron por qué.
- **Releases firmadas.** Sigstore attestation vía `actions/attest-build-provenance` + cosign keyless + SLSA L3 provenance + SBOM (Syft).
- Objetivo **Scorecard ≥ 8/10**; caída debajo de 7 bloquea releases.
- **Verificá antes del primer uso:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

Política completa en [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md). Modelo de amenaza en [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Severidad y gate

| Severidad | Gate por defecto | Ejemplos |
|---|---|---|
| 🔴 Critical | **Falla CI** | Credencial viva verificada · tabla pública sin RLS · workflow command injection · MCP SDK vulnerable · extracción de system prompt verificada |
| 🟠 High | **Falla CI** | Ruta sin auth · filtración de consejo genérico · CVE ≥ 7.0 · guardrails LLM en runtime ausentes |
| 🟡 Medium | Solo reporta | CSP ausente · dep no-MCP sin pinear |
| 🟢 Low | Solo reporta | Referrer-Policy subóptima |

Override con input `fail-on:`. Las entradas de allowlist requieren reason, acknowledged_by y `expires` dentro de 365 días — ver [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md).

## Lista de evitar

Incrustada en la herramienta porque las decisiones de supply chain son decisiones de seguridad:

| Proyecto | Razón |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (compromiso por force-push en mar/2025) |
| `aquasecurity/trivy-action` **por tag** | Tags force-pushed en mar/2026. El binario Trivy en sí está bien; lo invocamos directo desde nuestra imagen vendada. |
| `tfsec` | Deprecado, absorbido por Trivy — usá Checkov. |
| `protectai/rebuff` | Archivado en may/2025. |
| Corpora HarmBench / AdvBench **en CI** | MIT pero contienen contenido tóxico. |

## Roadmap

- [x] v0.1 — scaffold: orchestrator + 9 sondas + blue-team + SARIF + gate
- [x] v0.2 — suite de 37 tests de fixture + self-test CI
- [ ] v0.3 — binarios de Dockerfile pineados + imagen GHCR firmada
- [ ] v0.4 — integración promptfoo con preset `owasp:llm` + corpora Lakera Mosscap / Gandalf
- [ ] v0.5 — cableado Checkov + check de drift de catálogo Supabase en vivo
- [ ] v0.6 — helpers SARIF de suppression específicos por consumidor
- [ ] v1.0 — publicación en Marketplace, Scorecard ≥ 8, SLSA L3 firmado, docs completos

## Contribuir

PRs bienvenidos luego de la v1.0; hasta entonces estamos estabilizando la interfaz. Temas de seguridad → [`SECURITY.md`](../../SECURITY.md). Agregar sondas → abrí un issue primero para discutir severidad + mapeo de taxonomy.

## Licencia

MIT. Ver [`LICENSE`](../../LICENSE).

---

<div align="center">
  <sub>Un proyecto open-source de <a href="https://kardoxa.com">Kardoxa Labs</a>. Hecho para apps agentic que se toman la seguridad en serio.</sub>
</div>
