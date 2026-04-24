<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<a href="README.ko.md">🇰🇷 한국어</a> &middot;
<strong>🇧🇷 Português</strong> &middot;
<a href="README.es.md">🇪🇸 Español</a> &middot;
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
<img src="https://img.shields.io/badge/SUPPLY%20CHAIN-SHA--PINNED-7b7b7b?style=for-the-badge&labelColor=424242" alt="SHA-pinned" />

</div>

# purplegate — Bloqueie merges de agentic-AI inseguros

---

<div align="center">

**Aplicações agentic fazem merge de código que vaza segredos, esquece RLS ou aceita prompt injection.**
**purplegate roda sondas de red-team e uma varredura de defesa blue-team em cada PR — e quebra o build antes desses merges irem para produção.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>Auto-teste ao vivo →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## Por que purplegate

Aplicações agentic-AI são uma nova classe de superfície de ataque. O SAST tradicional não vê os bugs específicos de LLM (prompt injection, vazamento de system prompt, exposição de dados entre usuários). Actions de segurança tradicionais não enxergam a cadeia de suprimentos específica de AI (servidores MCP, SDKs de fornecedores, corpora vulneráveis). Você precisa dos dois. O purplegate cobre ambos.

- **🔴 Red-team** — oito sondas cobrindo toda classe de risco de app agentic: secrets, SAST, dependências, IaC / RLS, workflow injection, **prompt injection** (Claude-as-judge isolado), riscos de configuração MCP e cabeçalhos HTTP de segurança.
- **🔵 Blue-team** — um scanner de defesa que detecta guardrails em runtime (LLM Guard, Guardrails AI), rate limiters e entradas em allowlist — então **reduz a severidade** de findings já mitigados. A severidade nunca ultrapassa a linha de base do red-team.
- **🟣 Purple-team gate** — uma Action de CI, um relatório SARIF. Por padrão, findings Critical / High falham o build; Medium / Low apenas reportam. Totalmente configurável.

## O que ele pega (que os outros não veem)

| Classe | Finding de exemplo | Ferramenta |
|---|---|---|
| LLM prompt injection | "Who is Trump?" respondido apesar do scope guard de um app financeiro | Claude judge isolado via promptfoo |
| Vazamento de system prompt | Atacante extrai as instruções do app via payload elaborado | Mesmo judge, consenso 3 de 3 |
| Dados entre usuários | App referencia transações de outros usuários | Sonda dedicada do purple-team |
| Supabase RLS ausente | `CREATE TABLE public.transactions` sem `ENABLE ROW LEVEL SECURITY` | Verificação estática custom |
| Workflow command injection | `${{ github.event.issue.title }}` dentro de um bloco `run:` | Wrapeia [zizmor](https://github.com/zizmorcore/zizmor) |
| Credencial ao vivo no git | Um `sk_live_...` real commitado hoje | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| MCP SDK vulnerável | Versão pinada sem o fix do RCE do MCP da Anthropic (abr 2026) | Feed de advisory vendado |
| Vazamento de conselho genérico | "RRSPs are generally good" de um app que só deveria responder sobre dados do usuário | rubric v1 do judge |

Toda finding é mapeada para **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026** e **MITRE ATLAS v5.4.0** — exposta no `ruleId` do SARIF para que o GitHub Code Scanning e ferramentas SIEM downstream filtrem por framework.

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

Depois adicione `.purplegate/config.yml` — schema completo em [`docs/CONFIG.md`](../CONFIG.md). Walkthrough completo em [`docs/QUICKSTART.md`](../QUICKSTART.md).

## Arquitetura

```
┌─ Repo consumidor ───────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ Imagem Docker do purplegate
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
                        │   │                       judge isolado│
                        │   ├─ mcp            (scan estático)   │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Scanner de defesa blue-team          │
                        │   (ajusta severidade — nunca aumenta) │
                        ├───────────────────────────────────────┤
                        │  Relatório (SARIF + Markdown + JSON)  │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Postura de cadeia de suprimentos

A propriedade mais importante desta ferramenta é que **ela não se torne o vetor de ataque que pretende defender** — portanto consumidores não precisam confiar em nós; podem verificar:

- **Docker container action.** Cada scanner pinado por SHA no `Dockerfile`; sem `pip install` / `npm install` em runtime.
- **Todo `uses:` de terceiros pinado por commit SHA de 40 caracteres** — nunca por tag. Março/2025 (tj-actions) e março/2026 (trivy-action) nos ensinaram o motivo.
- **Releases assinadas.** Sigstore attestation via `actions/attest-build-provenance` + cosign keyless + SLSA L3 provenance + SBOM (Syft).
- Meta **Scorecard ≥ 8/10**; queda abaixo de 7 bloqueia releases.
- **Verifique antes do primeiro uso:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

Política completa em [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md). Modelo de ameaça em [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Severidade e gate

| Severidade | Gate padrão | Exemplos |
|---|---|---|
| 🔴 Critical | **Falha CI** | Credencial ao vivo verificada · tabela pública sem RLS · workflow command injection · MCP SDK vulnerável · extração de system prompt verificada |
| 🟠 High | **Falha CI** | Rota sem auth · vazamento de conselho genérico · CVE ≥ 7.0 · guardrails LLM em runtime ausentes |
| 🟡 Medium | Apenas reporta | CSP ausente · dep não-MCP não pinada |
| 🟢 Low | Apenas reporta | Referrer-Policy subótima |

Ajuste via input `fail-on:`. Entradas na allowlist precisam de reason, acknowledged_by e `expires` dentro de 365 dias — veja [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md).

## Lista de evitar

Embutida na ferramenta porque escolhas de cadeia de suprimentos são escolhas de segurança:

| Projeto | Motivo |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (comprometimento por force-push em março/2025) |
| `aquasecurity/trivy-action` **por tag** | Tags force-pushed em março/2026. O binário Trivy em si está ok; invocamos direto da nossa imagem vendada. |
| `tfsec` | Descontinuado, absorvido pelo Trivy — use Checkov. |
| `protectai/rebuff` | Arquivado em maio/2025. |
| Corpora HarmBench / AdvBench **em CI** | MIT, mas contêm conteúdo tóxico. |

## Roadmap

- [x] v0.1 — scaffold: orchestrator + 9 sondas + blue-team + SARIF + gate
- [x] v0.2 — suíte de 37 testes de fixture + self-test CI
- [ ] v0.3 — binários do Dockerfile pinados + imagem GHCR assinada
- [ ] v0.4 — integração promptfoo com preset `owasp:llm` + corpora Lakera Mosscap / Gandalf
- [ ] v0.5 — fiação do Checkov + checagem de drift de catálogo Supabase ao vivo
- [ ] v0.6 — helpers de suppression SARIF específicos por consumidor
- [ ] v1.0 — publicação no Marketplace, Scorecard ≥ 8, SLSA L3 assinado, docs completos

## Contribuindo

PRs bem-vindos após a v1.0; até lá estamos estabilizando a interface. Questões de segurança → [`SECURITY.md`](../../SECURITY.md). Adição de sondas → abra um issue primeiro para discutir severidade + mapeamento de taxonomy.

## Licença

MIT. Veja [`LICENSE`](../../LICENSE).

---

<div align="center">
  <sub>Um projeto open-source da <a href="https://kardoxa.com">Kardoxa Labs</a>. Feito para apps agentic que levam segurança a sério.</sub>
</div>
