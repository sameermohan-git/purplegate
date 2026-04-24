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
<a href="README.hi.md">🇮🇳 हिन्दी</a> &middot;
<strong>🇹🇷 Türkçe</strong>

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

# purplegate — Güvensiz agentic-AI merge'lerini engelleyin

---

<div align="center">

**Agentic uygulamalar; secret sızdıran, RLS unutan veya prompt injection kabul eden kodu merge eder.**
**purplegate her PR'da red-team probe'ları ve blue-team savunma taramasını çalıştırır — ve o merge'ler production'a ulaşmadan build'i düşürür.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>Canlı self-test →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## Neden purplegate

Agentic-AI uygulamaları yeni bir saldırı yüzeyi sınıfıdır. Geleneksel SAST, LLM'ye özgü bug'ları (prompt injection, system prompt sızıntısı, kullanıcılar arası veri ifşası) kaçırır. Geleneksel güvenlik Action'ları, AI'ye özgü supply chain'i (MCP sunucuları, gömülü SDK'lar, güvensiz corpora) kaçırır. İkisine de ihtiyacınız var. purplegate ikisini birden kapsar.

- **🔴 Red team** — agentic uygulamaların her risk sınıfını kapsayan sekiz probe: secrets, SAST, bağımlılıklar, IaC / RLS, workflow injection, **prompt injection** (izole Claude-as-judge), MCP yapılandırma riskleri ve HTTP güvenlik başlıkları.
- **🔵 Blue team** — runtime guardrail'leri (LLM Guard, Guardrails AI), rate limiter'ları ve allowlist girişlerini tespit eden bir savunma tarayıcısı — ardından zaten azaltılmış finding'lerin **severity'sini düşürür**. Severity, red-team baseline'ının asla üstüne çıkmaz.
- **🟣 Purple-team gate** — tek bir CI Action, tek bir SARIF raporu. Varsayılanda Critical / High finding'ler build'i düşürür; Medium / Low sadece raporlanır. Tamamen yapılandırılabilir.

## Diğer araçların kaçırdıklarını yakalar

| Sınıf | Örnek finding | Araç |
|---|---|---|
| LLM prompt injection | Bir finans uygulamasının scope guard'ına rağmen "Who is Trump?"'a yanıt | promptfoo üzerinden izole Claude judge |
| System prompt sızıntısı | Saldırgan özenle hazırlanmış payload ile uygulamanın talimatlarını çıkarıyor | Aynı judge, 3 tekrar uzlaşması |
| Kullanıcılar arası veri | Uygulama başka kullanıcıların transaction'larına atıfta bulunuyor | Purple-team özel probe |
| Eksik Supabase RLS | `ENABLE ROW LEVEL SECURITY` olmadan `CREATE TABLE public.transactions` | Özel statik kontrol |
| Workflow command injection | Bir `run:` adımı içinde `${{ github.event.issue.title }}` | [zizmor](https://github.com/zizmorcore/zizmor)'u sarmalar |
| Git'te canlı credential | Bugün commit edilmiş gerçek bir `sk_live_...` | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| Güvensiz MCP SDK | Nisan 2026 Anthropic MCP RCE düzeltmesi eksik sabit sürüm | Gömülü advisory feed |
| Genel tavsiye sızıntısı | Sadece kullanıcının kendi verisi hakkında cevap vermesi gereken bir uygulamadan "RRSPs are generally good" | Judge rubric v1 |

Her finding **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026** ve **MITRE ATLAS v5.4.0**'a eşlenir — GitHub Code Scanning ve downstream SIEM araçlarının framework'e göre filtreleyebilmesi için SARIF `ruleId` içinde görünür.

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

Sonra `.purplegate/config.yml` ekleyin — tam şema [`docs/CONFIG.md`](../CONFIG.md)'de. Tam walkthrough [`docs/QUICKSTART.md`](../QUICKSTART.md)'de.

## Mimari

```
┌─ Consumer repo ─────────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ purplegate Docker imajı
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ izole       │
                        │   │                       Claude judge│
                        │   ├─ mcp            (statik tarama)    │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Blue-team savunma tarayıcısı         │
                        │   (severity'yi düşürür — asla         │
                        │    yükseltmez)                        │
                        ├───────────────────────────────────────┤
                        │  Rapor (SARIF + Markdown + JSON)      │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## Tedarik zinciri duruşu

Bu aracın en önemli özelliği, **korumaya çalıştığı saldırı vektörünün kendisi olmamasıdır** — bu nedenle tüketicilerin bize güvenmesi gerekmez, doğrulayabilirler:

- **Docker container action.** Her tarayıcı `Dockerfile`'da SHA ile sabitlenmiştir; runtime'da `pip install` / `npm install` yok.
- **Her üçüncü taraf `uses:` 40 karakterli commit SHA ile sabit** — asla tag ile değil. Mart 2025 (tj-actions) ve Mart 2026 (trivy-action) bize nedenini öğretti.
- **İmzalı release'ler.** `actions/attest-build-provenance` ile Sigstore attestation + cosign keyless + SLSA L3 provenance + SBOM (Syft).
- Hedef **Scorecard ≥ 8/10**; 7'nin altına düşüş release'leri engeller.
- **İlk kullanımdan önce doğrulayın:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

Tam politika [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md)'de. Threat model [`THREAT_MODEL.md`](../../THREAT_MODEL.md)'de.

## Severity ve gate

| Severity | Varsayılan gate | Örnekler |
|---|---|---|
| 🔴 Critical | **CI düşer** | Doğrulanmış canlı credential · RLS'siz public tablo · workflow command injection · güvensiz MCP SDK · doğrulanmış system prompt çıkarımı |
| 🟠 High | **CI düşer** | Auth'suz route · genel tavsiye sızıntısı · CVE ≥ 7.0 · runtime LLM guardrail'leri eksik |
| 🟡 Medium | Sadece rapor | Eksik CSP · sabitlenmemiş MCP olmayan bağımlılık |
| 🟢 Low | Sadece rapor | Alt-optimum Referrer-Policy |

`fail-on:` input'u ile override edin. Allowlist girişleri reason, acknowledged_by ve 365 gün içindeki `expires` gerektirir — bkz [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md).

## Kaçınılacaklar listesi

Araçta dahili olarak yer alır çünkü tedarik zinciri seçimleri güvenlik seçimleridir:

| Proje | Sebep |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154 (Mart 2025 force-push saldırısı) |
| `aquasecurity/trivy-action` **tag ile** | Mart 2026'da tag'ler force-push edildi. Trivy binary'sinin kendisi sorunsuz; onu kendi paketlenmiş imajımızdan doğrudan çağırıyoruz. |
| `tfsec` | Deprecated, Trivy'ye dahil edildi — Checkov kullanın. |
| `protectai/rebuff` | Mayıs 2025'te arşivlendi. |
| CI'da HarmBench / AdvBench corpora'ları | MIT ancak toksik içerik barındırır. |

## Yol haritası

- [x] v0.1 — iskelet: orchestrator + 9 probe + blue-team + SARIF + gate
- [x] v0.2 — 37 testlik fixture paketi + self-test CI
- [ ] v0.3 — sabitlenmiş Dockerfile binary'leri + imzalı GHCR imajı
- [ ] v0.4 — `owasp:llm` preset + Lakera Mosscap / Gandalf corpora ile promptfoo entegrasyonu
- [ ] v0.5 — Checkov bağlantısı + canlı Supabase catalog drift kontrolü
- [ ] v0.6 — Consumer'a özel SARIF suppression helper'ları
- [ ] v1.0 — Marketplace yayını, Scorecard ≥ 8, SLSA L3 imzalı, docs tamamlanmış

## Katkı

v1.0 çıkana kadar arayüzü stabilize ediyoruz; o sonrasında PR'lar memnuniyetle karşılanır. Güvenlik sorunları → [`SECURITY.md`](../../SECURITY.md). Probe eklemeleri → önce severity + taxonomy eşlemesini tartışmak için bir issue açın.

## Lisans

MIT. Bkz [`LICENSE`](../../LICENSE).

---

<div align="center">
  <sub><a href="https://kardoxa.com">Kardoxa Labs</a>'in açık kaynaklı bir projesi. Güvenliği ciddiye alan agentic uygulamalar için.</sub>
</div>
