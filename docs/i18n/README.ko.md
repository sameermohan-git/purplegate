<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<strong>🇰🇷 한국어</strong> &middot;
<a href="README.pt.md">🇧🇷 Português</a> &middot;
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
<img src="https://img.shields.io/badge/SIGNED-COSIGN%20KEYLESS-2e7d32?style=for-the-badge&labelColor=424242&logo=sigstore&logoColor=white" alt="cosign keyless signed" />
<img src="https://img.shields.io/badge/PROVENANCE-SLSA%20L3-f5a623?style=for-the-badge&labelColor=424242" alt="SLSA Level 3" />
<img src="https://img.shields.io/badge/SBOM-SPDX%20%2B%20CYCLONEDX-1565c0?style=for-the-badge&labelColor=424242" alt="SBOM SPDX + CycloneDX" />

</div>

# purplegate — 안전하지 않은 agentic-AI 머지를 차단

---

<div align="center">

**Agentic 앱은 시크릿을 노출하거나, RLS를 놓치거나, prompt injection을 수용하는 코드를 머지합니다.**
**purplegate는 PR마다 red-team 프로브와 blue-team 디펜스 스캔을 실행하여 — 해당 머지가 출시되기 전에 빌드를 실패시킵니다.**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>라이브 셀프 테스트 →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## 왜 purplegate인가

Agentic-AI 앱은 새로운 공격 표면입니다. 전통적인 SAST는 LLM 고유 버그(prompt injection, 시스템 프롬프트 유출, 사용자 간 데이터 노출)를 놓칩니다. 전통적인 보안 Action은 AI 고유의 공급망(MCP 서버, 벤더 SDK, 취약한 코퍼스)을 놓칩니다. 두 가지 모두 필요합니다. purplegate는 둘 다 커버합니다.

- **🔴 Red-team** — agentic 앱의 모든 위험 클래스를 다루는 8개 프로브: secrets, SAST, 의존성, IaC / RLS, workflow 인젝션, **prompt injection**(격리된 Claude-as-judge), MCP 설정 리스크, HTTP 보안 헤더.
- **🔵 Blue-team** — 런타임 가드레일(LLM Guard, Guardrails AI), 레이트 리미터, 허용 목록 항목을 탐지하는 디펜스 스캐너. 이미 완화된 findings에 대해 **심각도를 낮춥니다**. 심각도는 red-team 베이스라인을 결코 넘지 않습니다.
- **🟣 Purple-team Gate** — 하나의 CI Action, 하나의 SARIF 리포트. 기본적으로 Critical / High findings는 빌드를 실패시키고 Medium / Low는 보고만. 완전히 구성 가능합니다.

## 다른 도구가 놓치는 것을 잡습니다

| 클래스 | 예시 finding | 도구 |
|---|---|---|
| LLM prompt injection | 금융 앱의 scope guard에도 불구하고 "Who is Trump?"에 답변 | promptfoo를 통한 격리된 Claude judge |
| 시스템 프롬프트 유출 | 공격자가 공들인 페이로드로 앱의 지침을 추출 | 같은 judge, 3회 반복 합의 |
| 사용자 간 데이터 노출 | 다른 사용자의 트랜잭션을 참조 | purple-team 전용 프로브 |
| Supabase RLS 누락 | `CREATE TABLE public.transactions` 인데 `ENABLE ROW LEVEL SECURITY` 없음 | 커스텀 정적 검사 |
| Workflow 명령 인젝션 | `run:` 단계 안의 `${{ github.event.issue.title }}` | [zizmor](https://github.com/zizmorcore/zizmor) 래핑 |
| Git에 라이브 자격 증명 | 오늘 커밋된 실제 `sk_live_...` | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| 취약한 MCP SDK | 2026년 4월 Anthropic MCP RCE 패치가 누락된 버전 | 포함된 어드바이저리 피드 |
| 일반 조언 유출 | 사용자 데이터만 다뤄야 할 금융 앱이 "RRSPs are generally good"이라고 답변 | judge rubric v1 |

모든 finding은 **OWASP LLM Top 10 v2025**, **OWASP Agentic 2026**, **MITRE ATLAS v5.4.0**에 매핑되며 — SARIF `ruleId`에 노출되어 GitHub Code Scanning과 다운스트림 SIEM 도구가 프레임워크별로 필터링할 수 있습니다.

## 빠른 시작

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

그 다음 `.purplegate/config.yml`을 추가하세요 — 전체 스키마는 [`docs/CONFIG.md`](../CONFIG.md) 참조. 완전한 walkthrough는 [`docs/QUICKSTART.md`](../QUICKSTART.md)에 있습니다.

## 아키텍처

```
┌─ Consumer 리포지토리 ───────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ purplegate Docker 이미지
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ 격리된      │
                        │   │                       Claude judge│
                        │   ├─ mcp            (정적 스캔)        │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Blue-team 디펜스 스캐너              │
                        │   (심각도 낮춤 — 올리지 않음)         │
                        ├───────────────────────────────────────┤
                        │  리포트 (SARIF + Markdown + JSON)     │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## 공급망 자세

이 도구의 가장 중요한 속성은 **방어하려는 공격 벡터 자체가 되지 않는 것** — 따라서 사용자는 저희를 신뢰할 필요 없이, 직접 검증할 수 있습니다:

- **Docker 컨테이너 Action.** 모든 스캐너를 `Dockerfile`에서 SHA로 고정, 런타임에 `pip install` / `npm install` 없음.
- **모든 제3자 `uses:`는 40자 commit SHA로 고정** — 절대 tag 사용 안 함. 2025년 3월(tj-actions)과 2026년 3월(trivy-action)이 이유를 가르쳐줍니다.
- **서명된 릴리스.** `actions/attest-build-provenance`를 통한 Sigstore attestation + cosign keyless + SLSA L3 provenance + SBOM(Syft).
- **Scorecard ≥ 8/10** 목표값. 7 미만이면 릴리스가 차단됩니다.
- **첫 사용 전 검증:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

전체 정책은 [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md)에. 위협 모델은 [`THREAT_MODEL.md`](../../THREAT_MODEL.md)에 있습니다.

## 심각도 및 Gate

| 심각도 | 기본 gate | 예시 |
|---|---|---|
| 🔴 Critical | **빌드 실패** | 검증된 라이브 자격 증명 · RLS 없는 public 테이블 · workflow 명령 인젝션 · 취약한 MCP SDK · 검증된 시스템 프롬프트 추출 |
| 🟠 High | **빌드 실패** | auth 없는 라우트 · 일반 조언 유출 · CVE ≥ 7.0 · 런타임 LLM 가드레일 누락 |
| 🟡 Medium | 보고만 | CSP 누락 · 고정 안 된 비-MCP 의존성 |
| 🟢 Low | 보고만 | 차선의 Referrer-Policy |

`fail-on:` 입력으로 재정의. 허용 목록 항목에는 reason, acknowledged_by, 365일 이내 `expires`가 필요 — [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md) 참조.

## 회피 목록

공급망 선택이 곧 보안 선택이기에 도구에 내장되어 있습니다:

| 프로젝트 | 이유 |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154(2025년 3월 force-push 침해) |
| `aquasecurity/trivy-action`(**tag 사용**) | 2026년 3월 tag force-push. Trivy 바이너리 자체는 정상; 자체 이미지에서 직접 호출. |
| `tfsec` | 폐기됨, Trivy로 통합됨 — Checkov 사용. |
| `protectai/rebuff` | 2025년 5월 아카이브됨. |
| CI의 HarmBench / AdvBench 코퍼스 | MIT지만 유해 콘텐츠 포함. |

## 로드맵

- [x] v0.1 — 스캐폴드: orchestrator + 9 프로브 + blue-team + SARIF + gate
- [x] v0.2 — 37 테스트 fixture 스위트 + 셀프 테스트 CI
- [ ] v0.3 — 고정된 Dockerfile 바이너리 + 서명된 GHCR 이미지
- [ ] v0.4 — promptfoo 통합, `owasp:llm` preset + Lakera Mosscap / Gandalf 코퍼스
- [ ] v0.5 — Checkov 연결 + Supabase catalog 라이브 드리프트 검사
- [ ] v0.6 — Consumer 전용 SARIF suppression 헬퍼
- [ ] v1.0 — Marketplace 공개, Scorecard ≥ 8, SLSA L3 서명, 문서 완성

## 기여

v1.0 cut 이후 PR 환영; 그때까지는 인터페이스를 안정화 중입니다. 보안 문제 → [`SECURITY.md`](../../SECURITY.md). 프로브 추가 → 먼저 issue로 심각도 + taxonomy 매핑 논의.

## 라이선스

MIT. [`LICENSE`](../../LICENSE) 참조.

---

<div align="center">
  <sub><a href="https://kardoxa.com">Kardoxa Labs</a>의 오픈소스 프로젝트. 보안을 진지하게 여기는 agentic 앱을 위해.</sub>
</div>
