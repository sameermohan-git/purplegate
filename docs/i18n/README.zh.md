<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<strong>🇨🇳 中文</strong> &middot;
<a href="README.ja.md">🇯🇵 日本語</a> &middot;
<a href="README.ko.md">🇰🇷 한국어</a> &middot;
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

# purplegate — 阻断不安全的 agentic-AI 合并

---

<div align="center">

**Agentic 应用会合并泄漏密钥、缺少 RLS 或接受 prompt injection 的代码。**
**purplegate 在每次 PR 上运行红队探针和蓝队防御扫描 —— 在那些合并进入生产前让构建失败。**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>在线自测 →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## 为什么选择 purplegate

Agentic-AI 应用代表了全新的攻击面。传统 SAST 无法发现 LLM 特有的缺陷(prompt injection、系统提示词泄漏、跨用户数据泄露)。传统安全 Action 忽视了 AI 特有的供应链(MCP 服务器、依赖的 SDK、受污染的语料)。两者你都需要 —— purplegate 两者兼备。

- **🔴 红队** —— 八个探针覆盖 agentic 应用的所有风险类别:secrets、SAST、依赖、IaC / RLS、workflow 注入、**prompt injection**(隔离式 Claude 评判器)、MCP 配置风险与 HTTP 安全头。
- **🔵 蓝队** —— 防御扫描器,识别运行时护栏(LLM Guard、Guardrails AI)、速率限制器与允许列表条目,然后**将已被缓解的发现的严重级别下调**。严重级别绝不会超过红队的基线。
- **🟣 紫队闸门** —— 一个 CI Action,一份 SARIF 报告。默认情况下 Critical / High 级别的发现会让构建失败;Medium / Low 仅报告。完全可配置。

## 能发现的问题(其他工具看不到)

| 类别 | 示例发现 | 工具 |
|---|---|---|
| LLM prompt injection | 在带 scope 限制的金融应用中仍回答"Who is Trump?" | 通过 promptfoo 的隔离 Claude 评判器 |
| 系统提示词泄漏 | 攻击者通过精心构造的载荷获取应用的指令 | 同一评判器,3 次重复共识 |
| 跨用户数据泄露 | 应用引用其他用户的交易记录 | 紫队专用探针 |
| 缺少 Supabase RLS | `CREATE TABLE public.transactions` 但没有 `ENABLE ROW LEVEL SECURITY` | 自定义静态检查 |
| Workflow 命令注入 | `${{ github.event.issue.title }}` 出现在 `run:` 步骤中 | 封装 [zizmor](https://github.com/zizmorcore/zizmor) |
| Git 中的活凭证 | 今天刚提交的真实 `sk_live_...` | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| 有漏洞的 MCP SDK | 钉住的版本未修复 2026 年 4 月 Anthropic MCP RCE | 内置通告源 |
| 通用建议泄漏 | 本应只回答用户自身数据的金融应用说出 "RRSPs are generally good" | 评判器 rubric v1 |

每一条发现都映射到 **OWASP LLM Top 10 v2025**、**OWASP Agentic 2026** 以及 **MITRE ATLAS v5.4.0** —— 通过 SARIF `ruleId` 字段呈现,GitHub Code Scanning 与下游 SIEM 工具可按框架过滤。

## 快速开始

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

随后添加 `.purplegate/config.yml` —— 完整 schema 参见 [`docs/CONFIG.md`](../CONFIG.md)。完整演练见 [`docs/QUICKSTART.md`](../QUICKSTART.md)。

## 架构

```
┌─ 消费端仓库 ────────────────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ purplegate Docker 镜像
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ 隔离式     │
                        │   │                       Claude 评判器│
                        │   ├─ mcp            (静态扫描)         │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  蓝队防御扫描器                        │
                        │   (严重级别下调 —— 永不上调)          │
                        ├───────────────────────────────────────┤
                        │  报告 (SARIF + Markdown + JSON)       │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## 供应链姿态

本工具最重要的属性是 **它本身不能成为它要防御的攻击向量** —— 因此消费者无需信任我们,可以自行验证:

- **Docker 容器 Action。** 每个扫描器在 `Dockerfile` 中按 SHA 钉住;运行时不执行 `pip install` / `npm install`。
- **每个第三方 `uses:` 都按 40 位 commit SHA 钉住** —— 绝不使用 tag。2025 年 3 月(tj-actions)与 2026 年 3 月(trivy-action)的事件告诉我们为何如此。
- **签名发布。** 通过 `actions/attest-build-provenance` 的 Sigstore attestation + cosign keyless + SLSA L3 provenance + SBOM(Syft)。
- **Scorecard ≥ 8/10** 目标值;低于 7 会阻断发布。
- **首次使用前验证:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

完整策略见 [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md)。威胁模型见 [`THREAT_MODEL.md`](../../THREAT_MODEL.md)。

## 严重级别与 Gate

| 级别 | 默认 gate | 示例 |
|---|---|---|
| 🔴 Critical | **构建失败** | 已验证的活凭证 · 未启用 RLS 的公开表 · workflow 命令注入 · 有漏洞的 MCP SDK · 已验证的系统提示词提取 |
| 🟠 High | **构建失败** | 没有 auth 的路由 · 通用建议泄漏 · CVE ≥ 7.0 · 缺失运行时 LLM 护栏 |
| 🟡 Medium | 仅报告 | 缺少 CSP · 未钉住的非 MCP 依赖 |
| 🟢 Low | 仅报告 | 次优的 Referrer-Policy |

通过 `fail-on:` 输入覆盖。允许列表条目需要 reason、acknowledged_by 以及 365 天内的 `expires` —— 详见 [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md)。

## 避免清单

因为供应链选择就是安全选择,以下内容已内置到工具中:

| 项目 | 原因 |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154(2025 年 3 月 force-push 事件) |
| `aquasecurity/trivy-action`(**使用 tag**) | 2026 年 3 月 tag 被 force-push。Trivy 二进制本身没问题;我们直接从自带镜像中调用它。 |
| `tfsec` | 已弃用,并入 Trivy —— 使用 Checkov。 |
| `protectai/rebuff` | 2025 年 5 月已归档。 |
| CI 中的 HarmBench / AdvBench 语料 | 虽为 MIT 但包含有毒内容。 |

## 路线图

- [x] v0.1 — 脚手架:orchestrator + 9 个探针 + 蓝队 + SARIF + gate
- [x] v0.2 — 37 测试用例 fixture 套件 + 自测 CI
- [ ] v0.3 — 钉住的 Dockerfile 二进制 + 签名的 GHCR 镜像
- [ ] v0.4 — promptfoo 集成,含 `owasp:llm` preset + Lakera Mosscap / Gandalf 语料
- [ ] v0.5 — Checkov 接线 + Supabase catalog 实时漂移检查
- [ ] v0.6 — 消费端专属 SARIF suppression 助手
- [ ] v1.0 — Marketplace 发布,Scorecard ≥ 8,SLSA L3 签名,文档完善

## 贡献

v1.0 切出后欢迎 PR;在此之前我们在稳定接口。安全问题 → [`SECURITY.md`](../../SECURITY.md)。新增探针 → 先开 issue 讨论严重级别与 taxonomy 映射。

## 许可证

MIT。见 [`LICENSE`](../../LICENSE)。

---

<div align="center">
  <sub>来自 <a href="https://kardoxa.com">Kardoxa Labs</a> 的开源项目。为认真对待安全的 agentic 应用而生。</sub>
</div>
