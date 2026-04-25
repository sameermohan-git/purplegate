<div align="center">

<a href="../../README.md">🇺🇸 English</a> &middot;
<a href="README.zh.md">🇨🇳 中文</a> &middot;
<strong>🇯🇵 日本語</strong> &middot;
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
<img src="https://img.shields.io/badge/SBOM-SPDX%20%2B%20CYCLONEDX%20(SIGNED)-1565c0?style=for-the-badge&labelColor=424242" alt="SBOM SPDX + CycloneDX (signed)" />

<br />

<a href="https://scorecard.dev/viewer/?uri=github.com/sameermohan-git/purplegate"><img src="https://api.securityscorecards.dev/projects/github.com/sameermohan-git/purplegate/badge" alt="OSSF Scorecard" /></a>
<a href="https://github.com/sameermohan-git/purplegate/actions/workflows/codeql.yml"><img src="https://github.com/sameermohan-git/purplegate/actions/workflows/codeql.yml/badge.svg" alt="CodeQL" /></a>
<a href="https://github.com/sameermohan-git/purplegate/actions/workflows/self-test.yml"><img src="https://github.com/sameermohan-git/purplegate/actions/workflows/self-test.yml/badge.svg" alt="self-test" /></a>

</div>

# purplegate — 安全でない agentic-AI マージをブロック

---

<div align="center">

**Agentic アプリは、シークレットを漏らし、RLS を忘れ、prompt injection を受け入れるコードをマージします。**
**purplegate は PR ごとに red-team プローブと blue-team ディフェンススキャンを実行し、そのマージが本番に届く前にビルドを失敗させます。**

</div>

<p align="center">
  <code>uses: sameermohan-git/purplegate@&lt;sha&gt;</code> &nbsp;|&nbsp;
  <code>docker run ghcr.io/sameermohan-git/purplegate:v1</code> &nbsp;|&nbsp;
  <a href="https://github.com/sameermohan-git/purplegate/actions"><strong>ライブセルフテスト →</strong></a>
</p>

<p align="center">
  <a href="https://github.com/sameermohan-git/purplegate/releases"><img src="https://img.shields.io/github/v/release/sameermohan-git/purplegate?display_name=tag&sort=semver&label=release&color=7b1fa2&include_prereleases" alt="release"/></a>
  <img src="https://img.shields.io/badge/tests-37%20passing-brightgreen" alt="tests"/>
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="alpha"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
</p>

---

## なぜ purplegate か

Agentic-AI アプリは新しい種類の攻撃面です。従来の SAST は LLM 固有のバグ(prompt injection、システムプロンプトの漏洩、ユーザー横断のデータ露出)を見逃します。従来のセキュリティ Action は AI 固有のサプライチェーン(MCP サーバー、ベンダー SDK、脆弱なコーパス)を見逃します。両方が必要です。purplegate は両方をカバーします。

- **🔴 Red-team** — agentic アプリのあらゆるリスククラスをカバーする 8 つのプローブ: secrets、SAST、依存関係、IaC / RLS、workflow injection、**prompt injection**(隔離された Claude-as-judge)、MCP 設定リスク、HTTP セキュリティヘッダ。
- **🔵 Blue-team** — ランタイムガードレール(LLM Guard、Guardrails AI)、レートリミッター、許可リストのエントリを検出するディフェンススキャナ。すでに緩和されている検出については **重要度を引き下げ** ます。重要度は red-team のベースラインを超えて引き上げられることはありません。
- **🟣 Purple-team Gate** — 1 つの CI Action、1 つの SARIF レポート。デフォルトで Critical / High の検出はビルドを失敗させます。Medium / Low は報告のみ。完全に設定可能です。

## 他のツールが見逃すものをキャッチ

| クラス | 検出例 | ツール |
|---|---|---|
| LLM prompt injection | 金融アプリのスコープガードにも関わらず「Who is Trump?」に回答 | promptfoo 経由の隔離された Claude judge |
| システムプロンプト漏洩 | 攻撃者が巧妙なペイロードでアプリの指示を抽出 | 同 judge、3 回反復の合意 |
| ユーザー横断データ露出 | 他ユーザーのトランザクションを参照 | purple-team 専用プローブ |
| Supabase RLS 欠落 | `CREATE TABLE public.transactions` に `ENABLE ROW LEVEL SECURITY` なし | カスタム静的チェック |
| Workflow コマンドインジェクション | `${{ github.event.issue.title }}` が `run:` ステップに | [zizmor](https://github.com/zizmorcore/zizmor) をラップ |
| Git にライブクレデンシャル | 本日コミットされた実在の `sk_live_...` | [trufflehog](https://github.com/trufflesecurity/trufflehog) `--only-verified` |
| 脆弱な MCP SDK | 2026 年 4 月の Anthropic MCP RCE 修正が欠けたバージョン | ベンダー済みのアドバイザリーフィード |
| 一般的助言の漏洩 | ユーザー自身のデータのみ扱うべき金融アプリから「RRSPs are generally good」 | judge rubric v1 |

すべての検出は **OWASP LLM Top 10 v2025**、**OWASP Agentic 2026**、**MITRE ATLAS v5.4.0** にマッピングされ、SARIF `ruleId` を通じて GitHub Code Scanning と下流の SIEM ツールがフレームワーク別にフィルタできます。

## クイックスタート

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

次に `.purplegate/config.yml` を追加 — スキーマ全体は [`docs/CONFIG.md`](../CONFIG.md) を参照。完全なウォークスルーは [`docs/QUICKSTART.md`](../QUICKSTART.md) に。

## アーキテクチャ

```
┌─ コンシューマリポジトリ ────────────────┐
│  .purplegate/config.yml                 │
│  .purplegate/allowlist.yml              │
│  .github/workflows/security-audit.yml ──┼─▶ purplegate Docker イメージ
└─────────────────────────────────────────┘     │
                                                ▼
                        ┌───────────────────────────────────────┐
                        │  Orchestrator                         │
                        │   ├─ secrets        (gitleaks + th)   │
                        │   ├─ sast           (Semgrep + AST)   │
                        │   ├─ deps           (osv-scanner)     │
                        │   ├─ iac            (Checkov + RLS)   │
                        │   ├─ workflows      (zizmor)          │
                        │   ├─ prompt_injection ──▶ 隔離された   │
                        │   │                       Claude judge│
                        │   ├─ mcp            (静的スキャン)     │
                        │   ├─ sbom           (Syft)            │
                        │   └─ headers        (httpx)           │
                        ├───────────────────────────────────────┤
                        │  Blue-team ディフェンススキャナ       │
                        │   (重要度を下げる — 上げない)         │
                        ├───────────────────────────────────────┤
                        │  レポート (SARIF + Markdown + JSON)   │
                        │  Gate (fail-on: critical / high / …)  │
                        └───────────────────────────────────────┘
```

## サプライチェーン姿勢

本ツールの最も重要な特性は **自らが防御すべき攻撃ベクトルにならないこと** — 利用者は信頼する必要なく、検証できます:

- **Docker コンテナ Action。** すべてのスキャナを `Dockerfile` 内で SHA 固定、実行時に `pip install` / `npm install` なし。
- **すべての第三者 `uses:` は 40 文字の commit SHA で固定** — tag では決して固定しません。2025 年 3 月(tj-actions)と 2026 年 3 月(trivy-action)の教訓です。
- **署名済みリリース。** `actions/attest-build-provenance` 経由の Sigstore attestation + cosign keyless + SLSA L3 provenance + SBOM(Syft)。
- **Scorecard ≥ 8/10** を目標値とし、7 未満になるとリリースをブロック。
- **初回利用前に検証:**
  ```bash
  gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --repo sameermohan-git/purplegate
  ```

完全なポリシーは [`docs/SUPPLY_CHAIN.md`](../SUPPLY_CHAIN.md) に。脅威モデルは [`THREAT_MODEL.md`](../../THREAT_MODEL.md) に。

## 重要度と Gate

| 重要度 | デフォルト gate | 例 |
|---|---|---|
| 🔴 Critical | **ビルド失敗** | 検証済みライブクレデンシャル · RLS なしのパブリックテーブル · workflow コマンドインジェクション · 脆弱な MCP SDK · 検証済みシステムプロンプト抽出 |
| 🟠 High | **ビルド失敗** | auth なしルート · 一般的助言の漏洩 · CVE ≥ 7.0 · ランタイム LLM ガードレール欠如 |
| 🟡 Medium | 報告のみ | CSP 欠如 · 固定されていない非 MCP 依存 |
| 🟢 Low | 報告のみ | 次善の Referrer-Policy |

`fail-on:` 入力で上書き可能。許可リストエントリには reason、acknowledged_by、365 日以内の `expires` が必須 — [`docs/SUPPRESSIONS.md`](../SUPPRESSIONS.md) 参照。

## 回避リスト

サプライチェーンの選択はセキュリティの選択であるため、本ツールに組み込み済み:

| プロジェクト | 理由 |
|---|---|
| `tj-actions/*` · `reviewdog/action-setup` / `-shellcheck` / `-staticcheck` / `-ast-grep` / `-typos` / `-composite-template` | CVE-2025-30066 / CVE-2025-30154(2025 年 3 月 force-push 事件) |
| `aquasecurity/trivy-action`(**tag 固定**) | 2026 年 3 月 tag force-push。Trivy バイナリ自体は問題なく、自家製イメージから直接呼び出し。 |
| `tfsec` | 廃止、Trivy に統合 — Checkov を使用。 |
| `protectai/rebuff` | 2025 年 5 月アーカイブ済。 |
| CI 内での HarmBench / AdvBench コーパス | MIT だが有害コンテンツを含む。 |

## ロードマップ

- [x] v0.1 — スキャフォールド: orchestrator + 9 プローブ + blue-team + SARIF + gate
- [x] v0.2 — 37 テスト fixture スイート + セルフテスト CI
- [ ] v0.3 — 固定された Dockerfile バイナリ + 署名済み GHCR イメージ
- [ ] v0.4 — promptfoo 統合、`owasp:llm` preset + Lakera Mosscap / Gandalf コーパス
- [ ] v0.5 — Checkov 配線 + Supabase catalog ライブドリフトチェック
- [ ] v0.6 — コンシューマ特化型 SARIF suppression ヘルパー
- [ ] v1.0 — Marketplace 公開、Scorecard ≥ 8、SLSA L3 署名、ドキュメント完備

## 貢献

v1.0 カット後に PR 歓迎;それまではインターフェイスを安定化させています。セキュリティ問題 → [`SECURITY.md`](../../SECURITY.md)。プローブ追加 → まず issue で重要度とタクソノミマッピングを議論。

## ライセンス

MIT. [`LICENSE`](../../LICENSE) を参照。

---

<div align="center">
  <sub><a href="https://kardoxa.com">Kardoxa Labs</a> のオープンソースプロジェクト。セキュリティを真剣に受け止める agentic アプリのために。</sub>
</div>
