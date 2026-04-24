# Threat Model

This document says, plainly, what `purplegate` **can** and **cannot** catch, and what
assumptions hold for each probe.

## What this Action is

An automated red-team / blue-team audit for agentic-AI applications, packaged as a
reusable GitHub Action. It wraps established, widely-used OSS scanners plus a
prompt-injection probe, normalizes output to SARIF + Markdown + JSON, and gates
CI on severity.

## What it is not

- **Not a penetration test.** It runs only the static + known-payload checks
  documented in `docs/PROBES.md`. Novel attack techniques, deep business-logic
  flaws, and authenticated multi-stage attacks require a human.
- **Not a replacement for code review.** Semgrep and zizmor catch specific
  documented patterns; originality escapes them.
- **Not a runtime defense.** All probes run in CI. Runtime WAF, rate limiting,
  and output filtering are the consumer's responsibility; the blue-team probe
  only reports whether those defenses exist.
- **Not an AI safety audit.** We test specific prompt-injection and off-topic
  scenarios from curated corpora. We do not enumerate every way an LLM can
  misbehave.

## Threat model (inputs)

| Asset | Threat actor | What we defend |
|---|---|---|
| Source code in the consumer repo | Malicious PR author | `sast`, `secrets`, `workflows`, `iac` probes. |
| CI runner credentials | Compromised third-party Action | SHA-pinning + `harden-runner` recommendation + signed image + provenance. |
| Deployed LLM endpoint | External attacker sending adversarial prompts | `prompt_injection` probe hits the endpoint (if `target-url` provided) with OWASP LLM Top 10 payloads + Lakera corpora. |
| Agent-generated responses | External attacker trying to exfiltrate / jailbreak | Prompt-injection probe judges responses for leakage, generic-advice, cross-tool-boundary, jailbreak acceptance. |
| MCP surface | Malicious MCP server or config | `mcp` probe scans configs + SDK versions. |

## Threat model (the Action itself)

This is the class of threat we take most seriously, because we run in consumer CI
with `contents: read` + (optionally) `security-events: write` + `pull-requests: write`.

| Threat | Mitigation |
|---|---|
| We ship malicious code to consumers via a tag force-push (like tj-actions CVE-2025-30066) | Consumers pin by SHA/digest (documented everywhere). We sign every release via Sigstore; `gh attestation verify` fails on tampered images. |
| An upstream scanner (Semgrep, gitleaks, etc.) is compromised | Tools are pinned by SHA in the Dockerfile; image is rebuilt only on reviewed SHA bumps; Scorecard ≥ 7 gate on dep additions. |
| Our image is trojanized post-publish | Published image digest is attested; consumers can re-verify on every run. |
| `llm-api-key` exfiltration | Key is only visible to the probe subprocess via env var; not logged; never written to artifact output; probe runs in a throwaway container. |
| Attacker embeds adversarial prompt in a fixture that the prompt-injection probe passes to an LLM | Judge runs in isolation, has no tool access, input is sanitized (code blocks and base64 stripped). Attacker input never becomes a judge instruction. |
| Consumer's SARIF output used for RCE on their GitHub App | We conform to SARIF 2.1.0 schema; no executable fields. |

## Known limitations

- **Prompt-injection recall ≤ 80%** on novel attack patterns. The corpus is refreshed per release; novel zero-days will slip past until payloads land.
- **LLM-as-judge is itself injectable** (research Apr 2025: ~73% ASR on naive judges). We isolate + sanitize + optionally double-check with a second classifier, but this is not a solved problem.
- **Static SAST misses logic bugs.** Semgrep rules catch documented patterns; a novel auth bypass that doesn't match a rule will be missed.
- **IaC RLS check is migration-file-based.** If your Supabase migration uses a non-standard pattern or dynamic SQL, our custom Semgrep rule may not flag correctly. Run with live `SUPABASE_DB_URL` for catalog drift detection.
- **MCP SDK vuln feed lags.** We consume `vulnerablemcp.info` + GHSA; any advisory added in the last 24 hours may not be in the vendored list.

## Assumptions

- The consumer's repo uses standard GitHub Actions conventions.
- The consumer's staging URL (if provided) is reachable from `ubuntu-latest` runners.
- The LLM provider API is available and within rate limits; judge errors fail-open (probe is marked inconclusive, not green).
- Network egress from the runner is allowed to tool vendors (npm, pypi for no-op fallback) and the LLM provider. Consumers using `harden-runner` in block mode must allowlist these; `docs/CONFIG.md` lists exact domains.

## Severity rationale

See [`docs/SEVERITY.md`](docs/SEVERITY.md). Short form: Critical/High fail CI by
default; consumer can lower the bar with `fail-on:` input but not below `high`
without explicit opt-in.

## Out-of-band reporting

If you believe a finding is a false positive that recurs across many consumers,
file an issue with the finding JSON (redacted if needed). If you believe we're
missing a class of attack entirely, please open a security-enhancement issue and
propose a payload.
