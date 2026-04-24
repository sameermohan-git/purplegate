# Taxonomy mapping

Every finding is tagged with a rule ID that maps to one or more industry
taxonomies. SARIF `ruleId` uses our canonical form; SARIF `relationships`
field links to the standards.

## Taxonomies we vendor

| Taxonomy | Version | File | Maintainer |
|---|---|---|---|
| OWASP Top 10 for Large Language Model Applications | **v2025 (v2.0)** | `src/taxonomy/owasp_llm_top10_v2025.yml` | OWASP Foundation |
| OWASP Top 10 for Agentic Applications | **2026** | `src/taxonomy/owasp_agentic_2026.yml` | OWASP Foundation |
| MITRE ATLAS | **v5.4.0 (Feb 2026)** | `src/taxonomy/mitre_atlas_v5_4_0.yml` | MITRE |

## Canonical rule-ID format

```
<probe>/<subsystem>/<short-name>
```

Examples:
- `secrets/trufflehog/stripe-live-key-verified`
- `prompt_injection/owasp-llm01/system-prompt-leak`
- `iac/supabase/missing-rls-on-public-table`
- `workflows/zizmor/template-injection-in-run`
- `mcp/sdk/anthropic-rce-apr-2026`

## SARIF relationships

Each rule lists every standard it maps to via SARIF `relationships`:

```json
{
  "ruleId": "prompt_injection/owasp-llm01/system-prompt-leak",
  "relationships": [
    {
      "target": { "id": "LLM01:2025", "toolComponent": { "name": "OWASP LLM Top 10 v2025" } },
      "kinds": ["superset"]
    },
    {
      "target": { "id": "AML.T0051", "toolComponent": { "name": "MITRE ATLAS v5.4.0" } },
      "kinds": ["relevant"]
    }
  ]
}
```

GitHub Code Scanning renders these as clickable links, and downstream SIEM/GRC
tools can filter by framework.

## Why these three

- **OWASP LLM Top 10 v2025** is the current industry baseline for LLM-app risks.
  If a consumer needs a single answer for "what are we testing against?",
  this is it.
- **OWASP Agentic 2026** specifically covers agent-flavored risks (tool misuse,
  cross-agent manipulation, memory injection) that LLM Top 10 doesn't.
- **MITRE ATLAS v5.4.0** gives us standard technique IDs (`AML.T*`) that map
  cleanly to MITRE ATT&CK for threat-model integration. Feb 2026 added
  `AML.T0062 Publish Poisoned AI Agent Tool` and `AML.T0063 Escape to Host`
  which cover MCP-adjacent attack patterns directly.

## Update policy

- Taxonomy files are **vendored**, not fetched at runtime. The Action never
  hits OWASP or MITRE network endpoints.
- Taxonomies bump only at **major** Action releases. A taxonomy bump means some
  rule IDs may change, which could reset allowlist entries — consumers are
  warned in the changelog.
- Rationale for each bump is documented in `CHANGELOG.md`.

## Rules that don't map

A handful of our rules (e.g., enforcing SHA-pinning of third-party actions)
don't have an OWASP/ATLAS counterpart. These rules still emit a SARIF `ruleId`
and description; the `relationships` array is just empty.
