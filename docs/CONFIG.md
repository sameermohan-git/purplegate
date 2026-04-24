# Configuration reference

The Action reads `.purplegate/config.yml` from the consumer repo root (override
with the `config:` input). The full JSON schema lives at `config/schemas/config.schema.json`.

## Top-level sections

```yaml
app:               # descriptive metadata
  name: MyApp
  stack: [fastapi, react, supabase, ios-swiftui]

paths:             # where each layer lives in the repo
  backend: backend
  frontend: src
  migrations: supabase/migrations
  ios: ios
  infrastructure: infrastructure

supabase:
  require_rls: true
  migrations_glob: supabase/migrations/*.sql
  # Optional: live catalog drift check.
  # SUPABASE_DB_URL must be provided via `env:` in the workflow step.
  db_url_env: SUPABASE_DB_URL

fastapi:
  routers_glob: backend/app/api/*.py
  # The Action considers a route authenticated if ANY of these symbols appears
  # in its Depends() chain. Add every acceptable auth dependency for your app.
  auth_dependencies:
    - get_current_user
    - require_ai_access
    - get_admin_user

endpoints:         # probed by prompt_injection when target-url is set
  - path: /api/v1/ai/chat
    method: POST
    payload_template: { question: "{{inject}}" }
    auth: bearer                     # bearer | none

secrets:
  # Custom regex patterns in addition to the built-in gitleaks/trufflehog rules.
  # Use for vendor keys that aren't in the defaults (e.g. Flinks, Cartesia).
  patterns:
    - name: flinks_secret
      regex: '(?i)flinks[_-]?secret[_-]?key["\s:=]+[A-Za-z0-9_-]{24,}'

mcp:
  # Dev-side MCP configs to scan. Supports globs.
  configs:
    - .claude/settings.json
    - .claude/settings.local.json
    - .mcp.json

probes:
  # Per-probe overrides. Severity can be lowered per-probe but not raised.
  secrets:
    history_commits: 200    # how far back to scan; default 200
  deps:
    ignore_paths:           # never scan these for SCA
      - tests/fixtures/
  prompt_injection:
    max_payloads: 80        # cap for PR runs; nightly uses full preset
    owasp_preset: true
    lakera_mosscap: true
    lakera_gandalf: true
    custom_packs:
      - .purplegate/attacks/custom_chat.yaml

blueteam:
  # Blue-team gets extra credit when these runtime defenses are detected.
  expected_guardrails:
    - llm_guard        # ProtectAI llm-guard imported in backend
    - guardrails_ai    # Guardrails AI validators
  rate_limit_decorators:
    - limiter.limit
    - RateLimiter

allowlist_path: .purplegate/allowlist.yml
```

## Inputs that live on the Action itself (not in config)

Some controls are workflow-time only and are passed via `with:`:

| Input | Purpose |
|---|---|
| `fail-on` | Severity gate — `critical` / `high` / `medium` / `low` / `none`. |
| `llm-provider` / `llm-api-key` / `llm-model` | LLM for the prompt-injection judge. `none` disables the probe. |
| `target-url` | Live endpoint for prompt-injection + headers probes. If omitted, prompt-injection runs against an offline mock. |
| `include-probes` / `exclude-probes` | Override the default probe list. |
| `comment-on-pr` | `true` / `false` — whether to post a PR summary comment. |
| `upload-sarif` | `true` / `false` — SARIF upload to GitHub Code Scanning. |

## Environment variables

The Action looks for these in the runner environment:

- `PURPLEGATE_LLM_API_KEY` — set from the `llm-api-key` input.
- `GITHUB_TOKEN` — auto-set from `${{ github.token }}`; needed for PR comment + SARIF upload.
- `SUPABASE_DB_URL` — optional; if set, `iac` probe does a live Supabase catalog RLS check.
- `PURPLEGATE_ALLOW_NETWORK` — set to `1` only when you intentionally want probes to reach the internet (e.g. OSV feed updates). Default: offline-only.

## Egress domains (for `harden-runner` block mode)

If you harden the runner with `egress-policy: block`, allowlist these:

```
api.github.com
ghcr.io
*.ghcr.io
objects.githubusercontent.com
api.osv.dev
api.anthropic.com   # if llm-provider=anthropic
api.openai.com      # if llm-provider=openai
*.openai.azure.com  # if llm-provider=azure
```

The Action does not reach out to telemetry, analytics, or third-party services
beyond these. Verify in your harden-runner baseline before flipping to `block`.
