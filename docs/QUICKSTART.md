# Quickstart

Four steps to get `purplegate` running on your repo.

## 1. Add the workflow

`.github/workflows/security-audit.yml`:

```yaml
name: Security Audit
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch: {}

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@<sha>
        with:
          egress-policy: audit     # flip to 'block' once you have a baseline
      - uses: actions/checkout@<sha>
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: sameermohan-git/purplegate@<sha>   # or @sha256:<digest>
        with:
          config: .purplegate/config.yml
          fail-on: high
          llm-provider: anthropic
          llm-api-key: ${{ secrets.AUDIT_ANTHROPIC_KEY }}
          target-url: ${{ secrets.STAGING_API_URL }}   # optional
```

Replace every `<sha>` with the 40-character commit SHA of the release you want.
See [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md) for the pinning rationale.

## 2. Add a config file

`.purplegate/config.yml` — see [`CONFIG.md`](CONFIG.md) for the full schema. Minimal example:

```yaml
app:
  name: MyApp
  stack: [fastapi, react, supabase]

paths:
  backend: backend
  migrations: supabase/migrations

supabase:
  require_rls: true
  migrations_glob: supabase/migrations/*.sql

fastapi:
  routers_glob: backend/app/api/*.py
  auth_dependencies: [get_current_user]

endpoints:
  - path: /api/v1/ai/chat
    method: POST
    payload_template: { question: "{{inject}}" }
    auth: bearer
```

## 3. Seed an allowlist

`.purplegate/allowlist.yml` — start empty, add entries as needed. Every entry must have an expiry within 365 days.

```yaml
# - finding_id: PROMPT-INJ-042
#   reason: "known off-topic leak; tracked in issue #123"
#   expires: 2026-06-30
#   acknowledged_by: me@example.com
```

## 4. Add secrets

In your GitHub repo **Settings → Secrets and variables → Actions**:

- `AUDIT_ANTHROPIC_KEY` (or `AUDIT_OPENAI_KEY`) — dedicated, low-budget key scoped only to this workflow.
- `STAGING_API_URL` (optional) — the URL of your deployed staging environment for live prompt-injection probing.

## Verify before first run

```bash
# Confirm the release is signed and provenance-attested.
gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
  --repo sameermohan-git/purplegate

# Pull and inspect the image digest.
docker pull ghcr.io/sameermohan-git/purplegate:vX.Y.Z
docker image inspect ghcr.io/sameermohan-git/purplegate:vX.Y.Z | jq '.[0].RepoDigests'
```

Then pin by that digest in your workflow:

```yaml
- uses: sameermohan-git/purplegate@sha256:<digest from above>
```

## First run

Open a throwaway PR that commits a fake secret (e.g. `sk_live_fake`) to verify the
Action fails on Critical. Remove the secret to verify it passes.

## Ongoing

- Renovate/Dependabot opens PRs to bump the pinned SHA — review each PR before merge.
- Review the nightly run's GitHub Code Scanning output on Mondays.
- Rotate `AUDIT_*_KEY` every 90 days.
