# Suppressions / Allowlist

The allowlist is where you declare that a known finding is acknowledged and
shouldn't block CI. Every entry must be **dated** and **reviewed on expiry**.

## Format

`.purplegate/allowlist.yml`:

```yaml
- finding_id: SECRETS-a1b2c3d4
  reason: "Sample Stripe test key used by unit test fixture."
  expires: 2026-10-15
  acknowledged_by: sam@example.com

- finding_id: PROMPT-INJ-42
  reason: "Known off-topic leak on /api/v1/ai/chat; judge-agent planned (issue #123)."
  expires: 2026-06-30
  acknowledged_by: sam@example.com
```

## Rules

The gate script rejects allowlist entries that:

1. Have no `expires` field.
2. Have an `expires` date more than 365 days in the future.
3. Have an `expires` date already in the past (expired-without-renewal).
4. Have no `reason` or a reason under 20 characters.
5. Have no `acknowledged_by` (must be a real email or GitHub handle).

If your allowlist is rejected, the Action exits non-zero with a specific
message identifying the bad entry — fix it and re-run.

## Finding IDs

Finding IDs are **stable across runs** — the same underlying issue produces the
same ID so an allowlist entry written today keeps working tomorrow.

Stability is achieved by hashing:
- Probe name
- Rule ID (Semgrep rule, CVE ID, Checkov check ID, etc.)
- File path
- Code snippet (whitespace-normalized)

If you refactor the code and the hash changes, the old allowlist entry stops
matching and the finding reappears. This is intentional — you need to re-review.

## When NOT to allowlist

- **Verified live credentials** — rotate, don't allowlist.
- **Missing auth on a public-facing route** — add the auth dep.
- **Critical CVEs in runtime deps** — upgrade or replace the dep.
- **RLS missing on a public table** — add RLS.

If an entry reaches the 365-day max expiry without a fix, the finding is
re-surfaced and you're forced to either fix or explicitly renew with a new
justification.

## Workflow

1. CI fails with a finding you've decided to accept for now.
2. Open an issue with the fix plan. Set a realistic date.
3. Add the allowlist entry referencing the issue in `reason:`.
4. Review the allowlist every quarter; delete entries whose issues are closed.
5. When `expires` approaches, either fix the finding or extend with a new
   justification (not a simple date bump — describe what changed).

## Visible and auditable

The allowlist file is checked into the repo. It's visible in PR diffs. Reviewers
should scrutinize every new entry. A large or rapidly-growing allowlist is a
signal that the gate is not being taken seriously — not a bug to work around.
