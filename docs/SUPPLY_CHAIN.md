# Supply chain policy

This Action's single most important property is that **it does not become the
attack vector it's meant to defend against**. Here's how we keep that property.

## Why this matters

- Mar 2025: `tj-actions/changed-files` + 15 `reviewdog/*` actions had tags
  force-pushed with credential-exfiltration code (CVE-2025-30066 / CVE-2025-30154,
  CISA alert). Any consumer pinning by tag was compromised.
- Mar 2026: `aquasecurity/trivy-action` tags force-pushed with malicious code.
  The Trivy binary itself was fine; the Action wrapper was trojanized.
- Apr 2026: RCE in Anthropic MCP SDK affecting 7k+ servers.

Consumers of a security Action are betting their CI on the Action's integrity.
We act accordingly.

## Our rules (for this repo)

1. **Every third-party `uses:` is pinned by 40-character commit SHA.**
   Never by tag. Renovate proposes SHA bumps; reviewers verify each new SHA
   matches a signed upstream release before merging the bump PR.

2. **Minimal permissions on every workflow.** `contents: read` by default,
   `security-events: write` only where SARIF is uploaded, `id-token: write`
   only on signing steps.

3. **`persist-credentials: false` on every checkout.**

4. **No `pull_request_target`** unless the workflow has been audited by zizmor
   and the specific use case is documented.

5. **Vendor, don't fetch-at-runtime.** Every scanner in our Docker image is
   installed at build time with pinned versions + checksums. No `pip install`
   or `npm install` executes when a consumer runs us.

6. **Dockerfile base images pinned by sha256 digest.** `debian:12-slim` and
   both `python:3.12.7-slim-bookworm` stages are pinned to the multi-arch
   index digest (so `linux/amd64` and `linux/arm64` resolve to fixed,
   reproducible bytes). Renovate proposes digest bumps; reviewers verify
   each new digest matches an upstream-published manifest before merging.

7. **Every release is signed and attested.**
   - `actions/attest-build-provenance` (Sigstore) for SLSA L3 provenance.
   - `cosign` keyless signature on the published image.
   - **SBOMs (SPDX + CycloneDX) signed via `cosign sign-blob` keyless** —
     `.sig` (raw signature) and `.pem` (Fulcio-issued certificate binding
     the signature to the workflow's OIDC identity) attach to the GitHub
     Release alongside the JSON SBOMs (since `v0.1.0-alpha.7`).
   - All four release artifacts plus the image are independently verifiable.

8. **`release.yml` permissions scoped at job level.** Top-level is
   `contents: read`. The `build` job opts in to the four write scopes it
   actually needs (`contents`, `packages`, `id-token`, `attestations`) and
   each scope carries an inline comment explaining why. The `verify` job
   is `contents: read` only.

9. **OSSF Scorecard runs on our own repo on every push.** Target ≥ 8/10.
   Live score badge in the README points to
   `https://scorecard.dev/viewer/?uri=github.com/sameermohan-git/purplegate`.
   Drops below 7 should block releases (we'll enforce this once Scorecard
   stabilizes — the project is <90 days old and Scorecard caps the
   `Maintained` check at 0 until then).

10. **CodeQL static analysis on every PR + push to `main`.** Queries:
    `security-extended`. Findings flow to Security → Code scanning. We
    additionally run Semgrep inside the runtime image for our self-test
    suite, but CodeQL is the gate for the OSSF Scorecard SAST check.

11. **Dep additions gated on upstream Scorecard ≥ 7.** Before we add any
    new upstream dependency, we check its Scorecard. Low-score deps are
    rejected.

12. **Image rebuilt on every release, never on `latest`.** The `latest` tag
    points to the current signed digest of the most recent released image.

## Rules we recommend for consumers

### 1. Pin us by SHA or digest

```yaml
- uses: sameermohan-git/purplegate@<40-char-sha>
# or
- uses: sameermohan-git/purplegate@sha256:<image-digest>
```

Renovate or Dependabot will bump the SHA on a schedule. Review each PR.

### 2. Wrap with `step-security/harden-runner`

```yaml
- uses: step-security/harden-runner@<sha>
  with:
    egress-policy: audit   # then 'block' once baselined
```

This provides EDR-style egress monitoring. In `block` mode it fails the runner
on unexpected outbound connections. Our egress domains are listed in
[`CONFIG.md`](CONFIG.md).

### 3. Verify provenance on first adoption

```bash
gh attestation verify \
  oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
  --repo sameermohan-git/purplegate
```

Inspect the image and pin by digest:

```bash
docker pull ghcr.io/sameermohan-git/purplegate:vX.Y.Z
docker image inspect ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
  | jq '.[0].RepoDigests'
```

### 4. Rotate the `llm-api-key`

Use a **dedicated** key scoped to this workflow with a tight budget.
Rotate every 90 days. If the Action is ever confirmed compromised, this is
the first key you revoke.

### 5. Enable native GitHub secret scanning + push-protection

Our `secrets` probe is a back-stop, not the first line of defense.
Push-protection catches secrets before they hit the repo at all.

### 6. Use `actions/dependency-review-action`

Pin by SHA and run on every PR. Catches risky dep additions before they merge.

## How to verify us

Everything we claim is verifiable. None of it is taken on trust.

- **Image digest** — `docker image inspect` or the GHCR UI.
- **Image signature** —
  ```bash
  cosign verify ghcr.io/sameermohan-git/purplegate:vX.Y.Z \
    --certificate-identity-regexp 'https://github.com/sameermohan-git/purplegate/.github/workflows/release\.yml@.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- **Build provenance** — `gh attestation verify oci://ghcr.io/sameermohan-git/purplegate:vX.Y.Z --owner sameermohan-git`.
- **SBOMs (SPDX + CycloneDX)** — JSON files attach to each GitHub Release; one `.cosign.bundle` per SBOM attaches alongside (Sigstore new-bundle format: signature + Fulcio cert + Rekor inclusion proof in a single file). Verify with:
  ```bash
  cosign verify-blob \
    --bundle sbom.spdx.json.cosign.bundle \
    --new-bundle-format \
    --certificate-identity-regexp 'https://github.com/sameermohan-git/purplegate/.github/workflows/release\.yml@.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    sbom.spdx.json
  ```
- **SLSA level** — included as metadata in the `attest-build-provenance` predicate.
- **Scorecard** — https://scorecard.dev/viewer/?uri=github.com/sameermohan-git/purplegate

## If something goes wrong

If you see unexpected behavior from our Action (network egress you didn't
expect, SARIF output that looks tampered, findings we shouldn't be finding),
report immediately per [`../SECURITY.md`](../SECURITY.md). Do not open a public
issue.

We'll respond within 72 hours, publish a post-mortem for any confirmed incident,
and if needed revoke the affected tag/digest within 24 hours.

## Projects we avoid and why

Baked into the README. Summary:
- `tj-actions/*`, `reviewdog/action-setup`/-shellcheck/-staticcheck/-ast-grep/-typos/-composite-template.
- `aquasecurity/trivy-action` (we use Trivy the binary, not this Action).
- `tfsec` (deprecated).
- `protectai/rebuff` (archived May 2025).
- Any Action without a Scorecard score, signed releases, or more than one maintainer.
