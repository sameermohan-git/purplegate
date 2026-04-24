# Branding assets

## `logo.png` — required

The README and the GitHub social-preview both reference `assets/logo.png`.

**Specs**
- Square, 512×512 minimum (1024×1024 preferred for high-DPI displays).
- PNG with transparent background.
- Purple-dominant palette consistent with the name.
- No stock-photo fragments, no other company logos, no AI-generated text artefacts.

**Design direction (pick one; all render cleanly at 220px)**

1. **Hexagonal shield** — a purple hex with a red/blue diagonal split meeting in the centre. Thin purple outline. Small circuit-board trace fading into the background.
2. **Gate silhouette** — two vertical bars forming a gate, left bar red, right bar blue, gate centre / crossbar purple. Minimal, geometric.
3. **Wordmark** — lowercase "purplegate" in a monospace-inspired sans (e.g. JetBrains Mono, Space Grotesk), lowercase g stylised as a padlock hasp. Purple tint.

**Acceptance criteria**
- Readable at 48×48 (favicon size).
- No text smaller than 16px at 1× render.
- Contrast ratio ≥ 4.5:1 on both dark-mode and light-mode GitHub backgrounds.

**How to submit**

Open a PR with:
- `assets/logo.png` (the rendered PNG).
- `assets/logo.svg` (the vector source, if available).
- A CC0 / MIT attribution statement in the PR description.

Maintainers will merge after verifying the spec + attribution. The chosen logo is
credited in `CHANGELOG.md` at the next release.

## `social-preview.png` — optional

1280×640 PNG for the GitHub repo's social-preview setting. Same palette, adds
the headline "Block insecure agentic-AI merges" to the right of the logo.
Upload via **Repo Settings → Options → Social preview**.
