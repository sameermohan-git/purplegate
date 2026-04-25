# Translations

purplegate's README and docs are maintained in English. Translations are welcome
and live under `docs/i18n/` — one directory per locale.

## Currently available

None yet. The flag links at the top of the README anticipate translations
landing here.

## Adding a translation

1. Fork + clone the repo.
2. Copy `README.md` to `docs/i18n/README.<lang>.md` (e.g. `README.ja.md`).
3. Translate the README content. Do **not** translate code blocks, CLI flags,
   rule IDs, or tool names. Keep taxonomy IDs (OWASP LLM01:2025, AML.T0051, etc.) verbatim.
4. Keep the supply-chain section accurate — it's not negotiable. If the threat
   taxonomy doesn't translate cleanly, link back to the English version rather than paraphrase.
5. Open a PR with subject `docs: add <language> translation`.
6. A maintainer will verify the sensitive sections (supply-chain, severity,
   avoid-list) are faithful to the original.

## Maintaining a translation

Translations drift. When a translation is > 2 minor versions behind the English
README, the flag link on the main README is struck through until a refresh PR lands.

**Translation freshness:** translations are kept loosely in sync with English
via mechanical badge / link updates per release. Body prose lags by one or
two minor versions — when English describes a claim more nuanced than a
translation, the English version at the time of the release is authoritative.
Refer to `../../README.md` from any translation if details diverge.

## Why manual translations, not LLM auto-translation

This is a security tool. A mistranslated threat claim — "verified live credential"
rendered as "possibly leaked credential" — changes the severity consumers act on.
Human review stays in the loop.
