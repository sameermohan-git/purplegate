"""Scans the consumer repo for positive defense signals (not red-team findings).

Results are consumed by `evaluator.apply_blueteam` to adjust severity down
on findings that are already mitigated by runtime defenses.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Runtime guardrails we recognize. Extend as the ecosystem grows.
# Keyed by a short label; value is the import/symbol to grep for.
_GUARDRAIL_IMPORTS = {
    "llm_guard": re.compile(r"^(?:from|import)\s+llm_guard\b", re.MULTILINE),
    "guardrails_ai": re.compile(r"^(?:from|import)\s+guardrails\b", re.MULTILINE),
    "nemo_guardrails": re.compile(r"^(?:from|import)\s+nemoguardrails\b", re.MULTILINE),
}

# Rate-limit decorators we recognize by default. Consumer can add more via
# `blueteam.rate_limit_decorators` in the config.
_DEFAULT_RATE_LIMIT_RE = re.compile(
    r"@\s*(?:limiter\.limit|RateLimiter|rate_limit|throttle)\b"
)


def detect_defenses(
    repo_root: Path,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Walk the backend tree once and report what defenses exist.

    Returned shape:
      {
        "guardrails":     {"llm_guard": True, "guardrails_ai": False, ...},
        "rate_limited_files": {Path, ...},
      }
    """
    backend = repo_root / (config.get("paths", {}).get("backend") or "backend")
    if not backend.is_dir():
        # Fall back to repo root so tiny projects without a split layout still work.
        backend = repo_root

    custom_rl = config.get("blueteam", {}).get("rate_limit_decorators") or []
    custom_rl_re = re.compile(r"@\s*(" + "|".join(map(re.escape, custom_rl)) + r")\b") if custom_rl else None

    guardrail_hits = {label: False for label in _GUARDRAIL_IMPORTS}
    rate_limited_files: set[Path] = set()

    for path in backend.rglob("*.py"):
        try:
            source = path.read_text(errors="replace")
        except OSError:
            continue

        for label, pattern in _GUARDRAIL_IMPORTS.items():
            if not guardrail_hits[label] and pattern.search(source):
                guardrail_hits[label] = True

        if _DEFAULT_RATE_LIMIT_RE.search(source) or (custom_rl_re and custom_rl_re.search(source)):
            rate_limited_files.add(path.resolve())

    return {
        "guardrails": guardrail_hits,
        "rate_limited_files": rate_limited_files,
    }
