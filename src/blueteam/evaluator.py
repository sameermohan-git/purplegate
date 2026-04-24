"""Blue-team severity adjuster.

Rules:
  - Severity can be lowered by at most 2 levels (critical -> medium).
  - Severity is NEVER raised — red-team severity is the ceiling.
  - Original severity preserved on the finding.
  - Allowlist entries (unexpired) drop severity to LOW and attach the entry.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.config_loader import AllowlistEntry
from src.models import DefenseRef, Finding, Probe, Severity

log = logging.getLogger(__name__)

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def apply_blueteam(
    findings: list[Finding],
    *,
    repo_root: Path,
    config: dict[str, Any],
    allowlist: list[AllowlistEntry],
    defenses: dict[str, Any],
) -> list[Finding]:
    """Return findings with severity adjusted + allowlist entries attached."""
    allow_map = {e.finding_id: e for e in allowlist}
    expected = set(config.get("blueteam", {}).get("expected_guardrails") or [])
    guardrail_hits: dict[str, bool] = defenses.get("guardrails", {})
    rate_limited: set[Path] = defenses.get("rate_limited_files", set())

    adjusted: list[Finding] = []
    for f in findings:
        f.original_severity = f.original_severity or f.severity
        drops = 0

        # Allowlist: worst-case drop to LOW + attach entry.
        if f.finding_id in allow_map:
            entry = allow_map[f.finding_id]
            f.allowlist_entry = entry.to_dict()
            f.severity = Severity.LOW
            f.defenses.append(
                DefenseRef(type="allowlist", status="present", evidence=entry.reason)
            )
            adjusted.append(f)
            continue

        # Prompt-injection neutralized by detected runtime guardrails.
        if f.probe == Probe.PROMPT_INJECTION and _any_guardrail_detected(guardrail_hits):
            drops += 1
            hit_label = next((k for k, v in guardrail_hits.items() if v), None)
            f.defenses.append(
                DefenseRef(type="runtime_guardrail", status="present", evidence=hit_label)
            )

        # SAST finding on a file that ALSO has a rate-limit decorator nearby.
        if f.probe == Probe.SAST and f.location.file:
            p = (repo_root / f.location.file).resolve()
            if p in rate_limited:
                drops += 1
                f.defenses.append(
                    DefenseRef(type="rate_limiter", status="present", evidence="decorator detected in file")
                )

        # Expected-guardrail absence on LLM-app: add an advisory defense=absent
        # annotation so the report surfaces it, but do NOT raise severity
        # (blue-team never raises).
        if "llm_guard" in expected and not guardrail_hits.get("llm_guard"):
            f.defenses.append(
                DefenseRef(type="expected_guardrail_llm_guard", status="absent", evidence=None)
            )

        if drops:
            f.severity = _drop(f.severity, drops)
            log.info(
                "blueteam adjusted %s from %s to %s (drops=%d)",
                f.finding_id, f.original_severity.value, f.severity.value, drops,
            )
        adjusted.append(f)

    return adjusted


def _any_guardrail_detected(guardrail_hits: dict[str, bool]) -> bool:
    return any(guardrail_hits.values())


def _drop(current: Severity, levels: int) -> Severity:
    idx = _SEVERITY_ORDER.index(current)
    new_idx = max(0, idx - levels)
    return _SEVERITY_ORDER[new_idx]
