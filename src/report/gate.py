"""Severity gate. Exits non-zero when findings breach the threshold."""
from __future__ import annotations

from src.models import Report, Severity

_THRESHOLDS = {
    "critical": Severity.CRITICAL.weight,
    "high": Severity.HIGH.weight,
    "medium": Severity.MEDIUM.weight,
    "low": Severity.LOW.weight,
    "none": 999,  # never fail
}


class GateFailure(Exception):
    """Raised when the gate would fail — caught by the CLI to exit non-zero."""


def enforce_gate(report: Report, fail_on: str) -> None:
    """Raise GateFailure if any finding >= threshold (after allowlisting).

    `fail_on` is the name of the minimum severity that should fail the build
    (so 'high' fails on high + critical).
    """
    fail_on = (fail_on or "high").lower()
    if fail_on not in _THRESHOLDS:
        raise ValueError(f"unknown fail-on value: {fail_on}")
    if fail_on == "none":
        return

    threshold_weight = _THRESHOLDS[fail_on]
    breaching = [
        f for f in report.findings
        if f.severity.weight >= threshold_weight
        and not f.allowlist_entry
    ]
    if breaching:
        by_sev: dict[str, int] = {}
        for f in breaching:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        counts = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items()))
        raise GateFailure(
            f"{len(breaching)} finding(s) at or above '{fail_on}' severity: {counts}"
        )
