"""Unit tests for the blue-team severity adjuster."""
from pathlib import Path

from src.blueteam import apply_blueteam
from src.config_loader import AllowlistEntry
from src.models import (
    DefenseRef,
    Finding,
    Location,
    Probe,
    Severity,
    make_finding_id,
)


def _mk(probe: Probe, sev: Severity, rel: str = "app/api/foo.py") -> Finding:
    return Finding(
        finding_id=make_finding_id(probe, f"{probe.value}/stub", rel, "x"),
        probe=probe,
        rule_id=f"{probe.value}/stub/x",
        severity=sev,
        title="stub finding",
        description="",
        location=Location(file=rel),
    )


class TestAllowlistDropsToLow:

    def test_matching_entry_drops_critical_to_low(self, tmp_path):
        f = _mk(Probe.SECRETS, Severity.CRITICAL)
        entry = AllowlistEntry({
            "finding_id": f.finding_id,
            "reason": "known sample fixture for unit tests",
            "expires": "2099-01-01",
            "acknowledged_by": "ci",
        })
        out = apply_blueteam(
            [f],
            repo_root=tmp_path,
            config={},
            allowlist=[entry],
            defenses={"guardrails": {}, "rate_limited_files": set()},
        )
        assert out[0].severity == Severity.LOW
        assert out[0].original_severity == Severity.CRITICAL
        assert out[0].allowlist_entry is not None


class TestGuardrailDrops:

    def test_prompt_injection_with_llm_guard_drops_one_level(self, tmp_path):
        f = _mk(Probe.PROMPT_INJECTION, Severity.HIGH)
        out = apply_blueteam(
            [f],
            repo_root=tmp_path,
            config={},
            allowlist=[],
            defenses={"guardrails": {"llm_guard": True}, "rate_limited_files": set()},
        )
        assert out[0].severity == Severity.MEDIUM
        assert any(d.type == "runtime_guardrail" and d.status == "present" for d in out[0].defenses)


class TestRateLimiterDrop:

    def test_sast_on_rate_limited_file_drops_one_level(self, tmp_path):
        path = tmp_path / "app" / "api" / "foo.py"
        path.parent.mkdir(parents=True)
        path.write_text("# stub")
        f = _mk(Probe.SAST, Severity.HIGH, rel="app/api/foo.py")
        out = apply_blueteam(
            [f],
            repo_root=tmp_path,
            config={},
            allowlist=[],
            defenses={"guardrails": {}, "rate_limited_files": {path.resolve()}},
        )
        assert out[0].severity == Severity.MEDIUM


class TestSeverityNeverRises:

    def test_no_adjustment_keeps_severity(self, tmp_path):
        f = _mk(Probe.SAST, Severity.MEDIUM)
        out = apply_blueteam(
            [f],
            repo_root=tmp_path,
            config={},
            allowlist=[],
            defenses={"guardrails": {}, "rate_limited_files": set()},
        )
        assert out[0].severity == Severity.MEDIUM
        assert out[0].original_severity == Severity.MEDIUM
