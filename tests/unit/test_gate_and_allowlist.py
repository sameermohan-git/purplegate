"""Gate + allowlist-policy tests."""
from datetime import date, timedelta
from pathlib import Path

import pytest

from src.config_loader import AllowlistError, load_allowlist
from src.models import Finding, Location, Probe, Report, Severity, make_finding_id
from src.report.gate import GateFailure, enforce_gate


def _mk(sev: Severity, allowlisted: bool = False) -> Finding:
    f = Finding(
        finding_id=make_finding_id(Probe.SECRETS, "stub/x", "a.py", "x"),
        probe=Probe.SECRETS,
        rule_id="secrets/gitleaks/stub",
        severity=sev,
        title="stub finding",
        description="",
        location=Location(file="a.py"),
    )
    if allowlisted:
        f.allowlist_entry = {"reason": "ok", "expires": "2099-01-01", "acknowledged_by": "ci"}
    return f


class TestGate:

    def test_no_findings_passes(self):
        enforce_gate(Report(findings=[]), "high")

    def test_critical_breaches_high_gate(self):
        report = Report(findings=[_mk(Severity.CRITICAL)])
        report.refresh_stats()
        with pytest.raises(GateFailure):
            enforce_gate(report, "high")

    def test_medium_does_not_breach_high_gate(self):
        report = Report(findings=[_mk(Severity.MEDIUM)])
        report.refresh_stats()
        enforce_gate(report, "high")  # should not raise

    def test_allowlisted_critical_does_not_breach(self):
        report = Report(findings=[_mk(Severity.CRITICAL, allowlisted=True)])
        report.refresh_stats()
        enforce_gate(report, "high")  # allowlisted

    def test_none_never_fails(self):
        report = Report(findings=[_mk(Severity.CRITICAL)])
        report.refresh_stats()
        enforce_gate(report, "none")


class TestAllowlistPolicy:

    def test_missing_expiry_rejected(self, tmp_path: Path):
        p = tmp_path / "allowlist.yml"
        p.write_text(
            "- finding_id: X-1\n"
            "  reason: valid reason with enough text to pass the length check\n"
            "  acknowledged_by: ci\n"
        )
        with pytest.raises(AllowlistError):
            load_allowlist(p)

    def test_expiry_more_than_max_rejected(self, tmp_path: Path):
        far = date.today() + timedelta(days=700)
        p = tmp_path / "allowlist.yml"
        p.write_text(
            f"- finding_id: X-1\n"
            f"  reason: valid reason with enough text to pass the length check\n"
            f"  expires: {far.isoformat()}\n"
            f"  acknowledged_by: ci\n"
        )
        with pytest.raises(AllowlistError):
            load_allowlist(p)

    def test_expired_entry_rejected(self, tmp_path: Path):
        past = date.today() - timedelta(days=1)
        p = tmp_path / "allowlist.yml"
        p.write_text(
            f"- finding_id: X-1\n"
            f"  reason: valid reason with enough text to pass the length check\n"
            f"  expires: {past.isoformat()}\n"
            f"  acknowledged_by: ci\n"
        )
        with pytest.raises(AllowlistError):
            load_allowlist(p)

    def test_short_reason_rejected(self, tmp_path: Path):
        ok = date.today() + timedelta(days=30)
        p = tmp_path / "allowlist.yml"
        p.write_text(
            f"- finding_id: X-1\n"
            f"  reason: short\n"
            f"  expires: {ok.isoformat()}\n"
            f"  acknowledged_by: ci\n"
        )
        with pytest.raises(AllowlistError):
            load_allowlist(p)

    def test_valid_entry_loads(self, tmp_path: Path):
        ok = date.today() + timedelta(days=30)
        p = tmp_path / "allowlist.yml"
        p.write_text(
            f"- finding_id: X-1\n"
            f"  reason: valid reason with enough text to pass the length check\n"
            f"  expires: {ok.isoformat()}\n"
            f"  acknowledged_by: ci\n"
        )
        entries = load_allowlist(p)
        assert len(entries) == 1
        assert entries[0].finding_id == "X-1"
