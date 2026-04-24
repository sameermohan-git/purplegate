"""Secrets probe — wraps gitleaks + trufflehog --only-verified.

Emits Critical for trufflehog-verified live credentials and High for
gitleaks high-entropy matches. Unknown-tool fallback emits 0 findings
(never Critical on tool absence).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from src.models import (
    Finding,
    Location,
    Probe,
    Severity,
    TaxonomyFramework,
    TaxonomyRef,
    make_finding_id,
)
from src.probes.base import BaseProbe

log = logging.getLogger(__name__)


_OWASP_TOP10_SECRETS = TaxonomyRef(
    framework=TaxonomyFramework.OWASP_TOP_10_2021,
    id="A07:2021",
    url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
)


class SecretsProbe(BaseProbe):
    name = Probe.SECRETS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_gitleaks())
        findings.extend(self._run_trufflehog())
        return findings

    # ── gitleaks ────────────────────────────────────────────────────────

    def _run_gitleaks(self) -> list[Finding]:
        binary = self.which_or_skip("gitleaks")
        if not binary:
            return []

        # gitleaks detect --no-banner --report-format json --report-path -
        proc = self.run_tool(
            [
                binary, "detect",
                "--no-banner",
                "--report-format", "json",
                "--report-path", "/dev/stdout",
                "--source", str(self.ctx.repo_root),
            ],
            timeout=600,
        )
        # gitleaks exit code 1 => findings present; not an error.
        if proc.returncode not in (0, 1):
            log.warning("gitleaks exited %d: %s", proc.returncode, proc.stderr[:200])
            return []

        try:
            raw = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            log.warning("gitleaks produced non-JSON output")
            return []

        findings: list[Finding] = []
        for hit in raw:
            file_path = hit.get("File", "")
            rule = hit.get("RuleID", "unknown")
            snippet = hit.get("Match", "")[:200]
            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        Probe.SECRETS, f"gitleaks/{rule}", file_path, snippet
                    ),
                    probe=Probe.SECRETS,
                    rule_id=f"secrets/gitleaks/{rule.lower().replace('_', '-')}",
                    severity=Severity.HIGH,  # unverified → HIGH; verified hits come from trufflehog
                    original_severity=Severity.HIGH,
                    title=f"gitleaks: potential secret ({rule})",
                    description=(
                        "gitleaks matched a high-entropy or pattern-based secret. "
                        "Rotate if real; add to allowlist if a known fixture."
                    ),
                    location=Location(
                        file=file_path,
                        start_line=int(hit.get("StartLine") or 0) or None,
                        end_line=int(hit.get("EndLine") or 0) or None,
                    ),
                    evidence=_redact_secret(snippet),
                    taxonomy=[_OWASP_TOP10_SECRETS],
                    probe_metadata={"tool": "gitleaks", "rule_id": rule},
                )
            )
        return findings

    # ── trufflehog --only-verified ──────────────────────────────────────

    def _run_trufflehog(self) -> list[Finding]:
        binary = self.which_or_skip("trufflehog")
        if not binary:
            return []

        proc = self.run_tool(
            [
                binary, "filesystem",
                str(self.ctx.repo_root),
                "--json",
                "--only-verified",
                "--fail",  # non-zero on finding; we handle
                "--no-update",
            ],
            timeout=600,
        )
        # exit 183 on findings, 0 on clean, anything else is a tool error we ignore
        if proc.returncode not in (0, 183):
            log.warning("trufflehog exited %d: %s", proc.returncode, proc.stderr[:200])
            return []

        findings: list[Finding] = []
        for line in (proc.stdout or "").splitlines():
            if not line.strip():
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = hit.get("DetectorName", "unknown")
            verified = bool(hit.get("Verified", False))
            if not verified:
                continue

            source_meta = (hit.get("SourceMetadata") or {}).get("Data", {})
            fs_meta = source_meta.get("Filesystem") or {}
            file_path = fs_meta.get("file", "")
            line_no = int(fs_meta.get("line") or 0) or None

            snippet = (hit.get("Raw") or "")[:200]
            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        Probe.SECRETS, f"trufflehog/{detector}", file_path, snippet
                    ),
                    probe=Probe.SECRETS,
                    rule_id=f"secrets/trufflehog/{detector.lower().replace(' ', '-')}-verified",
                    severity=Severity.CRITICAL,
                    original_severity=Severity.CRITICAL,
                    title=f"Verified live {detector} credential committed",
                    description=(
                        f"trufflehog verified a LIVE {detector} credential against the provider's "
                        "API. Rotate the key IMMEDIATELY, then remove from git history."
                    ),
                    location=Location(file=file_path, start_line=line_no),
                    evidence=_redact_secret(snippet),
                    taxonomy=[_OWASP_TOP10_SECRETS],
                    probe_metadata={"tool": "trufflehog", "detector": detector, "verified": True},
                )
            )
        return findings

    def tool_versions(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for bin_name in ("gitleaks", "trufflehog"):
            path = self.which_or_skip(bin_name)
            if not path:
                continue
            try:
                r = self.run_tool([path, "--version"], timeout=10)
                out[bin_name] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "unknown"
            except Exception:
                out[bin_name] = "unknown"
        return out


def _redact_secret(snippet: str) -> str:
    """Replace everything after the first 4 chars with asterisks.

    Keeps the finding identifiable (vendor prefix) but never leaks the secret
    back into the report artifact.
    """
    if not snippet:
        return snippet
    if len(snippet) <= 8:
        return "****"
    return snippet[:4] + "*" * (len(snippet) - 4)


def load_path_evidence(path: Path, line: int | None) -> str:
    """Read the line around a finding for use in the PR comment (not stored)."""
    try:
        if not path.is_file() or line is None or line < 1:
            return ""
        lines = path.read_text(errors="replace").splitlines()
        if 0 <= line - 1 < len(lines):
            return lines[line - 1][:200]
    except OSError:
        return ""
    return ""
