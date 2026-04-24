"""Deps probe — wraps osv-scanner + pip-audit + npm audit.

Merges findings by (ecosystem, package, version, cve) tuple. Severity derived
from CVSS when present; falls back to HIGH.
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


_OWASP_A06 = TaxonomyRef(
    framework=TaxonomyFramework.OWASP_TOP_10_2021,
    id="A06:2021",
    url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
)


class DepsProbe(BaseProbe):
    name = Probe.DEPS

    def run(self) -> list[Finding]:
        raw: list[dict] = []
        raw.extend(self._run_osv_scanner())
        raw.extend(self._run_pip_audit())
        # Dedupe on (package, version, cve)
        seen: set[tuple[str, str, str]] = set()
        findings: list[Finding] = []
        for rec in raw:
            key = (rec["package"], rec["version"], rec["id"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._to_finding(rec))
        return findings

    # ── osv-scanner ─────────────────────────────────────────────────────

    def _run_osv_scanner(self) -> list[dict]:
        binary = self.which_or_skip("osv-scanner")
        if not binary:
            return []
        proc = self.run_tool(
            [binary, "--format", "json", "--recursive", str(self.ctx.repo_root)],
            timeout=300,
        )
        # osv-scanner uses non-zero exit codes for findings, plugin warnings,
        # and partial failures — not just hard errors. Try parsing JSON first;
        # only treat unparseable output as a tool failure.
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            log.warning(
                "osv-scanner exited %d with non-JSON output: %s",
                proc.returncode, proc.stderr[:200],
            )
            return []
        if proc.returncode not in (0, 1):
            log.info(
                "osv-scanner exited %d (warnings present, JSON parsed OK)",
                proc.returncode,
            )

        out: list[dict] = []
        for result in data.get("results", []):
            source = (result.get("source") or {}).get("path", "")
            for pkg_res in result.get("packages", []):
                pkg = pkg_res.get("package", {})
                for vuln in pkg_res.get("vulnerabilities", []):
                    out.append(
                        {
                            "source": "osv-scanner",
                            "file": source,
                            "package": pkg.get("name", ""),
                            "version": pkg.get("version", ""),
                            "ecosystem": pkg.get("ecosystem", "Unknown"),
                            "id": vuln.get("id", "UNKNOWN"),
                            "aliases": vuln.get("aliases", []),
                            "summary": vuln.get("summary", ""),
                            "cvss": _extract_cvss(vuln),
                        }
                    )
        return out

    # ── pip-audit ───────────────────────────────────────────────────────

    def _run_pip_audit(self) -> list[dict]:
        """Audit each requirements file in the consumer repo.

        Scans `requirements.txt` and common variants if present. We do NOT
        scan the active environment (default pip-audit behaviour) because in
        this Docker action the active environment is purplegate's own venv,
        not the consumer's. Returns [] if no requirements file is found —
        osv-scanner picks up pyproject.toml + Pipfile + others anyway.
        """
        binary = self.which_or_skip("pip-audit")
        if not binary:
            return []

        candidates = [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements/base.txt",
            "requirements/prod.txt",
        ]
        req_files = [
            self.ctx.repo_root / c
            for c in candidates
            if (self.ctx.repo_root / c).is_file()
        ]
        if not req_files:
            return []

        out: list[dict] = []
        for req_file in req_files:
            rel = req_file.relative_to(self.ctx.repo_root).as_posix()
            proc = self.run_tool(
                [binary, "--format", "json", "-r", str(req_file)],
                cwd=self.ctx.repo_root,
                timeout=300,
            )
            # pip-audit exits 1 when vulnerabilities found, 0 when clean.
            # Anything else is a tool failure (network, parse, etc).
            try:
                data = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                log.warning(
                    "pip-audit exited %d on %s, non-JSON output: %s",
                    proc.returncode, rel, proc.stderr[:200],
                )
                continue
            if proc.returncode not in (0, 1):
                log.warning(
                    "pip-audit exited %d on %s: %s",
                    proc.returncode, rel, proc.stderr[:200],
                )
                # JSON may still be partial / usable — fall through.

            deps = data.get("dependencies", []) if isinstance(data, dict) else data
            for dep in deps or []:
                name = dep.get("name", "")
                version = dep.get("version", "")
                for vuln in dep.get("vulns", []):
                    out.append(
                        {
                            "source": "pip-audit",
                            "file": rel,
                            "package": name,
                            "version": version,
                            "ecosystem": "PyPI",
                            "id": vuln.get("id", "UNKNOWN"),
                            "aliases": vuln.get("aliases", []),
                            "summary": vuln.get("description", ""),
                            "cvss": None,
                        }
                    )
        return out

    # ── Common ──────────────────────────────────────────────────────────

    def _to_finding(self, rec: dict) -> Finding:
        cvss = rec.get("cvss")
        severity = Severity.from_cvss(cvss) if cvss is not None else Severity.HIGH
        cves = [a for a in rec.get("aliases", []) if a.startswith("CVE-")]
        if rec["id"].startswith("CVE-"):
            cves.insert(0, rec["id"])

        title = f"{rec['id']} in {rec['package']}@{rec['version']}"
        return Finding(
            finding_id=make_finding_id(Probe.DEPS, rec["id"], rec["file"], rec["package"]),
            probe=Probe.DEPS,
            rule_id=f"deps/{rec['ecosystem'].lower()}/{rec['id'].lower()}",
            severity=severity,
            original_severity=severity,
            title=title,
            description=rec.get("summary") or title,
            location=Location(file=rec["file"] or rec["package"]),
            evidence=f"{rec['package']} {rec['version']}",
            cve_ids=list(dict.fromkeys(cves)),
            taxonomy=[_OWASP_A06],
            probe_metadata={"source": rec.get("source"), "cvss": cvss, "aliases": rec.get("aliases")},
        )

    def tool_versions(self) -> dict[str, str]:
        out = {}
        for bin_name in ("osv-scanner", "pip-audit"):
            path = self.which_or_skip(bin_name)
            if not path:
                continue
            r = self.run_tool([path, "--version"], timeout=10)
            out[bin_name] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "unknown"
        return out


def _extract_cvss(vuln: dict) -> float | None:
    """Pull the first CVSS base score from an OSV vuln record, if any."""
    severity_list = vuln.get("severity") or []
    for s in severity_list:
        score = s.get("score", "")
        # OSV format: "CVSS_V3" + vector string; need the numeric score from
        # the "metrics" block if present.
    metrics = vuln.get("database_specific", {}).get("cvss_score")
    try:
        if metrics:
            return float(metrics)
    except (TypeError, ValueError):
        return None
    return None
