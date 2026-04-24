"""Workflow probe — zizmor (preferred) + Python fallback for the handful of
patterns we absolutely must catch even without the binary.

The fallback checks every `.github/workflows/*.yml` for:
  - `pull_request_target` combined with `${{ github.event.* }}` in `run:`.
  - `persist-credentials: true` OR missing `persist-credentials` on `actions/checkout`.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import yaml

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


_ATLAS_SUPPLY_CHAIN = TaxonomyRef(
    framework=TaxonomyFramework.MITRE_ATLAS,
    id="AML.T0010",
    url="https://atlas.mitre.org/techniques/AML.T0010",
)

_UNTRUSTED_EVENT_RE = re.compile(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.")
_ACTIONS_CHECKOUT_RE = re.compile(r"^\s*actions/checkout(?:@|\s|$)")


class WorkflowsProbe(BaseProbe):
    name = Probe.WORKFLOWS

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_zizmor())
        findings.extend(self._fallback_yaml_check())
        return findings

    # ── zizmor ──────────────────────────────────────────────────────────

    def _run_zizmor(self) -> list[Finding]:
        binary = self.which_or_skip("zizmor")
        if not binary:
            return []

        workflow_dir = self.ctx.repo_root / ".github" / "workflows"
        if not workflow_dir.is_dir():
            return []

        proc = self.run_tool(
            [binary, "--format", "sarif", "--no-progress", str(workflow_dir)],
            timeout=120,
        )
        # zizmor exits 13 when findings present — not a tool error.
        if proc.returncode not in (0, 13, 14):
            log.warning("zizmor exited %d: %s", proc.returncode, proc.stderr[:300])
            return []
        try:
            sarif = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            log.warning("zizmor produced non-JSON output")
            return []

        findings: list[Finding] = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                findings.append(self._from_sarif(result))
        return findings

    def _from_sarif(self, result: dict) -> Finding:
        rule_id = result.get("ruleId") or "zizmor/unknown"
        level = (result.get("level") or "warning").lower()
        severity = {"error": Severity.CRITICAL, "warning": Severity.HIGH, "note": Severity.MEDIUM}.get(
            level, Severity.MEDIUM
        )
        locs = result.get("locations") or []
        file_path = ""
        start_line = None
        if locs:
            phys = locs[0].get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            start_line = region.get("startLine")
        message = (result.get("message") or {}).get("text", "Workflow finding")[:160]
        return Finding(
            finding_id=make_finding_id(Probe.WORKFLOWS, rule_id, file_path, message),
            probe=Probe.WORKFLOWS,
            rule_id=f"workflows/zizmor/{rule_id.split('.')[-1].lower()}",
            severity=severity,
            original_severity=severity,
            title=message,
            description=message,
            location=Location(file=file_path, start_line=start_line),
            taxonomy=[_ATLAS_SUPPLY_CHAIN],
            probe_metadata={"tool": "zizmor", "rule_id": rule_id},
        )

    # ── Fallback YAML check ─────────────────────────────────────────────

    def _fallback_yaml_check(self) -> list[Finding]:
        findings: list[Finding] = []
        workflow_dir = self.ctx.repo_root / ".github" / "workflows"
        if not workflow_dir.is_dir():
            return []

        for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
            try:
                text = path.read_text(errors="replace")
                data = yaml.safe_load(text) or {}
            except (OSError, yaml.YAMLError):
                continue
            rel = path.relative_to(self.ctx.repo_root).as_posix()
            findings.extend(self._scan_workflow(data, text, rel))
        return findings

    def _scan_workflow(self, data: dict, text: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        triggers = data.get("on") or data.get(True)  # yaml quirk: on: is parsed as True
        has_prt = self._has_pull_request_target(triggers)

        for job_name, job in (data.get("jobs") or {}).items():
            steps = (job or {}).get("steps") or []
            for i, step in enumerate(steps):
                run = step.get("run") or ""
                uses = step.get("uses") or ""
                if has_prt and isinstance(run, str) and _UNTRUSTED_EVENT_RE.search(run):
                    findings.append(
                        Finding(
                            finding_id=make_finding_id(
                                Probe.WORKFLOWS, "prt-injection", rel, run
                            ),
                            probe=Probe.WORKFLOWS,
                            rule_id="workflows/fallback/pull-request-target-untrusted-input",
                            severity=Severity.CRITICAL,
                            original_severity=Severity.CRITICAL,
                            title=f"pull_request_target + untrusted input in '{job_name}' step {i + 1}",
                            description=(
                                "This workflow runs on pull_request_target (privileged token) "
                                "and interpolates attacker-controllable github.event fields "
                                "inside a run: block. This is a classic command-injection sink. "
                                "Move the logic to pull_request and/or read values from files, "
                                "not via ${{ github.event.* }} expansion."
                            ),
                            location=Location(file=rel),
                            taxonomy=[_ATLAS_SUPPLY_CHAIN],
                            probe_metadata={"job": job_name, "step_index": i},
                        )
                    )
                if _ACTIONS_CHECKOUT_RE.search(uses):
                    with_ = step.get("with") or {}
                    persist = with_.get("persist-credentials")
                    if persist is not False:
                        findings.append(
                            Finding(
                                finding_id=make_finding_id(
                                    Probe.WORKFLOWS, "checkout-persists-credentials", rel, uses
                                ),
                                probe=Probe.WORKFLOWS,
                                rule_id="workflows/fallback/checkout-persists-credentials",
                                severity=Severity.HIGH,
                                original_severity=Severity.HIGH,
                                title=f"actions/checkout without persist-credentials: false in '{job_name}'",
                                description=(
                                    "actions/checkout stores the job token in the git config by "
                                    "default. If any subsequent step runs untrusted code "
                                    "(including a vendored build script or third-party action), "
                                    "it can push to the repo. Always set `persist-credentials: false`."
                                ),
                                location=Location(file=rel),
                                taxonomy=[_ATLAS_SUPPLY_CHAIN],
                                probe_metadata={"job": job_name, "step_index": i, "uses": uses},
                            )
                        )
        return findings

    @staticmethod
    def _has_pull_request_target(triggers: object) -> bool:
        if triggers is None:
            return False
        if isinstance(triggers, str):
            return triggers == "pull_request_target"
        if isinstance(triggers, list):
            return "pull_request_target" in triggers
        if isinstance(triggers, dict):
            return "pull_request_target" in triggers
        return False

    def tool_versions(self) -> dict[str, str]:
        out = {}
        path = self.which_or_skip("zizmor")
        if path:
            r = self.run_tool([path, "--version"], timeout=10)
            out["zizmor"] = (r.stdout or r.stderr).strip()
        return out
