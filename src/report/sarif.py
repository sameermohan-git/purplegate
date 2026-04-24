"""SARIF 2.1.0 renderer.

Each finding becomes a `results[]` entry. Rule definitions with taxonomy
cross-references go in `tool.driver.rules[]` and `tool.driver.taxonomies[]`.
"""
from __future__ import annotations

import json
from typing import Any

from src.models import Finding, Report, Severity, TaxonomyFramework

# Map our internal severity to SARIF level.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def render_sarif(report: Report, *, version: str = "0.1.0") -> str:
    rules = _collect_rules(report.findings)
    results = [_result(f) for f in report.findings]
    taxonomies = _taxonomies_from_findings(report.findings)

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "purplegate",
                        "version": version,
                        "informationUri": "https://github.com/sameermohan-git/purplegate",
                        "rules": rules,
                    },
                    "extensions": taxonomies,
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _collect_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """One rule per unique rule_id."""
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        seen[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id.split("/")[-1],
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "helpUri": f"https://github.com/sameermohan-git/purplegate/blob/main/docs/PROBES.md#{f.probe.value}",
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.original_severity or f.severity]},
            "properties": {
                "probe": f.probe.value,
                "security-severity": _security_severity(f.original_severity or f.severity),
            },
            "relationships": [_relationship(t) for t in f.taxonomy],
        }
    return list(seen.values())


def _taxonomies_from_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """One toolComponent per distinct framework referenced."""
    seen: set[TaxonomyFramework] = set()
    for f in findings:
        for t in f.taxonomy:
            seen.add(t.framework)
    return [_framework_component(fw) for fw in seen]


def _framework_component(fw: TaxonomyFramework) -> dict[str, Any]:
    meta: dict[TaxonomyFramework, tuple[str, str]] = {
        TaxonomyFramework.OWASP_LLM_2025: (
            "owasp-llm-top-10-2025",
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ),
        TaxonomyFramework.OWASP_AGENTIC_2026: (
            "owasp-agentic-2026",
            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
        ),
        TaxonomyFramework.MITRE_ATLAS: (
            "mitre-atlas-v5.4.0",
            "https://atlas.mitre.org/",
        ),
        TaxonomyFramework.OWASP_TOP_10_2021: (
            "owasp-top-10-2021",
            "https://owasp.org/Top10/",
        ),
    }
    name, uri = meta[fw]
    return {
        "name": name,
        "informationUri": uri,
        "fullName": fw.value,
    }


def _relationship(tref) -> dict[str, Any]:
    return {
        "target": {
            "id": tref.id,
            "toolComponent": {"name": _framework_component(tref.framework)["name"]},
        },
        "kinds": ["relevant"],
    }


def _result(f: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    if f.location.start_line:
        region["startLine"] = f.location.start_line
    if f.location.end_line:
        region["endLine"] = f.location.end_line
    if f.location.start_column:
        region["startColumn"] = f.location.start_column
    if f.location.end_column:
        region["endColumn"] = f.location.end_column

    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f.description or f.title},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file},
                    **({"region": region} if region else {}),
                }
            }
        ],
        "partialFingerprints": {"findingId": f.finding_id},
        "properties": {
            "probe": f.probe.value,
            "finding_id": f.finding_id,
            "security-severity": _security_severity(f.severity),
        },
    }
    suppressions = _suppressions(f)
    if suppressions:
        result["suppressions"] = suppressions
    return result


def _security_severity(sev: Severity) -> str:
    # GitHub Code Scanning reads this as a float 0.0–10.0 (CVSS-shaped).
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.0",
    }[sev]


def _suppressions(f: Finding) -> list[dict[str, Any]]:
    if not f.allowlist_entry:
        return []
    return [
        {
            "kind": "external",
            "status": "accepted",
            "justification": f.allowlist_entry.get("reason", ""),
        }
    ]
