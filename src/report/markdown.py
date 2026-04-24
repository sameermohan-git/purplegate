"""Markdown renderer for the PR comment + GitHub step summary."""
from __future__ import annotations

from src.models import Finding, Report, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: ":red_circle:",
    Severity.HIGH: ":large_orange_diamond:",
    Severity.MEDIUM: ":large_yellow_circle:",
    Severity.LOW: ":white_circle:",
}


def render_markdown(report: Report, *, max_findings: int = 10) -> str:
    """Render a Markdown report suitable for a PR comment."""
    lines: list[str] = []
    lines.append("## agent-redblue-ci — Security Audit")
    lines.append("")
    lines.append(_summary_table(report))
    lines.append("")

    if not report.findings:
        lines.append(":white_check_mark: No findings.")
        return "\n".join(lines)

    # Sort: Critical → Low, then alphabetical rule_id.
    sorted_findings = sorted(
        report.findings,
        key=lambda f: (-f.severity.weight, f.rule_id),
    )

    shown = sorted_findings[:max_findings]
    hidden = len(sorted_findings) - len(shown)

    lines.append(f"### Top {len(shown)} findings")
    lines.append("")
    for f in shown:
        lines.extend(_finding_block(f))
        lines.append("")
    if hidden > 0:
        lines.append(f"_…and {hidden} more. See the full report artifact._")
    return "\n".join(lines)


def _summary_table(report: Report) -> str:
    s = report.stats
    by = s.by_severity
    return (
        "| severity | count |\n"
        "| --- | ---: |\n"
        f"| :red_circle: Critical | {by.get('critical', 0)} |\n"
        f"| :large_orange_diamond: High | {by.get('high', 0)} |\n"
        f"| :large_yellow_circle: Medium | {by.get('medium', 0)} |\n"
        f"| :white_circle: Low | {by.get('low', 0)} |\n"
        f"| **Total** | **{s.total}** |"
    )


def _finding_block(f: Finding) -> list[str]:
    header = f"#### {_SEVERITY_EMOJI[f.severity]} {f.severity.value.upper()} — `{f.rule_id}`"
    location = f"`{f.location.file}`"
    if f.location.start_line:
        location += f":{f.location.start_line}"
    taxonomy = ""
    if f.taxonomy:
        taxonomy = " · ".join(f"`{t.framework.value}:{t.id}`" for t in f.taxonomy)

    lines = [
        header,
        "",
        f"**{f.title}**",
        "",
        f.description or "_(no description provided)_",
        "",
        f"- Location: {location}",
        f"- Finding ID: `{f.finding_id}`",
    ]
    if f.original_severity and f.original_severity != f.severity:
        lines.append(
            f"- Severity adjusted: `{f.original_severity.value}` → `{f.severity.value}` (blue-team defenses detected)"
        )
    if taxonomy:
        lines.append(f"- Taxonomy: {taxonomy}")
    if f.cve_ids:
        lines.append(f"- CVEs: {', '.join(f.cve_ids)}")
    if f.allowlist_entry:
        lines.append(
            f"- :warning: Allowlisted: {f.allowlist_entry.get('reason', '')} "
            f"(expires {f.allowlist_entry.get('expires', 'unknown')})"
        )
    if f.suggested_hardening:
        lines.append("")
        lines.append("<details><summary>Suggested hardening</summary>")
        lines.append("")
        lines.append("```")
        lines.append(f.suggested_hardening)
        lines.append("```")
        lines.append("</details>")
    return lines
