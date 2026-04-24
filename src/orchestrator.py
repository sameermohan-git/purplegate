"""Orchestrator / CLI entry for the Action.

Flow:
  1. Load defaults + consumer config + allowlist.
  2. Run requested probes (each wrapped in error capture).
  3. Run blue-team pass on findings.
  4. Render SARIF + Markdown + JSON to /tmp/reports/.
  5. Enforce severity gate; exit non-zero if breached.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from src.blueteam import apply_blueteam
from src.blueteam.hardening_registry import detect_defenses
from src.config_loader import (
    AllowlistError,
    load_allowlist,
    load_consumer_config,
    load_defaults,
    merge_defaults,
)
from src.models import Finding, Probe, Report
from src.probes.base import ProbeContext, ProbeResult, ProbeStatus
from src.probes.deps import DepsProbe
from src.probes.headers import HeadersProbe
from src.probes.iac import IacProbe
from src.probes.mcp import McpProbe
from src.probes.prompt_injection import PromptInjectionProbe
from src.probes.sast import SastProbe
from src.probes.sbom import SbomProbe
from src.probes.secrets import SecretsProbe
from src.probes.workflows import WorkflowsProbe
from src.report import enforce_gate, render_markdown, render_sarif
from src.report.gate import GateFailure

log = logging.getLogger("purplegate")

_PROBE_REGISTRY = {
    Probe.SECRETS: SecretsProbe,
    Probe.SAST: SastProbe,
    Probe.DEPS: DepsProbe,
    Probe.IAC: IacProbe,
    Probe.WORKFLOWS: WorkflowsProbe,
    Probe.PROMPT_INJECTION: PromptInjectionProbe,
    Probe.MCP: McpProbe,
    Probe.SBOM: SbomProbe,
    Probe.HEADERS: HeadersProbe,
}


@click.command()
@click.option("--config", default=".purplegate/config.yml", show_default=True)
@click.option("--allowlist", default=".purplegate/allowlist.yml", show_default=True)
@click.option("--scan-paths", default=".", show_default=True,
              help="Comma-separated paths to scan (relative to repo root).")
@click.option("--fail-on", default="high", show_default=True,
              type=click.Choice(["critical", "high", "medium", "low", "none"], case_sensitive=False))
@click.option("--report-format", default="markdown,sarif,json", show_default=True,
              help="Comma-separated report formats.")
@click.option("--llm-provider", default="none", show_default=True,
              type=click.Choice(["anthropic", "openai", "azure", "none"], case_sensitive=False))
@click.option("--llm-model", default="", show_default=True)
@click.option("--target-url", default="", show_default=True)
@click.option("--include-probes", default=",".join(p.value for p in Probe), show_default=True)
@click.option("--exclude-probes", default="", show_default=True)
@click.option("--comment-on-pr", default="true", show_default=True)
@click.option("--upload-sarif", default="true", show_default=True)
def main(  # noqa: PLR0913 — Click entry
    config: str,
    allowlist: str,
    scan_paths: str,
    fail_on: str,
    report_format: str,
    llm_provider: str,
    llm_model: str,
    target_url: str,
    include_probes: str,
    exclude_probes: str,
    comment_on_pr: str,
    upload_sarif: str,
) -> None:
    _configure_logging()

    workspace = Path(os.environ.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
    log.info("purplegate starting (workspace=%s)", workspace)

    try:
        cfg = load_consumer_config(workspace / config)
    except FileNotFoundError:
        log.warning("config %s not found; using defaults only", config)
        cfg = {}
    defaults = load_defaults()
    merged = merge_defaults(cfg, defaults)

    try:
        allowlist_entries = load_allowlist(
            workspace / allowlist,
            max_expiry_days=merged.get("allowlist", {}).get("max_expiry_days", 365),
            min_reason_length=merged.get("allowlist", {}).get("min_reason_length", 20),
        )
    except AllowlistError as exc:
        log.error("allowlist rejected: %s", exc)
        sys.exit(2)

    probe_ctx = ProbeContext(
        repo_root=workspace,
        config=merged,
        defaults=defaults,
        scan_paths=[workspace / p.strip() for p in scan_paths.split(",") if p.strip()],
        target_url=target_url or None,
        llm_provider=llm_provider,
        llm_api_key=os.environ.get("PURPLEGATE_LLM_API_KEY") or None,
        llm_model=llm_model or None,
        probe_output_dir=Path("/tmp/redblue"),
    )

    include = {_parse_probe(p) for p in include_probes.split(",") if p.strip()}
    exclude = {_parse_probe(p) for p in exclude_probes.split(",") if p.strip()}
    selected = [p for p in _PROBE_REGISTRY if p in include and p not in exclude]
    log.info("running probes: %s", ", ".join(p.value for p in selected))

    results: list[ProbeResult] = []
    findings: list[Finding] = []
    for probe_enum in selected:
        probe_cls = _PROBE_REGISTRY[probe_enum]
        result = probe_cls(probe_ctx).execute()
        results.append(result)
        findings.extend(result.findings)
        log.info(
            "  %s: %s (%d findings in %dms)%s",
            probe_enum.value,
            result.status.value,
            len(result.findings),
            result.runtime_ms,
            f" error={result.error}" if result.status is ProbeStatus.ERROR else "",
        )

    # Blue-team pass.
    defenses = detect_defenses(workspace, merged)
    findings = apply_blueteam(
        findings,
        repo_root=workspace,
        config=merged,
        allowlist=allowlist_entries,
        defenses=defenses,
    )

    report = Report(
        action_version="0.1.0",
        findings=findings,
        image_digest=os.environ.get("GITHUB_ACTION_REPOSITORY_DIGEST"),
    )
    report.refresh_stats()

    out_dir = Path("/tmp/reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = {f.strip() for f in report_format.split(",") if f.strip()}
    report_path = out_dir / "audit.md"

    if "markdown" in formats:
        pr_max = merged.get("reporting", {}).get("pr_comment_max_findings", 10)
        report_path.write_text(render_markdown(report, max_findings=pr_max))
    if "sarif" in formats:
        (out_dir / "audit.sarif").write_text(render_sarif(report))
    if "json" in formats:
        (out_dir / "audit.json").write_text(
            report.model_dump_json(indent=2, exclude_none=True)
        )

    _emit_github_outputs(report, report_path)
    _emit_step_summary(report_path)

    try:
        enforce_gate(report, fail_on)
    except GateFailure as exc:
        log.error("GATE FAILED: %s", exc)
        sys.exit(1)

    log.info("done (%d findings, gate=%s)", len(findings), fail_on)


def _parse_probe(name: str) -> Probe | None:
    try:
        return Probe(name.strip().lower())
    except ValueError:
        log.warning("unknown probe: %s (ignored)", name)
        return None


def _configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("PURPLEGATE_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _emit_github_outputs(report: Report, report_path: Path) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a") as fh:
        fh.write(f"report-path={report_path}\n")
        fh.write(f"findings-count={report.stats.total}\n")
        fh.write(f"critical-count={report.stats.by_severity.get('critical', 0)}\n")
        fh.write(f"high-count={report.stats.by_severity.get('high', 0)}\n")


def _emit_step_summary(report_path: Path) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary or not report_path.exists():
        return
    with open(summary, "a") as fh:
        fh.write(report_path.read_text())


if __name__ == "__main__":
    main()
