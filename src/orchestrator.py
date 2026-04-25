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

    # Reports get written in two places:
    #   1. /tmp/reports/      — kept for backward-compat with anything that
    #                            reads from that path.
    #   2. <workspace>/.purplegate-reports/ — INSIDE the consumer's checkout,
    #                            so a downstream `actions/upload-artifact`
    #                            step can pick them up. Docker-container
    #                            Actions can't add post-steps to upload
    #                            themselves; the workspace-write is the
    #                            workaround.
    formats = {f.strip() for f in report_format.split(",") if f.strip()}
    pr_max = merged.get("reporting", {}).get("pr_comment_max_findings", 10)

    out_dirs = [Path("/tmp/reports"), workspace / ".purplegate-reports"]
    for out_dir in out_dirs:
        out_dir.mkdir(parents=True, exist_ok=True)
    primary_md = out_dirs[0] / "audit.md"
    primary_sarif = out_dirs[0] / "audit.sarif"

    md_text = render_markdown(report, max_findings=pr_max) if "markdown" in formats else ""
    sarif_text = render_sarif(report) if "sarif" in formats else ""
    json_text = report.model_dump_json(indent=2, exclude_none=True) if "json" in formats else ""

    for out_dir in out_dirs:
        if md_text:
            (out_dir / "audit.md").write_text(md_text)
        if sarif_text:
            (out_dir / "audit.sarif").write_text(sarif_text)
        if json_text:
            (out_dir / "audit.json").write_text(json_text)

    _emit_github_outputs(report, primary_md)
    _emit_step_summary(primary_md)

    if upload_sarif.lower() in ("1", "true", "yes") and sarif_text:
        _upload_sarif_to_code_scanning(sarif_text, workspace)

    if comment_on_pr.lower() in ("1", "true", "yes") and md_text:
        _post_pr_comment(md_text, report)

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


# ── SARIF upload to GitHub Code Scanning ─────────────────────────────────────


def _upload_sarif_to_code_scanning(sarif_text: str, workspace: Path) -> None:
    """POST the SARIF to /repos/{owner}/{repo}/code-scanning/sarifs.

    Findings show up on the PR's "Files changed" tab as inline annotations
    AND in the repo's Security → Code Scanning view.

    Required env (provided by GH Actions): GITHUB_TOKEN, GITHUB_REPOSITORY,
    GITHUB_SHA, GITHUB_REF. Token must have `security-events: write`
    permission. Logs + skips silently on any missing piece — never breaks
    the build.
    """
    import base64
    import gzip

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    sha = os.environ.get("GITHUB_SHA")
    ref = os.environ.get("GITHUB_REF")
    if not all([token, repo, sha, ref]):
        log.info("SARIF upload: missing GH context env; skipping")
        return

    try:
        import httpx
    except ImportError:
        log.warning("SARIF upload: httpx not available; skipping")
        return

    encoded = base64.b64encode(gzip.compress(sarif_text.encode("utf-8"))).decode("ascii")
    url = f"https://api.github.com/repos/{repo}/code-scanning/sarifs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "commit_sha": sha,
        "ref": ref,
        "sarif": encoded,
        "tool_name": "purplegate",
    }
    try:
        resp = httpx.post(url, headers=headers, json=payload, timeout=30)
    except httpx.HTTPError as exc:
        log.warning("SARIF upload failed (network): %s", exc)
        return
    if resp.status_code in (200, 202):
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        sarif_id = body.get("id", "<no-id>")
        log.info("SARIF upload: accepted (id=%s)", sarif_id)
    else:
        # Most common: 403 if security-events permission missing on the
        # workflow, or 422 if the repo's Code Scanning is disabled. Both
        # are configuration issues, not tool failures — log loudly.
        log.warning(
            "SARIF upload: HTTP %d. Body: %s",
            resp.status_code, resp.text[:300],
        )


# ── PR comment posting ───────────────────────────────────────────────────────


def _post_pr_comment(markdown_text: str, report: Report) -> None:
    """POST the Markdown report to /repos/{owner}/{repo}/issues/{n}/comments.

    Only runs on `pull_request` events; on push to a branch there's no PR
    number to comment on. Token needs `pull-requests: write`.
    """
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if not all([token, repo, event_path]):
        log.info("PR comment: missing GH context env; skipping")
        return
    if event_name not in ("pull_request", "pull_request_target"):
        log.info("PR comment: event=%s is not a PR; skipping", event_name)
        return

    try:
        import json as _json
        with open(event_path) as fh:
            event = _json.load(fh)
        pr_number = event.get("pull_request", {}).get("number") or event.get("number")
    except (OSError, ValueError) as exc:
        log.warning("PR comment: could not read GITHUB_EVENT_PATH: %s", exc)
        return
    if not pr_number:
        log.info("PR comment: no PR number in event payload; skipping")
        return

    try:
        import httpx
    except ImportError:
        log.warning("PR comment: httpx not available; skipping")
        return

    # Guard against very long reports — GitHub caps comment body at 65,536 chars.
    body = markdown_text
    if len(body) > 60000:
        body = body[:60000] + "\n\n_…report truncated; full version in workflow artifacts._"

    # Tag the comment with a stable marker so we can later choose to update
    # rather than append on subsequent runs (deferred to a follow-up).
    body = "<!-- purplegate-report-v1 -->\n" + body

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        resp = httpx.post(url, headers=headers, json={"body": body}, timeout=30)
    except httpx.HTTPError as exc:
        log.warning("PR comment failed (network): %s", exc)
        return
    if resp.status_code in (200, 201):
        log.info("PR comment: posted on PR #%s", pr_number)
    else:
        log.warning(
            "PR comment: HTTP %d. Body: %s",
            resp.status_code, resp.text[:300],
        )


if __name__ == "__main__":
    main()
