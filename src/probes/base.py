"""Base class + common utilities for probes.

Every probe subclasses BaseProbe and implements .run() returning list[Finding].
The orchestrator handles status/timing/error capture uniformly.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from src.models import Finding, Probe

log = logging.getLogger(__name__)


class ProbeStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ProbeContext:
    """Everything a probe needs to run. Built by the orchestrator."""

    repo_root: Path
    config: dict[str, Any]
    defaults: dict[str, Any]
    scan_paths: list[Path]
    target_url: str | None = None
    llm_provider: str = "none"
    llm_api_key: str | None = None
    llm_model: str | None = None
    probe_output_dir: Path = field(default_factory=lambda: Path("/tmp/redblue"))


@dataclass
class ProbeResult:
    name: Probe
    status: ProbeStatus
    findings: list[Finding] = field(default_factory=list)
    runtime_ms: int = 0
    error: str | None = None
    tool_versions: dict[str, str] = field(default_factory=dict)


class BaseProbe:
    """Subclasses set `name` and implement `run`."""

    name: Probe = Probe.SECRETS  # override

    def __init__(self, ctx: ProbeContext) -> None:
        self.ctx = ctx

    def run(self) -> list[Finding]:  # pragma: no cover — overridden
        raise NotImplementedError

    def execute(self) -> ProbeResult:
        """Wrap .run() with timing + error capture. Never raises."""
        t0 = time.monotonic()
        try:
            findings = self.run()
            runtime_ms = int((time.monotonic() - t0) * 1000)
            return ProbeResult(
                name=self.name,
                status=ProbeStatus.OK,
                findings=findings,
                runtime_ms=runtime_ms,
                tool_versions=self.tool_versions(),
            )
        except Exception as exc:
            log.exception("Probe %s failed", self.name.value)
            runtime_ms = int((time.monotonic() - t0) * 1000)
            return ProbeResult(
                name=self.name,
                status=ProbeStatus.ERROR,
                findings=[],
                runtime_ms=runtime_ms,
                error=f"{type(exc).__name__}: {exc}",
                tool_versions=self.tool_versions(),
            )

    # ── Helpers subclasses use ──────────────────────────────────────────

    def tool_versions(self) -> dict[str, str]:
        """Return the versions of the external binaries this probe wraps."""
        return {}

    @staticmethod
    def which_or_skip(binary: str) -> str | None:
        """Return absolute path to a required tool, or None if missing.

        If None, the probe should return [] and log — not raise. Missing
        tooling is a deployment issue for the image, not a security finding.
        """
        path = shutil.which(binary)
        if not path:
            log.warning("Binary '%s' not found on PATH; probe will return no findings", binary)
        return path

    @staticmethod
    def run_tool(
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 600,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run an external tool with sane defaults.

        Tools are expected to write JSON/SARIF to stdout. We capture both
        streams as text.
        """
        log.info("running: %s", " ".join(argv))
        return subprocess.run(  # noqa: S603 — we ARE the subprocess wrapper
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )
