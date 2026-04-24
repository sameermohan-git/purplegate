"""SBOM probe — wraps Syft. Emits no findings; drops SPDX + CycloneDX files
into the probe output dir as artifacts.
"""
from __future__ import annotations

import logging
from pathlib import Path

from src.models import Finding, Probe
from src.probes.base import BaseProbe

log = logging.getLogger(__name__)


class SbomProbe(BaseProbe):
    name = Probe.SBOM

    def run(self) -> list[Finding]:
        binary = self.which_or_skip("syft")
        if not binary:
            return []

        out_dir = self.ctx.probe_output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        for fmt, ext in (("spdx-json", "spdx.json"), ("cyclonedx-json", "cdx.json")):
            out_path = out_dir / f"sbom.{ext}"
            proc = self.run_tool(
                [binary, str(self.ctx.repo_root), "-o", f"{fmt}={out_path}", "--quiet"],
                timeout=300,
            )
            if proc.returncode != 0:
                log.warning("syft %s exited %d: %s", fmt, proc.returncode, proc.stderr[:200])

        # SBOM probe never emits findings; it's informational.
        return []

    def tool_versions(self) -> dict[str, str]:
        path = self.which_or_skip("syft")
        if not path:
            return {}
        r = self.run_tool([path, "--version"], timeout=10)
        return {"syft": (r.stdout or r.stderr).strip()}
