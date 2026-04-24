"""SAST probe — wraps Semgrep CE + adds a Python fallback for FastAPI auth gaps.

The Semgrep wrap invokes `semgrep --config <packs> --sarif` and normalizes the
SARIF output. If the binary isn't available, the fallback AST-walks FastAPI
routers listed in `fastapi.routers_glob` and flags routes missing every declared
`auth_dependencies` symbol.
"""
from __future__ import annotations

import ast
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


_OWASP_A01 = TaxonomyRef(
    framework=TaxonomyFramework.OWASP_TOP_10_2021,
    id="A01:2021",
    url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
)


class SastProbe(BaseProbe):
    name = Probe.SAST

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._run_semgrep())
        findings.extend(self._fastapi_auth_check())
        return findings

    # ── Semgrep CE ──────────────────────────────────────────────────────

    def _run_semgrep(self) -> list[Finding]:
        binary = self.which_or_skip("semgrep")
        if not binary:
            return []

        packs = self.ctx.defaults.get("probes", {}).get("sast", {}).get(
            "rule_packs", ["p/python", "p/javascript", "p/owasp-top-ten"]
        )
        argv: list[str] = [binary, "scan", "--sarif", "--error", "--disable-version-check", "--quiet"]
        for p in packs:
            argv.extend(["--config", p])
        argv.append(str(self.ctx.repo_root))

        proc = self.run_tool(argv, timeout=900)
        # semgrep exits 1 on findings — treat as success.
        if proc.returncode not in (0, 1):
            log.warning("semgrep exited %d: %s", proc.returncode, proc.stderr[:300])
            return []

        try:
            sarif = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            log.warning("semgrep produced non-JSON output")
            return []

        findings: list[Finding] = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                findings.append(self._from_sarif_result(result))
        return findings

    def _from_sarif_result(self, result: dict) -> Finding:
        rule_id = result.get("ruleId") or "semgrep/unknown"
        level = result.get("level") or "warning"
        severity = {
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "note": Severity.LOW,
        }.get(level, Severity.MEDIUM)

        locs = result.get("locations") or []
        file_path = ""
        start_line = None
        if locs:
            phys = locs[0].get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            start_line = region.get("startLine")

        message = (result.get("message") or {}).get("text", "Semgrep finding")[:160]

        return Finding(
            finding_id=make_finding_id(Probe.SAST, rule_id, file_path, message),
            probe=Probe.SAST,
            rule_id=f"sast/semgrep/{rule_id.split('.')[-1].lower()}",
            severity=severity,
            original_severity=severity,
            title=message,
            description=message,
            location=Location(file=file_path, start_line=start_line),
            probe_metadata={"semgrep_rule": rule_id, "level": level},
        )

    # ── FastAPI auth-gap custom check (runs whether Semgrep is present) ──

    def _fastapi_auth_check(self) -> list[Finding]:
        fastapi_cfg = self.ctx.config.get("fastapi", {})
        glob_pat = fastapi_cfg.get("routers_glob", "backend/app/api/*.py")
        accepted_deps = set(fastapi_cfg.get("auth_dependencies", []))
        if not accepted_deps:
            return []

        findings: list[Finding] = []
        for path in sorted(self.ctx.repo_root.glob(glob_pat)):
            try:
                source = path.read_text(errors="replace")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError):
                continue
            rel = path.relative_to(self.ctx.repo_root).as_posix()
            for node in ast.walk(tree):
                finding = self._check_node(node, accepted_deps, rel)
                if finding:
                    findings.append(finding)
        return findings

    def _check_node(
        self, node: ast.AST, accepted_deps: set[str], rel: str
    ) -> Finding | None:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        route_deco = self._route_decorator(node)
        if not route_deco:
            return None
        if self._has_auth_dep(node, accepted_deps):
            return None

        method, path_ = route_deco
        title = f"FastAPI route {method.upper()} {path_} has no auth dependency"
        return Finding(
            finding_id=make_finding_id(Probe.SAST, "fastapi/no-auth-dep", rel, f"{method} {path_}"),
            probe=Probe.SAST,
            rule_id="sast/fastapi/route-without-auth-dep",
            severity=Severity.HIGH,
            original_severity=Severity.HIGH,
            title=title,
            description=(
                f"The handler for '{method.upper()} {path_}' does not use any "
                f"of the configured auth dependencies ({', '.join(sorted(accepted_deps))}). "
                "Either add one via Depends(...) or document the public exemption "
                "in your config."
            ),
            location=Location(file=rel, start_line=node.lineno),
            taxonomy=[_OWASP_A01],
            probe_metadata={"method": method, "path": path_},
        )

    @staticmethod
    def _route_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func
            if not isinstance(func, ast.Attribute):
                continue
            method = func.attr
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not deco.args or not isinstance(deco.args[0], ast.Constant):
                continue
            path_ = deco.args[0].value
            if not isinstance(path_, str):
                continue
            return method, path_
        return None

    @staticmethod
    def _has_auth_dep(
        node: ast.FunctionDef | ast.AsyncFunctionDef, accepted: set[str]
    ) -> bool:
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.annotation is None:
                continue
        # Scan defaults AND kwarg defaults for Depends(<accepted_name>).
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d]
        for default in defaults:
            if not isinstance(default, ast.Call):
                continue
            fname = getattr(default.func, "id", None) or getattr(default.func, "attr", None)
            if fname != "Depends":
                continue
            if default.args and isinstance(default.args[0], ast.Name):
                if default.args[0].id in accepted:
                    return True
        return False

    def tool_versions(self) -> dict[str, str]:
        out = {}
        path = self.which_or_skip("semgrep")
        if path:
            r = self.run_tool([path, "--version"], timeout=10)
            out["semgrep"] = (r.stdout or r.stderr).strip()
        return out
