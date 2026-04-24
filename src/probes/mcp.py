"""MCP probe — static scan of MCP config files and SDK deps.

Purely static: never starts an MCP server, never issues tool calls, never reads
`.env`. Reads JSON configs listed in `mcp.configs` from the consumer config.
"""
from __future__ import annotations

import json
import logging
import re
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


_ATLAS_POISONED_TOOL = TaxonomyRef(
    framework=TaxonomyFramework.MITRE_ATLAS,
    id="AML.T0062",
    url="https://atlas.mitre.org/techniques/AML.T0062",
)

# Literal secrets in MCP config. Same regex family as the secrets probe, scoped
# to the config file's contents.
_SECRET_PATTERNS = [
    ("openai-api-key", r"sk-[A-Za-z0-9]{20,}"),
    ("anthropic-api-key", r"sk-ant-[A-Za-z0-9-]{40,}"),
    ("stripe-live", r"sk_live_[A-Za-z0-9]{24,}"),
    ("supabase-service-role", r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("github-pat", r"gh[pousr]_[A-Za-z0-9]{36,}"),
]
_ENV_INDIRECTION_RE = re.compile(r"\$\{[A-Z_][A-Z0-9_]+\}|\$[A-Z_][A-Z0-9_]+")

# Known bad MCP SDK versions. Update via the `mcp.vulnerable_feed` in defaults.
# Placeholder list for the scaffold — real feed ingestion is a follow-up PR.
_KNOWN_VULNERABLE = {
    # Apr 2026 Anthropic MCP SDK RCE — placeholder pinned version; replace
    # with the real patched-at version when the advisory is parsed.
    "@modelcontextprotocol/sdk": ("<0.6.4", "anthropic-mcp-rce-apr-2026"),
    "mcp": ("<0.11.0", "anthropic-mcp-rce-apr-2026"),
}


class McpProbe(BaseProbe):
    name = Probe.MCP

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_configs())
        findings.extend(self._scan_dep_manifests())
        return findings

    # ── Config scan ─────────────────────────────────────────────────────

    def _scan_configs(self) -> list[Finding]:
        findings: list[Finding] = []
        mcp_cfg = self.ctx.config.get("mcp", {}) or {}
        patterns: list[str] = mcp_cfg.get("configs") or [
            ".claude/settings.json",
            ".claude/settings.local.json",
            "claude_desktop_config.json",
            ".mcp.json",
        ]
        seen: set[Path] = set()
        for pat in patterns:
            for path in sorted(self.ctx.repo_root.glob(pat)):
                if path in seen or not path.is_file():
                    continue
                seen.add(path)
                findings.extend(self._scan_one_config(path))
        return findings

    def _scan_one_config(self, path: Path) -> list[Finding]:
        rel = path.relative_to(self.ctx.repo_root).as_posix()
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return []

        findings: list[Finding] = []

        # Literal secrets.
        for label, pattern in _SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                snippet = text[max(0, m.start() - 20) : m.end() + 20]
                findings.append(
                    Finding(
                        finding_id=make_finding_id(
                            Probe.MCP, f"secret-literal/{label}", rel, m.group(0)
                        ),
                        probe=Probe.MCP,
                        rule_id=f"mcp/config/secret-literal-{label}",
                        severity=Severity.CRITICAL,
                        original_severity=Severity.CRITICAL,
                        title=f"Literal {label} in MCP config {rel}",
                        description=(
                            f"The MCP config {rel} appears to contain a literal {label}. "
                            "MCP servers must read secrets via environment-variable indirection "
                            "(e.g. `${OPENAI_API_KEY}`), never literally."
                        ),
                        location=Location(file=rel),
                        evidence=_mask(snippet),
                        taxonomy=[_ATLAS_POISONED_TOOL],
                        probe_metadata={"pattern": label},
                    )
                )

        # Parse as JSON to inspect server definitions.
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings

        servers = _iter_mcp_servers(data)
        for name, server in servers:
            if not isinstance(server, dict):
                continue
            # Filesystem-root access.
            args = server.get("args") or []
            if isinstance(args, list) and any(a in {"/", "--root=/"} for a in args if isinstance(a, str)):
                findings.append(
                    Finding(
                        finding_id=make_finding_id(
                            Probe.MCP, "fs-root-access", rel, name
                        ),
                        probe=Probe.MCP,
                        rule_id="mcp/config/filesystem-root-access",
                        severity=Severity.HIGH,
                        original_severity=Severity.HIGH,
                        title=f"MCP server '{name}' granted filesystem root",
                        description=(
                            f"MCP server '{name}' in {rel} is configured with root "
                            "filesystem access. Scope to specific directories instead."
                        ),
                        location=Location(file=rel),
                        taxonomy=[_ATLAS_POISONED_TOOL],
                        probe_metadata={"server": name},
                    )
                )
            # Tool allowlist missing.
            tools = server.get("tools") or server.get("allowedTools")
            if tools in (None, "*", ["*"]):
                findings.append(
                    Finding(
                        finding_id=make_finding_id(
                            Probe.MCP, "no-tool-allowlist", rel, name
                        ),
                        probe=Probe.MCP,
                        rule_id="mcp/config/no-tool-allowlist",
                        severity=Severity.HIGH,
                        original_severity=Severity.HIGH,
                        title=f"MCP server '{name}' has no tool allowlist",
                        description=(
                            f"MCP server '{name}' does not restrict which tools it exposes. "
                            "An allowlist (explicit list of tool names) limits blast radius "
                            "if the upstream server adds a risky tool in a future release."
                        ),
                        location=Location(file=rel),
                        taxonomy=[_ATLAS_POISONED_TOOL],
                        probe_metadata={"server": name},
                    )
                )
        return findings

    # ── Dep manifest scan ───────────────────────────────────────────────

    def _scan_dep_manifests(self) -> list[Finding]:
        findings: list[Finding] = []
        # npm
        pkg_json = self.ctx.repo_root / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text())
            except json.JSONDecodeError:
                data = {}
            deps: dict[str, str] = {}
            deps.update(data.get("dependencies") or {})
            deps.update(data.get("devDependencies") or {})
            for name, version in deps.items():
                if name in _KNOWN_VULNERABLE:
                    spec, advisory = _KNOWN_VULNERABLE[name]
                    findings.append(
                        Finding(
                            finding_id=make_finding_id(
                                Probe.MCP, f"sdk-vuln/{advisory}", "package.json", name
                            ),
                            probe=Probe.MCP,
                            rule_id=f"mcp/sdk/{advisory}",
                            severity=Severity.CRITICAL,
                            original_severity=Severity.CRITICAL,
                            title=f"MCP SDK '{name}' version may be vulnerable ({advisory})",
                            description=(
                                f"{name} is pinned at {version}. Advisory {advisory} requires "
                                f"version {spec.lstrip('<>=')} or newer. Update to the patched version."
                            ),
                            location=Location(file="package.json"),
                            evidence=f"{name}: {version}",
                            taxonomy=[_ATLAS_POISONED_TOOL],
                            probe_metadata={"advisory": advisory, "constraint": spec},
                        )
                    )
        return findings

    def tool_versions(self) -> dict[str, str]:
        return {}  # pure-Python probe


def _iter_mcp_servers(data: object):
    """Yield (name, server_dict) pairs from any known MCP config shape."""
    if not isinstance(data, dict):
        return
    # Claude Desktop: { "mcpServers": { "<name>": {...} } }
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, s in servers.items():
            yield name, s
    # Generic: { "servers": [ {"name": "...", ... } ] }
    for s in data.get("servers") or []:
        if isinstance(s, dict):
            yield s.get("name", "unnamed"), s


def _mask(text: str) -> str:
    # Keep shape, lose content.
    return re.sub(r"[A-Za-z0-9]", "*", text)[:160]
