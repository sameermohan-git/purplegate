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

# Known MCP SDK + reference-server vulnerabilities.
#
# Each entry: package_name -> [(vulnerable_version_spec, advisory_id, severity, class, advisory_url)]
# A package may have multiple unrelated CVEs — use a list.
#
# Scope: only entries sourced from a primary advisory (GHSA, NVD, GitLab
# advisory DB, or vendor disclosure) and where both the package name and
# the fix version are confirmed. Unverified advisories (where the fix
# version cutoff could not be read from the GHSA directly) are
# intentionally omitted — see docs/PROBES.md for the next-pass list.
#
# Last refreshed: 2026-04-24. Re-verify before each minor release.

_KNOWN_VULNERABLE: dict[str, list[tuple[str, str, str, str, str]]] = {
    # ── npm — @modelcontextprotocol/* (Anthropic reference SDKs + servers) ──
    "@modelcontextprotocol/sdk": [
        ("<1.25.2", "CVE-2026-0621", "medium", "redos-dos",
         "https://advisories.gitlab.com/pkg/npm/@modelcontextprotocol/sdk/CVE-2026-0621/"),
        (">=1.10.0,<1.26.0", "CVE-2026-25536", "high", "cross-client-data-leak",
         "https://nvd.nist.gov/vuln/detail/CVE-2026-25536"),
    ],
    "@modelcontextprotocol/inspector": [
        ("<0.14.1", "CVE-2025-49596", "critical", "unauth-rce",
         "https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596"),
    ],
    "@modelcontextprotocol/server-filesystem": [
        # Pair of symlink-bypass + directory-containment CVEs, both fixed in 2025.7.1.
        ("<2025.7.1", "CVE-2025-53109", "high", "symlink-bypass-rce",
         "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/"),
        ("<2025.7.1", "CVE-2025-53110", "high", "prefix-match-bypass",
         "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/"),
    ],

    # ── npm — third-party MCP servers with active advisories ───────────────
    "mcp-remote": [
        (">=0.0.5,<0.1.16", "CVE-2025-6514", "critical", "os-command-injection",
         "https://github.com/advisories/GHSA-6xpm-ggf7-wc3p"),
    ],
    "@cyanheads/git-mcp-server": [
        ("<=2.1.4", "CVE-2025-53107", "high", "command-injection",
         "https://github.com/advisories/GHSA-3q26-f695-pp76"),
    ],

    # ── PyPI — mcp (Python SDK) ────────────────────────────────────────────
    "mcp": [
        ("<1.9.4", "CVE-2025-53366", "high", "unhandled-exception-dos",
         "https://advisories.gitlab.com/pkg/pypi/mcp/CVE-2025-53366/"),
        ("<1.23.0", "CVE-2025-66416", "high", "dns-rebinding-default-off",
         "https://advisories.gitlab.com/pkg/pypi/mcp/CVE-2025-66416/"),
    ],
    "mcp-server-git": [
        # Cluster: CVE-2025-68143 (fixed 2025.9.25), 68144 + 68145 (fixed 2025.12.18).
        # Single highest-fix-version cutoff used here; the advisory_id lists all three.
        ("<2025.12.18", "CVE-2025-68143,CVE-2025-68144,CVE-2025-68145", "high", "rce-chain",
         "https://vulnerablemcp.info/vuln/cve-2025-68145-anthropic-git-mcp-rce-chain.html"),
    ],

    # ── Go — modelcontextprotocol/go-sdk ───────────────────────────────────
    "github.com/modelcontextprotocol/go-sdk": [
        ("<1.3.1", "CVE-2026-27896", "medium", "case-insensitive-json-bypass",
         "https://cvereports.com/reports/CVE-2026-27896"),
    ],

    # ── RubyGems — mcp ─────────────────────────────────────────────────────
    "mcp-ruby": [
        # package name is "mcp" on rubygems; key distinguished here so the npm/pypi
        # lookup doesn't collide in dep-manifest scanners.
        ("<0.9.2", "CVE-2026-33946", "high", "session-hijacking",
         "https://www.sentinelone.com/vulnerability-database/cve-2026-33946/"),
    ],

    # ── Notable downstream consumer CVEs (April 2026 systemic MCP STDIO flaw) ──
    # These are not SDK bugs but MCP-consuming products with published fixes.
    # Listed here so users are warned if they pin these packages alongside MCP.
    "litellm": [
        ("<1.49.0", "CVE-2026-30623", "critical", "mcp-stdio-command-injection",
         "https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026"),
    ],
    # Intentionally omitted (advisory exists but exact numeric fix-version not
    # confirmed from primary source in this pass — re-verify before seeding):
    #   fastmcp                       (CVE-2026-32871)
    #   excel-mcp-server              (CVE-2026-40576)
    #   figma-developer-mcp           (CVE-2025-53967)
    #   @akoskm/create-mcp-server-stdio (CVE-2025-54994)
    #   Rust MCP crate (mcp-rs / rmcp) — no CVE located.
}

# Protocol-design advisory (April 2026) — not a single package-version pair.
# Published by OX Security: "Mother of All AI Supply Chains". Affects MCP
# STDIO config-to-command execution across the ecosystem; Anthropic declined
# protocol change, fixes shipped per downstream consumer. Surface as a general
# warning when any MCP SDK is present, regardless of version.
_PROTOCOL_ADVISORIES = [
    {
        "id": "mcp-stdio-systemic-apr-2026",
        "name": "MCP STDIO config-to-command execution (systemic)",
        "class": "design-flaw",
        "severity": "high",
        "url": "https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/",
        "guidance": (
            "Protocol-level flaw in MCP STDIO transport — malicious MCP server "
            "configs can execute arbitrary commands on client launch. Not fixable "
            "at the SDK level. Require: (a) MCP server allowlist, (b) MCP servers "
            "running in a sandboxed subprocess, (c) no user-writable MCP config "
            "paths. See the OX advisory and related CVE-2026-30615 (Windsurf), "
            "CVE-2026-30623 (LiteLLM) for consumer-side fixes."
        ),
    },
]


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
        findings.extend(self._scan_npm_manifest())
        findings.extend(self._scan_python_manifests())
        findings.extend(self._maybe_emit_protocol_warnings())
        return findings

    def _scan_npm_manifest(self) -> list[Finding]:
        pkg_json = self.ctx.repo_root / "package.json"
        if not pkg_json.is_file():
            return []
        try:
            data = json.loads(pkg_json.read_text())
        except json.JSONDecodeError:
            return []
        deps: dict[str, str] = {}
        deps.update(data.get("dependencies") or {})
        deps.update(data.get("devDependencies") or {})
        return self._match_deps(deps, "package.json")

    def _scan_python_manifests(self) -> list[Finding]:
        findings: list[Finding] = []
        # requirements.txt — tolerant line-parser, not a pip resolver.
        req = self.ctx.repo_root / "requirements.txt"
        if req.is_file():
            deps: dict[str, str] = {}
            for line in req.read_text().splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                name, ver = _split_python_req(line)
                if name:
                    deps[name.lower()] = ver
            findings.extend(self._match_deps(deps, "requirements.txt"))

        # pyproject.toml — look up [project.dependencies] + [project.optional-dependencies]
        py_project = self.ctx.repo_root / "pyproject.toml"
        if py_project.is_file():
            deps = self._parse_pyproject(py_project)
            findings.extend(self._match_deps(deps, "pyproject.toml"))
        return findings

    def _parse_pyproject(self, path: Path) -> dict[str, str]:
        try:
            import tomllib
            data = tomllib.loads(path.read_text())
        except (ImportError, Exception):  # noqa: BLE001 — tomllib on 3.11+, else skip
            return {}
        out: dict[str, str] = {}
        project = data.get("project", {})
        for raw in project.get("dependencies") or []:
            name, ver = _split_python_req(raw)
            if name:
                out[name.lower()] = ver
        for _group, items in (project.get("optional-dependencies") or {}).items():
            for raw in items or []:
                name, ver = _split_python_req(raw)
                if name:
                    out[name.lower()] = ver
        return out

    def _match_deps(self, deps: dict[str, str], source_file: str) -> list[Finding]:
        findings: list[Finding] = []
        for name, declared_version in deps.items():
            entries = _KNOWN_VULNERABLE.get(name)
            if not entries:
                continue
            for spec, advisory_id, severity_s, vuln_class, url in entries:
                if not _version_matches(declared_version, spec):
                    continue
                sev = {
                    "critical": Severity.CRITICAL,
                    "high":     Severity.HIGH,
                    "medium":   Severity.MEDIUM,
                    "low":      Severity.LOW,
                }.get(severity_s, Severity.HIGH)
                findings.append(
                    Finding(
                        finding_id=make_finding_id(
                            Probe.MCP, f"sdk-vuln/{advisory_id}", source_file, name
                        ),
                        probe=Probe.MCP,
                        rule_id=f"mcp/sdk/{advisory_id.split(',')[0].lower()}",
                        severity=sev,
                        original_severity=sev,
                        title=f"MCP dependency '{name}' matches advisory {advisory_id}",
                        description=(
                            f"{name} is declared as `{declared_version}` in {source_file}. "
                            f"Advisory {advisory_id} ({vuln_class}) covers versions {spec}. "
                            f"Review and upgrade to a fixed version. Source: {url}"
                        ),
                        location=Location(file=source_file),
                        evidence=f"{name}: {declared_version}",
                        cve_ids=[c for c in advisory_id.split(",") if c.startswith("CVE-")],
                        taxonomy=[_ATLAS_POISONED_TOOL],
                        probe_metadata={
                            "advisory": advisory_id,
                            "class": vuln_class,
                            "constraint": spec,
                            "advisory_url": url,
                        },
                    )
                )
        return findings

    def _maybe_emit_protocol_warnings(self) -> list[Finding]:
        """If any MCP SDK is present in the repo, emit the protocol-level advisory."""
        has_mcp = self._has_any_mcp_dep()
        if not has_mcp:
            return []
        findings: list[Finding] = []
        for adv in _PROTOCOL_ADVISORIES:
            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        Probe.MCP, f"protocol-advisory/{adv['id']}", "<repo>", adv["id"]
                    ),
                    probe=Probe.MCP,
                    rule_id=f"mcp/protocol/{adv['id']}",
                    severity=Severity.HIGH,
                    original_severity=Severity.HIGH,
                    title=f"MCP protocol advisory: {adv['name']}",
                    description=adv["guidance"] + f" See: {adv['url']}",
                    location=Location(file="<repo>"),
                    taxonomy=[_ATLAS_POISONED_TOOL],
                    probe_metadata={
                        "advisory_id": adv["id"],
                        "advisory_url": adv["url"],
                        "class": adv["class"],
                        "note": "protocol-level; not fixable by SDK version bump",
                    },
                )
            )
        return findings

    def _has_any_mcp_dep(self) -> bool:
        """Cheap detector: is any known-MCP package name declared?"""
        names = set(_KNOWN_VULNERABLE.keys())
        # Check package.json
        pkg = self.ctx.repo_root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text())
                for section in ("dependencies", "devDependencies"):
                    if any(n in names for n in (data.get(section) or {})):
                        return True
            except json.JSONDecodeError:
                pass
        # Check requirements.txt and pyproject.toml
        for path in (self.ctx.repo_root / "requirements.txt", self.ctx.repo_root / "pyproject.toml"):
            if path.is_file():
                text = path.read_text(errors="replace").lower()
                if any(n in text for n in names if "/" not in n):  # skip Go/npm-scoped keys
                    return True
        return False

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


# ── Version matching (naive but documented) ────────────────────────────────
#
# We don't pull in the `packaging` library here to keep the probe pure-stdlib
# in the Docker image. This covers the specifier shapes we actually seed in
# _KNOWN_VULNERABLE: "<X", "<=X", ">=X,<Y". It is deliberately strict — any
# spec or version string it can't parse returns False (miss), never True
# (false-positive). Re-verify when the advisory list grows more expressive.

_VERSION_PART_RE = re.compile(r"\d+")
_NPM_PREFIX_RE = re.compile(r"^[~^<>=!\s]+")


def _split_python_req(line: str) -> tuple[str, str]:
    """Parse a `requirements.txt`-style line → (name, version_string).

    Accepts forms like:
      foo==1.2.3
      foo>=1.0,<2.0
      foo~=1.2
      foo (==1.2.3)             # pyproject PEP 508 style
      foo
    Returns ("", "") for lines we can't parse (URLs, -e editable, etc.).
    """
    line = line.strip()
    if not line or line.startswith(("-", "git+", "http")):
        return "", ""
    # Drop environment markers + extras.
    line = line.split(";", 1)[0].strip()
    line = re.sub(r"\[[^]]*\]", "", line)
    m = re.match(r"^\(?\s*([A-Za-z0-9_.\-@/]+)\s*\)?\s*(.*)$", line)
    if not m:
        return "", ""
    name = m.group(1).strip()
    rest = m.group(2).strip()
    return name, rest or "*"


def _parse_version(v: str) -> tuple[int, ...] | None:
    """Extract a comparable numeric tuple from a version string. Returns None
    if the string has no digits (e.g. `*`, `latest`, git-SHA).
    """
    parts = _VERSION_PART_RE.findall(v)
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])  # cap at 4 components (major.minor.patch.build)


def _clean_declared(v: str) -> str:
    """Strip npm/pip prefix decorations so _parse_version can see the version."""
    v = v.strip()
    v = _NPM_PREFIX_RE.sub("", v).strip()
    # Take the first token so "==1.2.3,<2" -> "1.2.3" (the lower-bound).
    # This is a simplification; see comment at top of section.
    if "," in v:
        v = v.split(",", 1)[0]
    return v


def _version_matches(declared_version: str, spec: str) -> bool:
    """Return True if `declared_version` satisfies the vulnerable `spec`.

    Supported specs:
      "<X"       vulnerable if declared < X
      "<=X"      vulnerable if declared <= X
      ">=X,<Y"   vulnerable if X <= declared < Y
    All others → False (conservative; miss, never false-positive).
    """
    declared = _parse_version(_clean_declared(declared_version))
    if declared is None:
        return False
    spec = spec.replace(" ", "")

    # Range form ">=X,<Y"
    range_m = re.match(r"^>=(?P<lo>[\w.\-+]+),<(?P<hi>[\w.\-+]+)$", spec)
    if range_m:
        lo = _parse_version(range_m.group("lo"))
        hi = _parse_version(range_m.group("hi"))
        if lo is None or hi is None:
            return False
        return lo <= declared < hi

    # Single-bound forms
    for op in ("<=", "<"):
        if spec.startswith(op):
            bound = _parse_version(spec[len(op):])
            if bound is None:
                return False
            return declared <= bound if op == "<=" else declared < bound
    return False
