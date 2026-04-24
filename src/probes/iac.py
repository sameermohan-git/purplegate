"""IaC probe — Supabase RLS custom check + Checkov wrapper.

The RLS check is pure-Python static analysis over `supabase.migrations_glob`.
Checkov is optional (heavy dep) and wrapped only when the binary is present.
"""
from __future__ import annotations

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

_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([\w\"`]+)",
    re.IGNORECASE,
)
_RLS_ENABLE_RE = re.compile(
    r"ALTER\s+TABLE\s+(?:public\.)?([\w\"`]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)
_CREATE_POLICY_RE = re.compile(
    r"CREATE\s+POLICY\s+\S+\s+ON\s+(?:public\.)?([\w\"`]+)",
    re.IGNORECASE,
)


_OWASP_A01 = TaxonomyRef(
    framework=TaxonomyFramework.OWASP_TOP_10_2021,
    id="A01:2021",
    url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
)


class IacProbe(BaseProbe):
    name = Probe.IAC

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.ctx.config.get("supabase", {}).get("require_rls", True):
            findings.extend(self._check_supabase_rls())
        findings.extend(self._run_checkov())
        return findings

    # ── Supabase RLS custom check ───────────────────────────────────────

    def _check_supabase_rls(self) -> list[Finding]:
        sb = self.ctx.config.get("supabase", {})
        glob_pat = sb.get("migrations_glob", "supabase/migrations/*.sql")
        tables_created: dict[str, Path] = {}
        tables_rls_enabled: set[str] = set()
        tables_with_policy: set[str] = set()

        for path in sorted(self.ctx.repo_root.glob(glob_pat)):
            try:
                sql = path.read_text(errors="replace")
            except OSError:
                continue
            sql = _strip_sql_comments(sql)

            for m in _CREATE_TABLE_RE.finditer(sql):
                name = _normalize_table_name(m.group(1))
                tables_created.setdefault(name, path)
            for m in _RLS_ENABLE_RE.finditer(sql):
                tables_rls_enabled.add(_normalize_table_name(m.group(1)))
            for m in _CREATE_POLICY_RE.finditer(sql):
                tables_with_policy.add(_normalize_table_name(m.group(1)))

        findings: list[Finding] = []
        for table, path in tables_created.items():
            rel = path.relative_to(self.ctx.repo_root).as_posix()
            if table not in tables_rls_enabled:
                findings.append(
                    Finding(
                        finding_id=make_finding_id(
                            Probe.IAC, "supabase/missing-rls", rel, table
                        ),
                        probe=Probe.IAC,
                        rule_id="iac/supabase/missing-rls-on-public-table",
                        severity=Severity.CRITICAL,
                        original_severity=Severity.CRITICAL,
                        title=f"Public table '{table}' has no RLS enabled",
                        description=(
                            f"Table '{table}' is created in migrations without a corresponding "
                            "`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`. Without RLS, any "
                            "authenticated Supabase client can read/write it via PostgREST."
                        ),
                        location=Location(file=rel),
                        evidence=f"CREATE TABLE ... {table}",
                        taxonomy=[_OWASP_A01],
                        probe_metadata={"table": table},
                    )
                )
            elif table not in tables_with_policy:
                findings.append(
                    Finding(
                        finding_id=make_finding_id(
                            Probe.IAC, "supabase/rls-without-policy", rel, table
                        ),
                        probe=Probe.IAC,
                        rule_id="iac/supabase/rls-enabled-without-policy",
                        severity=Severity.HIGH,
                        original_severity=Severity.HIGH,
                        title=f"Table '{table}' has RLS enabled but no policy",
                        description=(
                            f"Table '{table}' has RLS enabled but no CREATE POLICY statement. "
                            "RLS-enabled tables without policies are inaccessible to clients — "
                            "likely unintended; add a SELECT/INSERT policy or remove RLS."
                        ),
                        location=Location(file=rel),
                        evidence=f"ENABLE ROW LEVEL SECURITY on {table} (no policy)",
                        taxonomy=[_OWASP_A01],
                        probe_metadata={"table": table},
                    )
                )
        return findings

    # ── Checkov (optional) ──────────────────────────────────────────────

    def _run_checkov(self) -> list[Finding]:
        binary = self.which_or_skip("checkov")
        if not binary:
            return []
        # Checkov support is stubbed at scaffold time — parsing its JSON
        # report belongs in a follow-up PR that wires the full ruleset.
        log.info("Checkov present but parser not wired in scaffold; returning no findings")
        return []

    def tool_versions(self) -> dict[str, str]:
        out = {}
        path = self.which_or_skip("checkov")
        if path:
            r = self.run_tool([path, "--version"], timeout=10)
            out["checkov"] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "unknown"
        return out


def _normalize_table_name(raw: str) -> str:
    return raw.strip().strip('"').strip("`").lower()


_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_sql_comments(sql: str) -> str:
    """Remove -- line and /* block */ comments so the CREATE-TABLE regex
    doesn't match phrases like `CREATE TABLE in the public schema` in a comment.
    """
    sql = _BLOCK_COMMENT_RE.sub(" ", sql)
    sql = _LINE_COMMENT_RE.sub("", sql)
    return sql
