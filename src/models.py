"""Shared Pydantic models — the internal findings schema.

Stays aligned with config/schemas/findings.schema.json.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW

    @property
    def weight(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class Probe(str, Enum):
    SECRETS = "secrets"
    SAST = "sast"
    DEPS = "deps"
    IAC = "iac"
    WORKFLOWS = "workflows"
    PROMPT_INJECTION = "prompt_injection"
    MCP = "mcp"
    SBOM = "sbom"
    HEADERS = "headers"


class TaxonomyFramework(str, Enum):
    OWASP_LLM_2025 = "OWASP LLM Top 10 v2025"
    OWASP_AGENTIC_2026 = "OWASP Agentic 2026"
    MITRE_ATLAS = "MITRE ATLAS v5.4.0"
    OWASP_TOP_10_2021 = "OWASP Top 10 2021"


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None


class TaxonomyRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: TaxonomyFramework
    id: str
    url: str | None = None


class DefenseRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    status: str = Field(pattern="^(present|absent|unknown)$")
    evidence: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    probe: Probe
    rule_id: str
    severity: Severity
    original_severity: Severity | None = None
    title: str = Field(min_length=5, max_length=160)
    description: str = ""
    location: Location
    evidence: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    taxonomy: list[TaxonomyRef] = Field(default_factory=list)
    defenses: list[DefenseRef] = Field(default_factory=list)
    suggested_hardening: str | None = None
    allowlist_entry: dict[str, Any] | None = None
    probe_metadata: dict[str, Any] = Field(default_factory=dict)


class Stats(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = 0
    by_severity: dict[str, int] = Field(
        default_factory=lambda: {s.value: 0 for s in Severity}
    )
    by_probe: dict[str, int] = Field(default_factory=dict)
    runtime_ms: int = 0
    llm_cost_usd: float = 0.0


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action_version: str | None = None
    image_digest: str | None = None
    config_hash: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    stats: Stats = Field(default_factory=Stats)

    def refresh_stats(self) -> None:
        self.stats.total = len(self.findings)
        self.stats.by_severity = {s.value: 0 for s in Severity}
        self.stats.by_probe = {}
        for f in self.findings:
            self.stats.by_severity[f.severity.value] += 1
            self.stats.by_probe[f.probe.value] = self.stats.by_probe.get(f.probe.value, 0) + 1


def make_finding_id(
    probe: Probe | str,
    rule_id: str,
    file_path: str,
    snippet: str = "",
) -> str:
    """Stable hash so allowlist entries remain matched across runs.

    Whitespace in snippet is normalized. We use the first 16 hex chars of
    SHA-256 — not for cryptographic purposes, just a short stable identifier.
    """
    probe_v = probe.value if isinstance(probe, Probe) else probe
    normalized = " ".join(snippet.split())
    raw = f"{probe_v}\x00{rule_id}\x00{file_path}\x00{normalized}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    prefix = probe_v.upper().replace("_", "-")
    return f"{prefix}-{digest}"
