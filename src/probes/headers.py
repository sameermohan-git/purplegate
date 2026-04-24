"""Headers probe — fetches target-url + sample paths, checks security headers."""
from __future__ import annotations

import logging
from typing import Iterable

import httpx

from src.models import Finding, Location, Probe, Severity, make_finding_id
from src.probes.base import BaseProbe

log = logging.getLogger(__name__)

_REQUIRED = {
    "content-security-policy": (Severity.MEDIUM, "Content-Security-Policy"),
    "strict-transport-security": (Severity.MEDIUM, "Strict-Transport-Security (HSTS)"),
    "x-frame-options": (Severity.MEDIUM, "X-Frame-Options"),
    "x-content-type-options": (Severity.LOW, "X-Content-Type-Options"),
    "referrer-policy": (Severity.LOW, "Referrer-Policy"),
}


class HeadersProbe(BaseProbe):
    name = Probe.HEADERS

    def run(self) -> list[Finding]:
        target = self.ctx.target_url
        if not target:
            return []

        paths = self.ctx.config.get("probes", {}).get("headers", {}).get("sample_paths") or ["/"]
        findings: list[Finding] = []
        for path in paths:
            url = target.rstrip("/") + path
            findings.extend(self._check_url(url))
        return findings

    def _check_url(self, url: str) -> list[Finding]:
        try:
            with httpx.Client(timeout=10, follow_redirects=True) as client:
                resp = client.get(url)
        except httpx.HTTPError as exc:
            log.warning("headers probe: %s -> %s", url, exc)
            return []

        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        findings: list[Finding] = []
        for key, (severity, display) in _REQUIRED.items():
            if key in hdrs and hdrs[key].strip():
                continue
            findings.append(
                Finding(
                    finding_id=make_finding_id(Probe.HEADERS, f"missing/{key}", url, ""),
                    probe=Probe.HEADERS,
                    rule_id=f"headers/missing/{key}",
                    severity=severity,
                    original_severity=severity,
                    title=f"Missing {display} on {url}",
                    description=(
                        f"Response from {url} does not include a {display} header. "
                        "This weakens the browser-side defense-in-depth for the app."
                    ),
                    location=Location(file=url),
                    probe_metadata={"url": url, "header": key, "status_code": resp.status_code},
                )
            )
        return findings
