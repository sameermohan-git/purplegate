"""Unit tests for the sast probe's FastAPI auth-gap fallback.

We only test the fallback path (no Semgrep binary needed).
"""
from src.models import Probe, Severity
from src.probes.sast import SastProbe


class TestFastApiAuthCheck:

    def test_unauth_route_flagged_high(self, make_context):
        ctx = make_context("vuln_fastapi")
        findings = [
            f for f in SastProbe(ctx)._fastapi_auth_check()
            if f.rule_id == "sast/fastapi/route-without-auth-dep"
        ]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].location.file.endswith("unauth_route.py")
        assert "/public/ping" in findings[0].title

    def test_authed_route_not_flagged(self, make_context):
        ctx = make_context("vuln_fastapi")
        findings = [
            f for f in SastProbe(ctx)._fastapi_auth_check()
            if "/authed/ping" in f.title
        ]
        assert findings == []

    def test_clean_app_zero_findings(self, make_context):
        ctx = make_context("clean_app")
        findings = SastProbe(ctx)._fastapi_auth_check()
        assert findings == []

    def test_findings_tagged_sast_probe(self, make_context):
        ctx = make_context("vuln_fastapi")
        findings = SastProbe(ctx)._fastapi_auth_check()
        assert all(f.probe == Probe.SAST for f in findings)
