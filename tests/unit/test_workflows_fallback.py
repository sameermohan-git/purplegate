"""Unit tests for the workflow probe's pure-Python fallback."""
from src.models import Probe, Severity
from src.probes.workflows import WorkflowsProbe


class TestWorkflowsFallback:

    def test_prt_untrusted_input_flagged_critical(self, make_context):
        ctx = make_context("vuln_workflow")
        findings = WorkflowsProbe(ctx)._fallback_yaml_check()
        crits = [
            f for f in findings
            if f.rule_id == "workflows/fallback/pull-request-target-untrusted-input"
        ]
        assert len(crits) >= 1
        assert all(c.severity == Severity.CRITICAL for c in crits)

    def test_checkout_persists_credentials_flagged_high(self, make_context):
        ctx = make_context("vuln_workflow")
        findings = WorkflowsProbe(ctx)._fallback_yaml_check()
        persists = [
            f for f in findings
            if f.rule_id == "workflows/fallback/checkout-persists-credentials"
        ]
        assert len(persists) == 1
        assert persists[0].severity == Severity.HIGH

    def test_clean_app_zero_findings(self, make_context):
        ctx = make_context("clean_app")
        findings = WorkflowsProbe(ctx)._fallback_yaml_check()
        assert findings == []

    def test_findings_tagged_workflows_probe(self, make_context):
        ctx = make_context("vuln_workflow")
        findings = WorkflowsProbe(ctx)._fallback_yaml_check()
        assert all(f.probe == Probe.WORKFLOWS for f in findings)
