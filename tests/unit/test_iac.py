"""Unit tests for the iac probe against the vuln_supabase_sql + clean_app fixtures."""
from src.models import Probe, Severity
from src.probes.iac import IacProbe


class TestIacSupabaseRls:

    def test_missing_rls_flagged_critical(self, make_context):
        ctx = make_context("vuln_supabase_sql")
        findings = IacProbe(ctx).run()
        missing = [f for f in findings if f.rule_id == "iac/supabase/missing-rls-on-public-table"]
        assert len(missing) == 1
        assert missing[0].severity == Severity.CRITICAL
        assert "transactions" in missing[0].title.lower()

    def test_rls_without_policy_flagged_high(self, make_context):
        ctx = make_context("vuln_supabase_sql")
        findings = IacProbe(ctx).run()
        without_policy = [f for f in findings if f.rule_id == "iac/supabase/rls-enabled-without-policy"]
        assert len(without_policy) == 1
        assert without_policy[0].severity == Severity.HIGH
        assert "profiles" in without_policy[0].title.lower()

    def test_fully_protected_table_not_flagged(self, make_context):
        """receipts table in migration 003 has RLS + policies → 0 findings on it."""
        ctx = make_context("vuln_supabase_sql")
        findings = IacProbe(ctx).run()
        receipts_flags = [f for f in findings if "receipts" in f.title.lower()]
        assert receipts_flags == []

    def test_clean_app_produces_zero(self, make_context):
        ctx = make_context("clean_app")
        findings = IacProbe(ctx).run()
        assert findings == []

    def test_all_findings_are_iac_probe(self, make_context):
        ctx = make_context("vuln_supabase_sql")
        findings = IacProbe(ctx).run()
        assert all(f.probe == Probe.IAC for f in findings)
