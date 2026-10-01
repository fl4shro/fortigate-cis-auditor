"""
Unit Tests – CIS Rules
========================
Tests for Level 1 and Level 2 CIS rules against the test config.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cis_benchmark.config_parser import FortiGateConfigParser
from cis_benchmark.rules import get_all_rules, get_level1_rules, get_level2_rules
from cis_benchmark.rules.base import CISLevel, RuleSeverity, RuleResult


@pytest.fixture
def config():
    parser = FortiGateConfigParser()
    return parser.parse_file(str(Path(__file__).parent / "test_sample_config.conf"))


class TestRuleStructure:
    """Test rule metadata and structure."""

    def test_all_rules_have_ids(self):
        for rule in get_all_rules():
            assert rule.rule_id, f"Rule missing ID: {rule.title}"

    def test_all_rules_have_titles(self):
        for rule in get_all_rules():
            assert rule.title, f"Rule {rule.rule_id} missing title"

    def test_all_rules_have_severity(self):
        for rule in get_all_rules():
            assert isinstance(rule.severity, RuleSeverity)

    def test_all_rules_have_level(self):
        for rule in get_all_rules():
            assert isinstance(rule.level, CISLevel)

    def test_level1_rules_count(self):
        assert len(get_level1_rules()) >= 30

    def test_level2_rules_count(self):
        assert len(get_level2_rules()) >= 15

    def test_unique_rule_ids(self):
        ids = [r.rule_id for r in get_all_rules()]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"


class TestLevel1Rules:
    """Test Level 1 rules against the test config."""

    def test_dns_configured(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "1.1")
        result = rule.evaluate(config)
        assert result.passed, f"DNS should pass: {result.actual_value}"

    def test_intra_zone_deny(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "1.2")
        result = rule.evaluate(config)
        assert result.passed

    def test_pre_login_banner(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.1")
        result = rule.evaluate(config)
        assert result.passed

    def test_post_login_banner(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.2")
        result = rule.evaluate(config)
        assert result.passed

    def test_ntp(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.4")
        result = rule.evaluate(config)
        assert result.passed

    def test_hostname(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.5")
        result = rule.evaluate(config)
        assert result.passed

    def test_usb_disabled(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.7")
        result = rule.evaluate(config)
        assert result.passed

    def test_strong_crypto(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.9")
        result = rule.evaluate(config)
        assert result.passed

    def test_tls_versions(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.1.10")
        result = rule.evaluate(config)
        assert result.passed

    def test_password_policy(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.2.1")
        result = rule.evaluate(config)
        assert result.passed

    def test_admin_lockout(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.2.2")
        result = rule.evaluate(config)
        assert result.passed

    def test_admin_timeout(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.4.4")
        result = rule.evaluate(config)
        assert result.passed

    def test_encrypted_access(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "2.4.5")
        result = rule.evaluate(config)
        assert result.passed

    def test_event_logging(self, config):
        rule = next(r for r in get_level1_rules() if r.rule_id == "7.1.1")
        result = rule.evaluate(config)
        assert result.passed

    def test_all_rules_evaluatable(self, config):
        """Every L1 rule should evaluate without error."""
        for rule in get_level1_rules():
            result = rule.evaluate(config)
            assert isinstance(result, RuleResult), f"Rule {rule.rule_id} returned non-RuleResult"


class TestLevel2Rules:
    """Test Level 2 rules against the test config."""

    def test_local_in_policies(self, config):
        rule = next(r for r in get_level2_rules() if r.rule_id == "2.4.6")
        result = rule.evaluate(config)
        assert result.passed

    def test_default_admin_ports_changed(self, config):
        rule = next(r for r in get_level2_rules() if r.rule_id == "2.4.7")
        result = rule.evaluate(config)
        assert result.passed

    def test_ssl_vpn_tls(self, config):
        rule = next(r for r in get_level2_rules() if r.rule_id == "6.1.2")
        result = rule.evaluate(config)
        assert result.passed

    def test_ipsec_encryption(self, config):
        rule = next(r for r in get_level2_rules() if r.rule_id == "6.2.1")
        result = rule.evaluate(config)
        assert result.passed

    def test_log_encryption(self, config):
        rule = next(r for r in get_level2_rules() if r.rule_id == "7.2.1")
        result = rule.evaluate(config)
        assert result.passed

    def test_all_rules_evaluatable(self, config):
        """Every L2 rule should evaluate without error."""
        for rule in get_level2_rules():
            result = rule.evaluate(config)
            assert isinstance(result, RuleResult), f"Rule {rule.rule_id} returned non-RuleResult"


class TestRuleResults:
    """Test RuleResult serialization."""

    def test_result_to_dict(self, config):
        rule = get_level1_rules()[0]
        result = rule.evaluate(config)
        d = result.to_dict()
        assert "rule_id" in d
        assert "status" in d
        assert "severity" in d
        assert d["status"] in ["PASS", "FAIL"]

    def test_result_status_strings(self, config):
        for rule in get_all_rules():
            result = rule.evaluate(config)
            assert result.status in ["PASS", "FAIL"]
