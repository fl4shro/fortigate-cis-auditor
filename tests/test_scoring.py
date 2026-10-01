"""
Unit Tests – Scoring System
==============================
Tests for the compliance scoring calculator.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cis_benchmark.scoring import ComplianceScorer, ComplianceReport
from cis_benchmark.rules.base import RuleResult, CISLevel, RuleSeverity


@pytest.fixture
def scorer():
    return ComplianceScorer()


def make_result(rule_id="1.1", passed=True, level=CISLevel.LEVEL_1,
                severity=RuleSeverity.MEDIUM, category="Test"):
    return RuleResult(
        rule_id=rule_id,
        title=f"Test Rule {rule_id}",
        level=level,
        severity=severity,
        passed=passed,
        description="Test",
        expected_value="Expected",
        actual_value="Actual",
        remediation="Fix it",
        category=category,
    )


class TestComplianceScorer:
    """Test compliance scoring calculations."""

    def test_empty_results(self, scorer):
        report = scorer.calculate([])
        assert report.total_rules == 0
        assert report.overall_percentage == 0

    def test_all_pass(self, scorer):
        results = [make_result(f"1.{i}", passed=True) for i in range(10)]
        report = scorer.calculate(results)
        assert report.overall_percentage == 100.0
        assert report.risk_rating == "Low"
        assert report.failed_rules == 0

    def test_all_fail(self, scorer):
        results = [make_result(f"1.{i}", passed=False) for i in range(10)]
        report = scorer.calculate(results)
        assert report.overall_percentage == 0.0
        assert report.risk_rating == "Critical"
        assert report.passed_rules == 0

    def test_fifty_percent(self, scorer):
        results = [make_result(f"1.{i}", passed=i < 5) for i in range(10)]
        report = scorer.calculate(results)
        assert report.overall_percentage == 50.0

    def test_level_breakdown(self, scorer):
        results = [
            make_result("1.1", passed=True, level=CISLevel.LEVEL_1),
            make_result("1.2", passed=False, level=CISLevel.LEVEL_1),
            make_result("2.1", passed=True, level=CISLevel.LEVEL_2),
        ]
        report = scorer.calculate(results)
        assert report.level1_total == 2
        assert report.level1_passed == 1
        assert report.level1_percentage == 50.0
        assert report.level2_total == 1
        assert report.level2_passed == 1
        assert report.level2_percentage == 100.0

    def test_severity_breakdown(self, scorer):
        results = [
            make_result("1.1", passed=False, severity=RuleSeverity.CRITICAL),
            make_result("1.2", passed=True, severity=RuleSeverity.HIGH),
            make_result("1.3", passed=False, severity=RuleSeverity.MEDIUM),
            make_result("1.4", passed=True, severity=RuleSeverity.LOW),
        ]
        report = scorer.calculate(results)
        assert report.critical_total == 1
        assert report.critical_passed == 0
        assert len(report.critical_failures) == 1
        assert report.high_total == 1
        assert report.high_passed == 1

    def test_category_breakdown(self, scorer):
        results = [
            make_result("1.1", passed=True, category="Network"),
            make_result("1.2", passed=False, category="Network"),
            make_result("2.1", passed=True, category="System"),
        ]
        report = scorer.calculate(results)
        assert "Network" in report.category_scores
        assert report.category_scores["Network"].total == 2
        assert report.category_scores["Network"].passed == 1
        assert report.category_scores["Network"].percentage == 50.0

    def test_weighted_score(self, scorer):
        results = [
            make_result("1.1", passed=True, severity=RuleSeverity.CRITICAL),  # weight 10
            make_result("1.2", passed=False, severity=RuleSeverity.LOW),      # weight 1
        ]
        report = scorer.calculate(results)
        # 10/(10+1) = 90.9%
        assert report.weighted_score > 80

    def test_risk_ratings(self, scorer):
        # Critical risk: < 40%
        r1 = scorer.calculate([make_result("1.1", passed=False)])
        assert r1.risk_rating == "Critical"

        # Low risk: >= 80%
        r2 = scorer.calculate([make_result("1.1", passed=True)])
        assert r2.risk_rating == "Low"

    def test_report_to_dict(self, scorer):
        results = [make_result("1.1", passed=True)]
        report = scorer.calculate(results)
        d = report.to_dict()
        assert "summary" in d
        assert "level_breakdown" in d
        assert "severity_breakdown" in d
        assert "results" in d

    def test_failed_results_list(self, scorer):
        results = [
            make_result("1.1", passed=True),
            make_result("1.2", passed=False),
        ]
        report = scorer.calculate(results)
        assert len(report.failed_results) == 1
        assert report.failed_results[0].rule_id == "1.2"
