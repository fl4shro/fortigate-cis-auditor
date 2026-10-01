"""
Compliance Scoring System
==========================
Calculates compliance scores with breakdowns by level, severity, and category.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from collections import defaultdict
from cis_benchmark.rules.base import RuleResult, CISLevel, RuleSeverity


@dataclass
class CategoryScore:
    """Score for a specific category."""
    category: str
    total: int = 0
    passed: int = 0
    failed: int = 0

    @property
    def percentage(self) -> float:
        return round((self.passed / self.total) * 100, 1) if self.total > 0 else 0.0


@dataclass
class ComplianceReport:
    """Complete compliance scoring report."""
    # Overall
    total_rules: int = 0
    passed_rules: int = 0
    failed_rules: int = 0
    overall_percentage: float = 0.0
    risk_rating: str = "Unknown"
    risk_color: str = "#6c757d"

    # By Level
    level1_total: int = 0
    level1_passed: int = 0
    level1_percentage: float = 0.0
    level2_total: int = 0
    level2_passed: int = 0
    level2_percentage: float = 0.0

    # By Severity
    critical_total: int = 0
    critical_passed: int = 0
    critical_percentage: float = 0.0
    high_total: int = 0
    high_passed: int = 0
    high_percentage: float = 0.0
    medium_total: int = 0
    medium_passed: int = 0
    medium_percentage: float = 0.0
    low_total: int = 0
    low_passed: int = 0
    low_percentage: float = 0.0

    # By Category
    category_scores: Dict[str, CategoryScore] = field(default_factory=dict)

    # Weighted score
    weighted_score: float = 0.0

    # Results
    results: List[RuleResult] = field(default_factory=list)
    failed_results: List[RuleResult] = field(default_factory=list)
    passed_results: List[RuleResult] = field(default_factory=list)

    # Severity breakdown for failed rules
    critical_failures: List[RuleResult] = field(default_factory=list)
    high_failures: List[RuleResult] = field(default_factory=list)
    medium_failures: List[RuleResult] = field(default_factory=list)
    low_failures: List[RuleResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_rules": self.total_rules,
                "passed_rules": self.passed_rules,
                "failed_rules": self.failed_rules,
                "overall_percentage": self.overall_percentage,
                "weighted_score": self.weighted_score,
                "risk_rating": self.risk_rating,
            },
            "level_breakdown": {
                "level1": {
                    "total": self.level1_total,
                    "passed": self.level1_passed,
                    "percentage": self.level1_percentage,
                },
                "level2": {
                    "total": self.level2_total,
                    "passed": self.level2_passed,
                    "percentage": self.level2_percentage,
                },
            },
            "severity_breakdown": {
                "critical": {"total": self.critical_total, "passed": self.critical_passed, "percentage": self.critical_percentage},
                "high": {"total": self.high_total, "passed": self.high_passed, "percentage": self.high_percentage},
                "medium": {"total": self.medium_total, "passed": self.medium_passed, "percentage": self.medium_percentage},
                "low": {"total": self.low_total, "passed": self.low_passed, "percentage": self.low_percentage},
            },
            "category_breakdown": {
                name: {"total": cs.total, "passed": cs.passed, "percentage": cs.percentage}
                for name, cs in self.category_scores.items()
            },
            "results": [r.to_dict() for r in self.results],
        }


class ComplianceScorer:
    """
    Calculates comprehensive compliance scores from rule results.
    
    Usage:
        scorer = ComplianceScorer()
        report = scorer.calculate(results)
        print(f"Score: {report.overall_percentage}%")
        print(f"Risk: {report.risk_rating}")
    """

    RISK_RATINGS = [
        (0, 40, "Critical", "#dc3545"),
        (40, 60, "High", "#fd7e14"),
        (60, 80, "Medium", "#ffc107"),
        (80, 101, "Low", "#28a745"),
    ]

    def calculate(self, results: List[RuleResult]) -> ComplianceReport:
        """Calculate compliance report from rule results."""
        report = ComplianceReport()
        report.results = results

        if not results:
            return report

        # Overall counts
        report.total_rules = len(results)
        report.passed_rules = sum(1 for r in results if r.passed)
        report.failed_rules = report.total_rules - report.passed_rules
        report.overall_percentage = round(
            (report.passed_rules / report.total_rules) * 100, 1
        )

        # Separate passed/failed
        report.passed_results = [r for r in results if r.passed]
        report.failed_results = [r for r in results if not r.passed]

        # Level breakdown
        l1 = [r for r in results if r.level == CISLevel.LEVEL_1]
        l2 = [r for r in results if r.level == CISLevel.LEVEL_2]
        report.level1_total = len(l1)
        report.level1_passed = sum(1 for r in l1 if r.passed)
        report.level1_percentage = round(
            (report.level1_passed / report.level1_total) * 100, 1
        ) if report.level1_total > 0 else 0.0
        report.level2_total = len(l2)
        report.level2_passed = sum(1 for r in l2 if r.passed)
        report.level2_percentage = round(
            (report.level2_passed / report.level2_total) * 100, 1
        ) if report.level2_total > 0 else 0.0

        # Severity breakdown
        self._calculate_severity(results, report)

        # Category breakdown
        self._calculate_categories(results, report)

        # Weighted score (severity-weighted)
        report.weighted_score = self._calculate_weighted_score(results)

        # Risk rating
        for low, high, rating, color in self.RISK_RATINGS:
            if low <= report.weighted_score < high:
                report.risk_rating = rating
                report.risk_color = color
                break

        return report

    def _calculate_severity(self, results: List[RuleResult], report: ComplianceReport):
        """Calculate severity-level breakdowns."""
        severity_map = {
            RuleSeverity.CRITICAL: ("critical", []),
            RuleSeverity.HIGH: ("high", []),
            RuleSeverity.MEDIUM: ("medium", []),
            RuleSeverity.LOW: ("low", []),
        }

        for result in results:
            prefix, failures = severity_map.get(result.severity, ("low", []))
            total_attr = f"{prefix}_total"
            passed_attr = f"{prefix}_passed"
            setattr(report, total_attr, getattr(report, total_attr) + 1)
            if result.passed:
                setattr(report, passed_attr, getattr(report, passed_attr) + 1)
            else:
                failures.append(result)

        # Set failure lists
        report.critical_failures = severity_map[RuleSeverity.CRITICAL][1]
        report.high_failures = severity_map[RuleSeverity.HIGH][1]
        report.medium_failures = severity_map[RuleSeverity.MEDIUM][1]
        report.low_failures = severity_map[RuleSeverity.LOW][1]

        # Calculate percentages
        for prefix in ["critical", "high", "medium", "low"]:
            total = getattr(report, f"{prefix}_total")
            passed = getattr(report, f"{prefix}_passed")
            pct = round((passed / total) * 100, 1) if total > 0 else 0.0
            setattr(report, f"{prefix}_percentage", pct)

    def _calculate_categories(self, results: List[RuleResult], report: ComplianceReport):
        """Calculate category-level breakdowns."""
        categories: Dict[str, CategoryScore] = {}

        for result in results:
            cat = result.category or "Uncategorized"
            if cat not in categories:
                categories[cat] = CategoryScore(category=cat)
            categories[cat].total += 1
            if result.passed:
                categories[cat].passed += 1
            else:
                categories[cat].failed += 1

        report.category_scores = dict(sorted(categories.items()))

    def _calculate_weighted_score(self, results: List[RuleResult]) -> float:
        """Calculate severity-weighted compliance score."""
        total_weight = 0
        earned_weight = 0

        for result in results:
            weight = result.severity.weight
            total_weight += weight
            if result.passed:
                earned_weight += weight

        if total_weight == 0:
            return 0.0
        return round((earned_weight / total_weight) * 100, 1)
