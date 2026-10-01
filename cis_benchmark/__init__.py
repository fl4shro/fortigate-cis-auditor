"""
FortiGate CIS Benchmark Compliance Engine
==========================================
Enterprise-grade CIS FortiGate Benchmark v1.4.0 auditing framework.

Modules:
    - config_parser: Parse FortiGate configuration backup files
    - rules: CIS Benchmark rule engine (Level 1 & Level 2)
    - scoring: Compliance scoring and risk assessment
    - reporting: Multi-format report generation (HTML, JSON, PDF)
    - remediation: CLI remediation command generation
"""

__version__ = "2.0.0"
__author__ = "Priyam Patel"
__benchmark_version__ = "CIS FortiGate Benchmark v1.4.0"

from cis_benchmark.config_parser import FortiGateConfigParser
from cis_benchmark.scoring import ComplianceScorer
from cis_benchmark.remediation import RemediationEngine

__all__ = [
    "FortiGateConfigParser",
    "ComplianceScorer",
    "RemediationEngine",
    "__version__",
    "__benchmark_version__",
]
