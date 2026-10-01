"""
JSON Report Generator
======================
Generates structured JSON reports for SIEM/GRC integration.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class JSONReportGenerator:
    """Generate JSON compliance reports."""

    def generate(self, report, config_file: str = "", output_path: str = "") -> str:
        """Generate JSON report from ComplianceReport."""
        data = {
            "metadata": {
                "tool": "FortiGate CIS Benchmark Checker",
                "version": "2.0.0",
                "benchmark": "CIS FortiGate Benchmark v1.4.0",
                "generated_at": datetime.now().isoformat(),
                "config_file": config_file,
            },
            "compliance": report.to_dict(),
        }

        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            Path(output_path).write_text(json_str, encoding="utf-8")
            logger.info(f"JSON report saved: {output_path}")

        return json_str
