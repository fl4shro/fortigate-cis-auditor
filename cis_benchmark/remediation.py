"""
Remediation Engine
===================
Generates FortiGate CLI remediation commands and downloadable scripts.
"""

import logging
from typing import List, Optional
from datetime import datetime
from cis_benchmark.rules.base import RuleResult

logger = logging.getLogger(__name__)


class RemediationEngine:
    """
    Generates remediation scripts from failed CIS rules.
    
    Usage:
        engine = RemediationEngine()
        script = engine.generate_script(failed_results)
        engine.save_script(script, "remediation.txt")
    """

    HEADER = """# ============================================================
# FortiGate CIS Benchmark Remediation Script
# Generated: {timestamp}
# Mode: {mode}
# Total Remediation Commands: {count}
# ============================================================
#
# WARNING: Review each command carefully before applying.
# Test in a lab environment first.
# Ensure you have a configuration backup.
#
# Usage:
#   1. Connect to FortiGate CLI (SSH or Console)
#   2. Paste commands one section at a time
#   3. Verify changes with 'get system status'
#
# ============================================================
"""

    def generate_script(
        self,
        failed_results: List[RuleResult],
        dry_run: bool = True,
    ) -> str:
        """Generate a remediation script from failed rule results."""
        mode = "DRY-RUN (Preview Only)" if dry_run else "LIVE EXECUTION"
        commands = []
        
        for result in failed_results:
            if result.remediation_cli:
                commands.append(result)

        script = self.HEADER.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            mode=mode,
            count=len(commands),
        )

        if dry_run:
            script += "\n# === DRY-RUN MODE ===\n"
            script += "# Commands are shown for review only. No changes will be applied.\n"
            script += "# Remove '# [DRY-RUN]' prefix to enable execution.\n\n"

        # Group by category
        categories = {}
        for result in commands:
            cat = result.category or "General"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)

        for category, results in sorted(categories.items()):
            script += f"\n# {'=' * 60}\n"
            script += f"# Category: {category}\n"
            script += f"# {'=' * 60}\n\n"

            for result in results:
                script += f"# Rule {result.rule_id}: {result.title}\n"
                script += f"# Severity: {result.severity.value}\n"
                script += f"# Current: {result.actual_value}\n"
                script += f"# Expected: {result.expected_value}\n"

                if dry_run:
                    for line in result.remediation_cli.split('\n'):
                        script += f"# [DRY-RUN] {line}\n"
                else:
                    script += result.remediation_cli + "\n"

                script += "\n"

        script += "\n# === END OF REMEDIATION SCRIPT ===\n"
        return script

    def save_script(self, script: str, filepath: str):
        """Save remediation script to file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(script)
            logger.info(f"Remediation script saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save remediation script: {e}")
            raise

    def get_remediation_summary(self, failed_results: List[RuleResult]) -> dict:
        """Get a summary of remediations grouped by severity."""
        summary = {
            "total_remediations": 0,
            "with_cli_commands": 0,
            "manual_only": 0,
            "by_severity": {},
            "by_category": {},
        }

        for result in failed_results:
            summary["total_remediations"] += 1

            if result.remediation_cli:
                summary["with_cli_commands"] += 1
            else:
                summary["manual_only"] += 1

            sev = result.severity.value
            if sev not in summary["by_severity"]:
                summary["by_severity"][sev] = 0
            summary["by_severity"][sev] += 1

            cat = result.category or "General"
            if cat not in summary["by_category"]:
                summary["by_category"][cat] = 0
            summary["by_category"][cat] += 1

        return summary
