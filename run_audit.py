#!/usr/bin/env python3
"""
FortiGate CIS Benchmark Audit Tool – CLI Entry Point
======================================================
Usage:
    python run_audit.py <config_file> [options]
    python run_audit.py --web [--port 5000]

Options:
    --format html,json,pdf    Output formats (default: html,json)
    --level 1|2|all           CIS level filter (default: all)
    --output-dir DIR          Output directory (default: ./reports)
    --web                     Start web UI dashboard
    --port PORT               Web UI port (default: 5000)
    --remediation             Generate remediation script
    --dry-run                 Remediation in dry-run mode (default: true)
"""

import sys
import os
import argparse
import logging
import concurrent.futures
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cis_benchmark.config_parser import FortiGateConfigParser
from cis_benchmark.rules import get_all_rules, get_level1_rules, get_level2_rules
from cis_benchmark.scoring import ComplianceScorer
from cis_benchmark.remediation import RemediationEngine
from cis_benchmark.reporting import HTMLReportGenerator, JSONReportGenerator, PDFReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fortigate_cis_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║       FortiGate CIS Benchmark Compliance Auditor v2.0       ║
║       CIS FortiGate Benchmark v1.4.0                         ║
║       Author: Priyam Patel                                   ║
╚══════════════════════════════════════════════════════════════╝
"""


def evaluate_rules_threaded(rules, config, max_workers=4):
    """Evaluate rules using thread pool for performance."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_rule = {executor.submit(rule.evaluate, config): rule for rule in rules}
        for future in concurrent.futures.as_completed(future_to_rule):
            rule = future_to_rule[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Rule {rule.rule_id} failed: {e}")
    # Sort by rule_id
    results.sort(key=lambda r: r.rule_id)
    return results


def run_audit(config_path, level="all", output_dir="reports", formats=None, generate_remediation=True, dry_run=True):
    """Run a complete CIS audit."""
    if formats is None:
        formats = ["html", "json"]

    print(BANNER)
    logger.info(f"Starting CIS audit: {config_path}")

    # Parse config
    parser = FortiGateConfigParser()
    config = parser.parse_file(config_path)
    logger.info(f"Parsed config: model={config.model}, version={config.version}, hostname={config.hostname}")

    # Select rules
    if level == "1":
        rules = get_level1_rules()
    elif level == "2":
        rules = get_level2_rules()
    else:
        rules = get_all_rules()
    logger.info(f"Evaluating {len(rules)} rules (Level: {level})")

    # Evaluate rules (threaded for performance)
    results = evaluate_rules_threaded(rules, config)

    # Calculate scores
    scorer = ComplianceScorer()
    report = scorer.calculate(results)

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  COMPLIANCE SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Overall Score:    {report.overall_percentage}% ({report.risk_rating} Risk)")
    print(f"  Weighted Score:   {report.weighted_score}%")
    print(f"  Total Controls:   {report.total_rules}")
    print(f"  Passed:           {report.passed_rules}")
    print(f"  Failed:           {report.failed_rules}")
    print(f"  Level 1 Score:    {report.level1_percentage}% ({report.level1_passed}/{report.level1_total})")
    print(f"  Level 2 Score:    {report.level2_percentage}% ({report.level2_passed}/{report.level2_total})")
    print(f"{'=' * 60}")

    if report.critical_failures:
        print(f"\n  ⚠ CRITICAL FAILURES ({len(report.critical_failures)}):")
        for r in report.critical_failures:
            print(f"    [{r.rule_id}] {r.title}")
    if report.high_failures:
        print(f"\n  ⚠ HIGH FAILURES ({len(report.high_failures)}):")
        for r in report.high_failures:
            print(f"    [{r.rule_id}] {r.title}")

    # Generate reports
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    config_name = Path(config_path).stem

    if "html" in formats:
        html_gen = HTMLReportGenerator()
        html_path = os.path.join(output_dir, f"CIS_Audit_{config_name}_{timestamp}.html")
        html_gen.generate(report, config_file=config_path, output_path=html_path)
        print(f"\n  ✓ HTML Report: {html_path}")

    if "json" in formats:
        json_gen = JSONReportGenerator()
        json_path = os.path.join(output_dir, f"CIS_Audit_{config_name}_{timestamp}.json")
        json_gen.generate(report, config_file=config_path, output_path=json_path)
        print(f"  ✓ JSON Report: {json_path}")

    if "pdf" in formats:
        html_gen = HTMLReportGenerator()
        html_content = html_gen.generate(report, config_file=config_path)
        pdf_gen = PDFReportGenerator()
        pdf_path = os.path.join(output_dir, f"CIS_Audit_{config_name}_{timestamp}.pdf")
        success = pdf_gen.generate(html_content, pdf_path)
        if success:
            print(f"  ✓ PDF Report: {pdf_path}")
        else:
            print(f"  ✓ PDF (as HTML): {pdf_path.replace('.pdf', '_report.html')}")

    if generate_remediation and report.failed_results:
        engine = RemediationEngine()
        script = engine.generate_script(report.failed_results, dry_run=dry_run)
        remediation_path = os.path.join(output_dir, f"Remediation_{config_name}_{timestamp}.txt")
        engine.save_script(script, remediation_path)
        print(f"  ✓ Remediation: {remediation_path}")

    print(f"\n{'=' * 60}")
    logger.info("Audit complete")
    return report


def start_web_ui(port=5000):
    """Start the web UI dashboard."""
    print(BANNER)
    print(f"  Starting CIS Compliance Dashboard...")
    print(f"  Open: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")

    from web.app import app
    app.run(host='0.0.0.0', port=port, debug=False)


def main():
    argparser = argparse.ArgumentParser(
        description="FortiGate CIS Benchmark Compliance Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_audit.py test_file.txt
  python run_audit.py config.conf --format html,json --level 1
  python run_audit.py config.conf --output-dir ./reports --remediation
  python run_audit.py --web --port 8080
        """
    )
    argparser.add_argument('config_file', nargs='?', help='Path to FortiGate config file')
    argparser.add_argument('--format', default='html,json', help='Output formats (html,json,pdf)')
    argparser.add_argument('--level', default='all', choices=['1', '2', 'all'], help='CIS level filter')
    argparser.add_argument('--output-dir', default='reports', help='Output directory')
    argparser.add_argument('--web', action='store_true', help='Start web UI dashboard')
    argparser.add_argument('--port', type=int, default=5000, help='Web UI port')
    argparser.add_argument('--remediation', action='store_true', default=True, help='Generate remediation script')
    argparser.add_argument('--no-remediation', action='store_false', dest='remediation')
    argparser.add_argument('--dry-run', action='store_true', default=True, help='Remediation in dry-run mode')

    args = argparser.parse_args()

    if args.web:
        start_web_ui(args.port)
    elif args.config_file:
        formats = [f.strip() for f in args.format.split(',')]
        run_audit(
            config_path=args.config_file,
            level=args.level,
            output_dir=args.output_dir,
            formats=formats,
            generate_remediation=args.remediation,
            dry_run=args.dry_run,
        )
    else:
        argparser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
