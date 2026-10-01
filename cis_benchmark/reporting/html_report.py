"""
HTML Report Generator
======================
Generates enterprise-grade HTML compliance reports with executive summary,
risk heatmap, failed controls table, and remediation recommendations.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """Generate enterprise-grade HTML compliance reports."""

    def generate(self, report, config_file: str = "", output_path: str = "") -> str:
        """Generate HTML report from ComplianceReport."""
        html = self._build_report(report, config_file)

        if output_path:
            Path(output_path).write_text(html, encoding="utf-8")
            logger.info(f"HTML report saved: {output_path}")

        return html

    def _build_report(self, report, config_file: str) -> str:
        """Build the complete HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build category heatmap rows
        heatmap_rows = ""
        for name, cs in report.category_scores.items():
            pct = cs.percentage
            color = self._pct_color(pct)
            heatmap_rows += f"""
                <tr>
                    <td>{name}</td>
                    <td>{cs.total}</td>
                    <td>{cs.passed}</td>
                    <td>{cs.failed}</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width:{pct}%;background:{color}"></div>
                        </div>
                        <span class="pct-label">{pct}%</span>
                    </td>
                </tr>"""

        # Build failed controls table
        failed_rows = ""
        for r in report.failed_results:
            sev_class = r.severity.value.lower()
            level_badge = f"L{r.level.value}"
            failed_rows += f"""
                <tr class="severity-{sev_class}">
                    <td><span class="rule-id">{r.rule_id}</span></td>
                    <td>{r.title}</td>
                    <td><span class="badge badge-level">{level_badge}</span></td>
                    <td><span class="badge badge-{sev_class}">{r.severity.value}</span></td>
                    <td class="actual-value">{r.actual_value}</td>
                    <td class="expected-value">{r.expected_value}</td>
                    <td class="remediation">{r.remediation}</td>
                </tr>"""

        # Build all controls table
        all_rows = ""
        for r in report.results:
            status_class = "pass" if r.passed else "fail"
            sev_class = r.severity.value.lower()
            all_rows += f"""
                <tr class="status-{status_class}" data-severity="{r.severity.value}" data-level="{r.level.value}" data-category="{r.category}" data-status="{r.status}">
                    <td><span class="rule-id">{r.rule_id}</span></td>
                    <td>{r.title}</td>
                    <td><span class="badge badge-level">L{r.level.value}</span></td>
                    <td><span class="badge badge-{sev_class}">{r.severity.value}</span></td>
                    <td><span class="status-badge status-{status_class}">{r.status}</span></td>
                    <td class="actual-value">{r.actual_value}</td>
                </tr>"""

        # Score gauge color
        gauge_color = self._pct_color(report.overall_percentage)
        l1_color = self._pct_color(report.level1_percentage)
        l2_color = self._pct_color(report.level2_percentage)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FortiGate CIS Benchmark Audit Report</title>
<style>
:root {{
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --bg-card-hover: #1f2b3d;
    --text-primary: #e5e7eb;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --accent-blue: #3b82f6;
    --accent-cyan: #06b6d4;
    --accent-green: #10b981;
    --accent-red: #ef4444;
    --accent-orange: #f59e0b;
    --accent-purple: #8b5cf6;
    --border: #1f2937;
    --radius: 12px;
    --shadow: 0 4px 24px rgba(0,0,0,0.3);
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}}

.container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}

/* Header */
.report-header {{
    background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 50%, #1a1a2e 100%);
    border-radius: var(--radius);
    padding: 40px;
    margin-bottom: 30px;
    border: 1px solid rgba(59,130,246,0.2);
    position: relative;
    overflow: hidden;
}}
.report-header::before {{
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(59,130,246,0.08), transparent 70%);
    pointer-events: none;
}}
.report-header h1 {{
    font-size: 28px;
    font-weight: 700;
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
}}
.report-header .subtitle {{ color: var(--text-secondary); font-size: 14px; }}
.report-header .meta {{ color: var(--text-muted); font-size: 13px; margin-top: 12px; }}

/* Score Cards */
.score-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}}
.score-card {{
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 24px;
    border: 1px solid var(--border);
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
}}
.score-card:hover {{
    transform: translateY(-2px);
    box-shadow: var(--shadow);
}}
.score-card .score-value {{
    font-size: 42px;
    font-weight: 700;
    margin: 8px 0;
}}
.score-card .score-label {{
    font-size: 13px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
}}
.score-card .score-detail {{
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 8px;
}}

/* Sections */
.section {{
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 28px;
    margin-bottom: 24px;
    border: 1px solid var(--border);
}}
.section-title {{
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 10px;
}}
.section-title .icon {{
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
}}

/* Tables */
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
th {{
    text-align: left;
    padding: 12px 16px;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
}}
td {{
    padding: 12px 16px;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    vertical-align: top;
}}
tr:hover {{ background: var(--bg-card-hover); }}

/* Badges */
.badge {{
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.badge-critical {{ background: rgba(239,68,68,0.15); color: #f87171; }}
.badge-high {{ background: rgba(245,158,11,0.15); color: #fbbf24; }}
.badge-medium {{ background: rgba(59,130,246,0.15); color: #60a5fa; }}
.badge-low {{ background: rgba(16,185,129,0.15); color: #34d399; }}
.badge-level {{ background: rgba(139,92,246,0.15); color: #a78bfa; }}

.status-badge {{
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
}}
.status-pass {{ background: rgba(16,185,129,0.15); color: #34d399; }}
.status-fail {{ background: rgba(239,68,68,0.15); color: #f87171; }}

.rule-id {{
    font-family: 'Consolas', 'Monaco', monospace;
    font-weight: 600;
    color: var(--accent-cyan);
}}

/* Progress bars */
.progress-bar {{
    width: 120px;
    height: 8px;
    background: rgba(255,255,255,0.06);
    border-radius: 4px;
    overflow: hidden;
    display: inline-block;
    vertical-align: middle;
}}
.progress-fill {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.5s ease;
}}
.pct-label {{
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-left: 8px;
}}

/* Risk Indicator */
.risk-indicator {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 16px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 13px;
    margin-top: 8px;
}}

/* Severity summary */
.severity-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}}
.severity-item {{
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
    border-left: 3px solid;
}}

/* Search/Filter */
.controls-bar {{
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    align-items: center;
}}
.search-input {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 16px;
    color: var(--text-primary);
    font-size: 13px;
    flex: 1;
    min-width: 200px;
}}
.search-input:focus {{ outline: none; border-color: var(--accent-blue); }}
.filter-btn {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 16px;
    color: var(--text-secondary);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
}}
.filter-btn:hover, .filter-btn.active {{
    background: var(--accent-blue);
    color: white;
    border-color: var(--accent-blue);
}}

.actual-value {{ color: var(--accent-orange); font-family: monospace; font-size: 12px; }}
.expected-value {{ color: var(--accent-green); font-family: monospace; font-size: 12px; }}
.remediation {{ font-size: 12px; color: var(--text-secondary); }}

/* Footer */
.report-footer {{
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
    padding: 20px;
    margin-top: 20px;
}}

/* Print styles - optimized for A4 PDF / WeasyPrint */
@page {{
    size: A4 landscape;
    margin: 10mm;
}}

@media print {{
    html,
    body {{
        width: 100%;
        margin: 0;
        padding: 0;
        background: #ffffff !important;
        color: #222222 !important;
        font-size: 10px;
    }}

    * {{
        box-sizing: border-box;
    }}

    .container {{
        width: 100% !important;
        max-width: none !important;
        margin: 0 !important;
        padding: 0 !important;
    }}

    .report-header {{
        background: #f3f4f6 !important;
        color: #222 !important;
        border: 1px solid #d1d5db !important;
        border-radius: 0 !important;
        padding: 18px !important;
        margin-bottom: 12px !important;
        page-break-inside: avoid;
    }}

    .report-header h1 {{
        color: #1f2937 !important;
        background: none !important;
        -webkit-text-fill-color: #1f2937 !important;
        font-size: 20px !important;
    }}

    .report-header .subtitle,
    .report-header .meta {{
        color: #4b5563 !important;
    }}

    .score-grid {{
        grid-template-columns: repeat(4, 1fr) !important;
        gap: 8px !important;
        margin-bottom: 12px !important;
    }}

    .score-card {{
        background: #ffffff !important;
        border: 1px solid #d1d5db !important;
        border-radius: 6px !important;
        padding: 12px !important;
        box-shadow: none !important;
        page-break-inside: avoid;
    }}

    .score-card .score-value {{
        font-size: 28px !important;
    }}

    .score-card .score-label,
    .score-card .score-detail {{
        color: #4b5563 !important;
    }}

    .section {{
        background: #ffffff !important;
        color: #222222 !important;
        border: 1px solid #d1d5db !important;
        border-radius: 6px !important;
        padding: 14px !important;
        margin-bottom: 12px !important;
        box-shadow: none !important;
    }}

    .section-title {{
        color: #1f2937 !important;
        font-size: 14px !important;
        margin-bottom: 10px !important;
        page-break-after: avoid;
    }}

    .severity-grid {{
        gap: 8px !important;
    }}

    .severity-item {{
        background: #f9fafb !important;
        padding: 10px !important;
    }}

    .controls-bar {{
        display: none !important;
    }}

    table {{
        width: 100% !important;
        max-width: 100% !important;
        table-layout: fixed !important;
        border-collapse: collapse !important;
        font-size: 8.5px !important;
        color: #222222 !important;
    }}

    th {{
        background: #e5e7eb !important;
        color: #1f2937 !important;
        border: 1px solid #cbd5e1 !important;
        padding: 6px 5px !important;
        font-size: 8px !important;
        white-space: normal !important;
        overflow-wrap: anywhere !important;
        word-break: break-word !important;
    }}

    td {{
        background: #ffffff !important;
        color: #222222 !important;
        border: 1px solid #e5e7eb !important;
        padding: 6px 5px !important;
        vertical-align: top !important;
        white-space: normal !important;
        overflow-wrap: anywhere !important;
        word-break: break-word !important;
    }}

    tr {{
        page-break-inside: avoid !important;
        break-inside: avoid !important;
    }}

    .actual-value,
    .expected-value,
    .remediation {{
        font-size: 8px !important;
        white-space: normal !important;
        overflow-wrap: anywhere !important;
        word-break: break-word !important;
    }}

    .rule-id {{
        color: #0369a1 !important;
    }}

    .badge,
    .status-badge {{
        font-size: 7.5px !important;
        padding: 2px 5px !important;
    }}

    .status-pass {{
        background: #dcfce7 !important;
        color: #166534 !important;
    }}

    .status-fail {{
        background: #fee2e2 !important;
        color: #991b1b !important;
    }}

    /* Compliance by Category */
    .section:nth-of-type(3) table th:nth-child(1),
    .section:nth-of-type(3) table td:nth-child(1) {{
        width: 40%;
    }}

    .section:nth-of-type(3) table th:nth-child(2),
    .section:nth-of-type(3) table td:nth-child(2),
    .section:nth-of-type(3) table th:nth-child(3),
    .section:nth-of-type(3) table td:nth-child(3),
    .section:nth-of-type(3) table th:nth-child(4),
    .section:nth-of-type(3) table td:nth-child(4) {{
        width: 12%;
        text-align: center;
    }}

    .section:nth-of-type(3) table th:nth-child(5),
    .section:nth-of-type(3) table td:nth-child(5) {{
        width: 24%;
    }}

    /* Failed Controls - 7 columns */
    .section table th:nth-child(1),
    .section table td:nth-child(1) {{
        width: 7%;
    }}

    .section table th:nth-child(2),
    .section table td:nth-child(2) {{
        width: 19%;
    }}

    .section table th:nth-child(3),
    .section table td:nth-child(3) {{
        width: 7%;
    }}

    .section table th:nth-child(4),
    .section table td:nth-child(4) {{
        width: 9%;
    }}

    .section table th:nth-child(5),
    .section table td:nth-child(5) {{
        width: 19%;
    }}

    .section table th:nth-child(6),
    .section table td:nth-child(6) {{
        width: 18%;
    }}

    .section table th:nth-child(7),
    .section table td:nth-child(7) {{
        width: 21%;
    }}

    /* All Controls - 6 columns */
    #allControlsTable th:nth-child(1),
    #allControlsTable td:nth-child(1) {{
        width: 8%;
    }}

    #allControlsTable th:nth-child(2),
    #allControlsTable td:nth-child(2) {{
        width: 27%;
    }}

    #allControlsTable th:nth-child(3),
    #allControlsTable td:nth-child(3) {{
        width: 8%;
    }}

    #allControlsTable th:nth-child(4),
    #allControlsTable td:nth-child(4) {{
        width: 10%;
    }}

    #allControlsTable th:nth-child(5),
    #allControlsTable td:nth-child(5) {{
        width: 11%;
    }}

    #allControlsTable th:nth-child(6),
    #allControlsTable td:nth-child(6) {{
        width: 36%;
    }}

    .progress-bar {{
        width: 70px !important;
    }}

    .report-footer {{
        color: #6b7280 !important;
        font-size: 8px !important;
        padding: 8px !important;
    }}
}}
</style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div class="report-header">
        <h1>&#128737; FortiGate CIS Benchmark Audit Report</h1>
        <div class="subtitle">CIS FortiGate Benchmark v1.4.0 Compliance Assessment</div>
        <div class="meta">
            Generated: {timestamp} &nbsp;|&nbsp; Config: {config_file or 'N/A'} &nbsp;|&nbsp;
            Total Controls: {report.total_rules}
        </div>
    </div>

    <!-- Executive Summary - Score Cards -->
    <div class="score-grid">
        <div class="score-card">
            <div class="score-label">Overall Compliance</div>
            <div class="score-value" style="color:{gauge_color}">{report.overall_percentage}%</div>
            <div class="score-detail">{report.passed_rules}/{report.total_rules} controls passed</div>
            <div class="risk-indicator" style="background:rgba(0,0,0,0.3);color:{report.risk_color}">
                &#9888; Risk: {report.risk_rating}
            </div>
        </div>
        <div class="score-card">
            <div class="score-label">Level 1 (Basic)</div>
            <div class="score-value" style="color:{l1_color}">{report.level1_percentage}%</div>
            <div class="score-detail">{report.level1_passed}/{report.level1_total} controls passed</div>
        </div>
        <div class="score-card">
            <div class="score-label">Level 2 (Advanced)</div>
            <div class="score-value" style="color:{l2_color}">{report.level2_percentage}%</div>
            <div class="score-detail">{report.level2_passed}/{report.level2_total} controls passed</div>
        </div>
        <div class="score-card">
            <div class="score-label">Weighted Score</div>
            <div class="score-value" style="color:{gauge_color}">{report.weighted_score}%</div>
            <div class="score-detail">Severity-weighted calculation</div>
        </div>
    </div>

    <!-- Severity Breakdown -->
    <div class="section">
        <div class="section-title">&#9888;&#65039; Severity Breakdown</div>
        <div class="severity-grid">
            <div class="severity-item" style="border-color:#ef4444">
                <div style="font-size:24px;font-weight:700;color:#f87171">{report.critical_total - report.critical_passed}</div>
                <div style="font-size:12px;color:var(--text-secondary)">Critical Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.critical_passed}/{report.critical_total} passed</div>
            </div>
            <div class="severity-item" style="border-color:#f59e0b">
                <div style="font-size:24px;font-weight:700;color:#fbbf24">{report.high_total - report.high_passed}</div>
                <div style="font-size:12px;color:var(--text-secondary)">High Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.high_passed}/{report.high_total} passed</div>
            </div>
            <div class="severity-item" style="border-color:#3b82f6">
                <div style="font-size:24px;font-weight:700;color:#60a5fa">{report.medium_total - report.medium_passed}</div>
                <div style="font-size:12px;color:var(--text-secondary)">Medium Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.medium_passed}/{report.medium_total} passed</div>
            </div>
            <div class="severity-item" style="border-color:#10b981">
                <div style="font-size:24px;font-weight:700;color:#34d399">{report.low_total - report.low_passed}</div>
                <div style="font-size:12px;color:var(--text-secondary)">Low Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.low_passed}/{report.low_total} passed</div>
            </div>
        </div>
    </div>

    <!-- Risk Heatmap by Category -->
    <div class="section">
        <div class="section-title">&#128200; Compliance by Category</div>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Total</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>{heatmap_rows}</tbody>
        </table>
    </div>

    <!-- Failed Controls -->
    <div class="section">
        <div class="section-title">&#10060; Failed Controls ({report.failed_rules})</div>
        {"<p style='color:var(--accent-green);font-size:14px;'>All controls passed! &#10004;</p>" if report.failed_rules == 0 else f'''
        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Control</th>
                    <th>Level</th>
                    <th>Severity</th>
                    <th>Actual Value</th>
                    <th>Expected Value</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>{failed_rows}</tbody>
        </table>'''}
    </div>

    <!-- All Controls -->
    <div class="section">
        <div class="section-title">&#128203; All Controls ({report.total_rules})</div>
        <div class="controls-bar">
            <input type="text" class="search-input" placeholder="Search rules..." oninput="filterTable(this.value)" id="searchInput">
            <button class="filter-btn active" onclick="filterStatus('all', this)">All</button>
            <button class="filter-btn" onclick="filterStatus('PASS', this)">Pass</button>
            <button class="filter-btn" onclick="filterStatus('FAIL', this)">Fail</button>
            <button class="filter-btn" onclick="filterSeverity('Critical', this)">Critical</button>
            <button class="filter-btn" onclick="filterSeverity('High', this)">High</button>
            <button class="filter-btn" onclick="filterSeverity('Medium', this)">Medium</button>
            <button class="filter-btn" onclick="filterSeverity('Low', this)">Low</button>
        </div>
        <table id="allControlsTable">
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Control</th>
                    <th>Level</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>{all_rows}</tbody>
        </table>
    </div>

    <div class="report-footer">
        FortiGate CIS Benchmark Checker v2.0.0 &bull; CIS FortiGate Benchmark v1.4.0 &bull; Generated {timestamp}
    </div>
</div>

<script>
let currentStatusFilter = 'all';
let currentSeverityFilter = 'all';

function filterTable(query) {{
    const rows = document.querySelectorAll('#allControlsTable tbody tr');
    const q = query.toLowerCase();
    rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        const matchText = !q || text.includes(q);
        const status = row.dataset.status;
        const severity = row.dataset.severity;
        const matchStatus = currentStatusFilter === 'all' || status === currentStatusFilter;
        const matchSev = currentSeverityFilter === 'all' || severity === currentSeverityFilter;
        row.style.display = matchText && matchStatus && matchSev ? '' : 'none';
    }});
}}

function filterStatus(status, btn) {{
    currentStatusFilter = status;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterTable(document.getElementById('searchInput').value);
}}

function filterSeverity(severity, btn) {{
    currentSeverityFilter = severity === currentSeverityFilter ? 'all' : severity;
    filterTable(document.getElementById('searchInput').value);
}}
</script>
</body>
</html>"""
        return html

    def _pct_color(self, pct: float) -> str:
        if pct >= 80:
            return "#10b981"
        elif pct >= 60:
            return "#f59e0b"
        elif pct >= 40:
            return "#f97316"
        else:
            return "#ef4444"
