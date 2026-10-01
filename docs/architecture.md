# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    FortiGate CIS Benchmark                  │
│                    Compliance Auditor v2.0                   │
├─────────────┬─────────────────────────────────┬─────────────┤
│  Entry      │         Core Engine              │  Output      │
│  Points     │         (cis_benchmark/)         │              │
│             │                                  │              │
│ run_audit   │  ┌─────────────────┐            │  HTML Report │
│   .py       │  │  Config Parser  │            │  JSON Report │
│             │  │  config_parser  │            │  PDF Report  │
│ web/app.py  │  │      .py        │            │  Remediation │
│             │  └───────┬─────────┘            │   Script     │
│ legacy:     │          │                       │              │
│ fortigate_  │  ┌───────▼─────────┐            │              │
│ cis_checker │  │  Rule Engine    │            │              │
│   .py       │  │  rules/         │            │              │
│             │  │  ├─ base.py     │            │              │
│             │  │  ├─ level1.py   │            │              │
│             │  │  └─ level2.py   │            │              │
│             │  └───────┬─────────┘            │              │
│             │          │                       │              │
│             │  ┌───────▼─────────┐            │              │
│             │  │  Scoring        │            │              │
│             │  │  scoring.py     │────────────│► Reports     │
│             │  └───────┬─────────┘            │              │
│             │          │                       │              │
│             │  ┌───────▼─────────┐            │              │
│             │  │  Reporting      │            │              │
│             │  │  reporting/     │            │              │
│             │  │  ├─ html        │            │              │
│             │  │  ├─ json        │            │              │
│             │  │  └─ pdf         │            │              │
│             │  └─────────────────┘            │              │
│             │                                  │              │
│             │  ┌─────────────────┐            │              │
│             │  │  Remediation    │            │              │
│             │  │  remediation.py │────────────│► CLI Script  │
│             │  └─────────────────┘            │              │
└─────────────┴─────────────────────────────────┴──────────────┘
```

## Data Flow

1. **Input** → FortiGate `.conf` backup file
2. **Parsing** → `FortiGateConfigParser` extracts structured blocks
3. **Rule Evaluation** → 56 CIS rules (35 L1, 21 L2) evaluate config
4. **Scoring** → `ComplianceScorer` calculates weighted scores
5. **Reporting** → HTML/JSON/PDF reports generated
6. **Remediation** → CLI scripts auto-generated for failures

## Module Details

| Module | File | Purpose |
|--------|------|---------|
| Config Parser | `config_parser.py` | Parse `.conf` into structured `FortiGateConfig` |
| Rule Base | `rules/base.py` | `CISRule`, `RuleResult`, severity/level enums |
| Level 1 Rules | `rules/level1_rules.py` | 35 basic CIS controls |
| Level 2 Rules | `rules/level2_rules.py` | 21 advanced CIS controls |
| Scoring | `scoring.py` | Compliance %, weighted scores, risk ratings |
| HTML Report | `reporting/html_report.py` | Enterprise dark-mode report |
| JSON Report | `reporting/json_report.py` | SIEM-compatible output |
| PDF Report | `reporting/pdf_report.py` | Optional PDF generation |
| Remediation | `remediation.py` | FortiGate CLI remediation scripts |
| Web UI | `web/app.py` | Flask dashboard |
| CLI | `run_audit.py` | Command-line entry point |
