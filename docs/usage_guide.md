# Usage Guide

## Installation

```bash
# Clone / navigate to the project
cd Fortigate_CIS_check-main

# Install dependencies
pip install -r requirements.txt
```

## CLI Usage

### Basic Audit

```bash
python run_audit.py <config_file>
```

### Specify Output Format

```bash
python run_audit.py config.conf --format html,json,pdf
```

### Filter by CIS Level

```bash
python run_audit.py config.conf --level 1    # Level 1 only
python run_audit.py config.conf --level 2    # Level 2 only
python run_audit.py config.conf --level all  # All levels (default)
```

### Custom Output Directory

```bash
python run_audit.py config.conf --output-dir ./my_reports
```

### Generate Remediation Script

```bash
python run_audit.py config.conf --remediation --dry-run
```

## Web Dashboard

### Start the Dashboard

```bash
python run_audit.py --web
# or with custom port:
python run_audit.py --web --port 8080
```

### Using the Dashboard

1. Open browser to `http://localhost:5000`
2. Upload a FortiGate `.conf` backup file
3. Select CIS Level filter (All / Level 1 / Level 2)
4. Click **Run Audit**
5. View compliance scores, failed controls, and severity breakdown
6. Download reports (HTML, JSON, PDF, Remediation Script)

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Specific modules
python -m pytest tests/test_config_parser.py -v
python -m pytest tests/test_rules.py -v
python -m pytest tests/test_scoring.py -v
```

## Legacy Usage

The original CLI remains functional:

```bash
python fortigate_cis_checker.py <config_file>
```

## Report Outputs

| Format | Description | Use Case |
|--------|-------------|----------|
| HTML | Interactive dark-mode report with filters | Browser viewing, presentations |
| JSON | Structured data output | SIEM/GRC integration, automation |
| PDF | Printable report (requires weasyprint) | Formal compliance documentation |
| TXT | Remediation CLI commands | Applying fixes on FortiGate |
