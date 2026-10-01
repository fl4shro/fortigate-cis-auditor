# FortiGate CIS Benchmark Checker v2.0

Enterprise-grade FortiGate CIS Benchmark compliance auditing tool.

This project analyzes FortiGate .conf configuration files and evaluates them against the CIS FortiGate Benchmark v1.4.0.

## Features

- 56 CIS Controls
- 34 Level 1 controls
- 22 Level 2 controls
- Structured FortiGate configuration parser
- Compliance scoring
- Severity-weighted scoring
- HTML reports
- JSON reports
- PDF reports
- Web dashboard
- Detailed evidence for each control
- FortiGate CLI remediation scripts
- Anonymous browser sessions
- In-memory processing of uploaded configurations
- HTTPS and protected session cookies
- Tested with FortiOS 7.0.x and 7.6.x

## CIS Benchmark

The auditing engine uses the following CIS benchmark as its reference:

CIS FortiGate 7.0.x Benchmark v1.4.0

Official CIS reference:

https://www.cisecurity.org/benchmark/fortinet

The benchmark is maintained by the Center for Internet Security (CIS).

## FortiOS Versions

The parser and auditing engine have been tested with configurations from:

- FortiOS 7.0.x
- FortiOS 7.6.x

The project keeps the CIS control set defined by the benchmark used by the auditor.

Compatibility with a FortiOS version does not mean that CIS publishes a separate benchmark for every FortiOS release.

## Compliance Reports

Reports include:

- Overall compliance score
- Level 1 score
- Level 2 score
- Severity-weighted score
- PASS / FAIL status
- Control severity
- Actual configuration value
- Expected value
- Configuration evidence
- Remediation recommendation
- Compliance by category

Available formats:

- HTML
- JSON
- PDF

## Quick Start

Clone the repository:

git clone https://github.com/YOUR-USERNAME/fortigate-cis-auditor.git
cd fortigate-cis-auditor

Create a virtual environment:

python3 -m venv venv
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

## Web Dashboard

Start the application with:

gunicorn --workers 1 --threads 2 --bind 127.0.0.1:8000 web.app:app

Then access:

http://127.0.0.1:8000

## FortiGate Configuration

For a complete configuration suitable for auditing, use:

config system console
    set output standard
end

show full-configuration

Save the output as a .conf file.

## Privacy and Security

The web application is designed so that uploaded FortiGate configurations are not permanently stored by the application.

The .conf file is processed in memory during the audit.

Audit results are associated with an anonymous browser session and stored temporarily in application memory.

The project supports:

- HTTPS
- Secure session cookies
- HttpOnly cookies
- SameSite protection
- No-cache security headers
- Temporary in-memory processing

Production FortiGate configuration files, credentials, certificates and private keys must never be committed to the repository.

## Project Structure

fortigate-cis/
├── cis_benchmark/
│   ├── config_parser.py
│   ├── scoring.py
│   ├── remediation.py
│   ├── benchmark_selector.py
│   ├── rules/
│   │   ├── base.py
│   │   ├── level1_rules.py
│   │   ├── level2_rules.py
│   │   ├── level1_rules_legacy.py
│   │   ├── level2_rules_legacy.py
│   │   └── cis_v140_registry.py
│   └── reporting/
│       ├── html_report.py
│       ├── json_report.py
│       └── pdf_report.py
├── web/
│   ├── app.py
│   └── templates/
│       └── dashboard.html
├── tests/
│   ├── test_rules.py
│   └── test_sample_config.conf
├── requirements.txt
├── run_audit.py
└── README.md

## Test Configuration

The repository contains a fictional FortiGate configuration used exclusively for testing:

tests/test_sample_config.conf

It does not represent a production FortiGate environment.

All values contained in the test configuration are intended for testing purposes only.

## Testing

Run:

pytest

## Contributions

Contributions are welcome.

If you find a FortiGate configuration that is not parsed correctly, a FortiOS syntax difference, an incorrect rule, incorrect evidence, a report issue or a possible improvement, please open an Issue or submit a Pull Request.

## Disclaimer

This project is an auditing and compliance assistance tool.

Audit results should be reviewed by a qualified network or security professional before making changes to a production FortiGate environment.

Do not automatically apply remediation recommendations without evaluating their impact on the environment.

## License

MIT
