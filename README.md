# Automated Authentication Log Analyzer & Incident Detection Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Clean](https://img.shields.io/badge/code%20style-pep8-brightgreen.svg)](https://www.python.org/dev/peps/pep-0008/)

A lightweight, automated Python security CLI tool that parses standard Linux authentication logs (`auth.log` / `secure`), detects potential **brute-force attacks** and **credential stuffing patterns**, and generates structured incident response reports in **CLI text**, **JSON**, or **Markdown**.

Developed by **Deepika Tamang** (Computer Engineering, Texas A&M University).

---

## 🔍 Key Capabilities

- **Log Parsing:** Regex-based extraction of accepted and failed SSH authentication events including timestamps, process IDs, targeted usernames, client IP addresses, and ports.
- **Threat Detection Engine:** Identifies IPs exceeding configurable failure thresholds (e.g., 5+ failed attempts).
- **Attack Classification:** Differentiates between targeted single-account password guessing and wide-spectrum credential stuffing attacks.
- **Multi-Format Reporting:**
  - `text`: Human-readable terminal incident overview.
  - `json`: Machine-readable payload for SIEM ingestion or automated firewall integration (e.g., `iptables` / `fail2ban`).
  - `markdown`: Formatted tables ready for incident documentation and ticketing.
- **Zero Third-Party Dependencies:** Built entirely with Python's standard library (`dataclasses`, `re`, `argparse`, `json`, `collections`).

---

## 📂 Project Architecture

```
auth-log-analyzer/
├── analyzer.py             # Core parser, threat evaluator & CLI reporting engine
├── data/
│   └── sample_auth.log     # Test syslog records demonstrating brute-force attempts
├── tests/
│   └── test_analyzer.py    # Unit tests validating parsing, thresholds, & outputs
├── LICENSE                 # MIT License
└── README.md               # Documentation & setup guide
```

---

## 🚀 Quickstart & Usage

### 1. Run Analysis on Sample Log
```bash
# Terminal overview (default threshold: 5)
python analyzer.py data/sample_auth.log

# Custom failure threshold of 3
python analyzer.py data/sample_auth.log -t 3
```

### 2. Export Structured JSON
```bash
python analyzer.py data/sample_auth.log -f json -o incident_report.json
```

### 3. Generate Markdown Incident Summary
```bash
python analyzer.py data/sample_auth.log -f markdown -o report.md
```

---

## 🧪 Running Unit Tests

Run the built-in test suite:
```bash
python -m unittest discover tests -v
```

All test cases validate:
- Accurate extraction of valid and failed logins
- Calculation of threshold breaches
- Correct aggregation of targeted accounts per IP
- Markdown table formatting

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
