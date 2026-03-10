# Compliance Evidence Collector

A Python automation tool that simulates security compliance auditing mapped to **NIST SP 800-53 Rev 5** controls. Designed to demonstrate how cybersecurity teams automate evidence collection for audits, reducing manual effort and human error.

---

## What It Does

This tool runs a series of automated security checks across four compliance domains and generates structured evidence reports in **JSON** and **CSV** format:

| Check | NIST Controls |
|---|---|
| User Account Review (MFA, inactive accounts) | AC-2, IA-2 |
| Audit Logging Status | AU-2, AU-9 |
| Security Configuration Baseline | CM-6, CM-7 |
| Patch & Vulnerability Status | SI-2 |

---

## Why This Matters

Manual compliance evidence collection is slow, inconsistent, and error-prone. Automation ensures:
- **Consistent** findings every audit cycle
- **Timestamped** evidence with structured output for auditors
- **Scalable** — add new checks without changing the reporting engine
- **Traceable** — every finding maps to a specific NIST control

---

## Project Structure

```
compliance-evidence-collector/
├── src/
│   └── collector.py          # Core logic: checks + report generation
├── tests/
│   └── test_collector.py     # Unit tests (pytest)
├── sample_output/            # Reports saved here at runtime (git-ignored)
├── docs/
│   └── nist_control_map.md   # Control reference documentation
├── .github/
│   └── workflows/
│       └── ci.yml            # GitHub Actions: auto-runs tests on every push
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/compliance-evidence-collector.git
cd compliance-evidence-collector
```

### 2. Run the Collector
```bash
python src/collector.py
```

### 3. View Reports
Reports are saved to `sample_output/` in both JSON and CSV format.

---

## Sample Output

```
============================================================
  COMPLIANCE EVIDENCE COLLECTION — SUMMARY
============================================================
  Total Checks : 17
  PASS         : 9
  FAIL         : 8
  CRITICAL     : 1
  HIGH         : 3
============================================================

  FAILURES REQUIRING REMEDIATION:
------------------------------------------------------------
  [HIGH    ] AC-2 | IA-2 | svc_backup
             Issue: MFA not enabled; Inactive for 90 days

  [CRITICAL] SI-2 | legacy-server
             Issue: Last patched 120 days ago; 5 critical vulnerabilities unpatched
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests validate:
- All findings contain required fields
- Status values are always `PASS` or `FAIL`
- Severity levels are always one of: `INFO`, `MEDIUM`, `HIGH`, `CRITICAL`
- MFA-disabled accounts are always flagged as FAIL
- Logging-disabled services are always flagged as FAIL

---

## CI/CD Pipeline

This project includes a **GitHub Actions** workflow that automatically:
1. Runs all unit tests on every `push` or `pull request` to `main`
2. Executes a smoke test of the full collector

Status badge will appear here once connected to GitHub Actions.

---

## Roadmap

- [ ] **Phase 2:** Connect to live AWS environment via `boto3` (IAM, S3, CloudTrail, Config)
- [ ] **Phase 3:** Deploy as an AWS Lambda function on a scheduled trigger
- [ ] **Phase 4:** Push findings to a JupiterOne graph or Jira ticket automatically
- [ ] **Phase 5:** Add HTML dashboard output with severity charts

---

## NIST 800-53 Control Reference

| Control ID | Name | Description |
|---|---|---|
| AC-2 | Account Management | Manage system accounts including creation, activation, review, and removal |
| AU-2 | Audit Events | Identify events requiring audit logging |
| AU-9 | Protection of Audit Info | Protect audit logs from unauthorized access and modification |
| CM-6 | Configuration Settings | Establish and document configuration settings for IT products |
| CM-7 | Least Functionality | Configure systems to provide only essential capabilities |
| IA-2 | Identification & Authentication | Uniquely identify and authenticate organizational users |
| SI-2 | Flaw Remediation | Identify, report, and correct information system flaws |

---

## Author

**Kareem Martinez**  
Cybersecurity Professional | DOE Q Clearance | CompTIA Sec+ | Net+ | Linux Essentials  
Pursuing: CCSP · CISSP · AWS Certified Cloud Practitioner

---

## License

MIT License — free to use, modify, and build upon.
