"""
tests/test_collector.py
-----------------------
Basic unit tests for the Compliance Evidence Collector.
Run with: python -m pytest tests/
"""

import sys
import os

# Add src/ to the path so we can import collector.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from collector import (
    check_user_accounts,
    check_audit_logging,
    check_configuration_settings,
    check_patching,
    run_all_checks,
)


def test_user_accounts_returns_list():
    """check_user_accounts() should return a non-empty list."""
    results = check_user_accounts()
    assert isinstance(results, list)
    assert len(results) > 0


def test_user_account_finding_has_required_keys():
    """Every finding must have the required fields for reporting."""
    required_keys = {"check", "resource", "status", "issue", "nist_control", "severity"}
    results = check_user_accounts()
    for finding in results:
        assert required_keys.issubset(finding.keys())


def test_status_values_are_valid():
    """Status must be either PASS or FAIL — nothing else."""
    results = run_all_checks()
    for finding in results:
        assert finding["status"] in ("PASS", "FAIL")


def test_severity_values_are_valid():
    """Severity must be one of the defined levels."""
    valid_severities = {"INFO", "MEDIUM", "HIGH", "CRITICAL"}
    results = run_all_checks()
    for finding in results:
        assert finding["severity"] in valid_severities


def test_mfa_disabled_account_fails():
    """Any account without MFA should be flagged as FAIL."""
    results = check_user_accounts()
    for finding in results:
        if "MFA not enabled" in finding["issue"]:
            assert finding["status"] == "FAIL"


def test_disabled_logging_fails():
    """Any service with logging disabled should be flagged as FAIL."""
    results = check_audit_logging()
    for finding in results:
        if "DISABLED" in finding["issue"]:
            assert finding["status"] == "FAIL"


def test_run_all_checks_combines_results():
    """run_all_checks() should return more findings than any single check."""
    total   = len(run_all_checks())
    users   = len(check_user_accounts())
    logging = len(check_audit_logging())
    configs = len(check_configuration_settings())
    patches = len(check_patching())
    assert total == users + logging + configs + patches
```

3. Click **File → Save As**
4. Navigate to `compliance-evidence-collector` → `tests` folder
5. File name: `test_collector.py`
6. Save as type: **All Files (*.*)**
7. Click **Save**

---

## Push to GitHub

1. Open **GitHub Desktop**
2. Switch to `compliance-evidence-collector` repo
3. You'll see `test_collector.py` listed as a new file
4. Summary box type:
```
   Add test_collector.py to tests folder