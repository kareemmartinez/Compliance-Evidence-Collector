"""
collector.py
------------
Compliance Evidence Collector — Local Mode
Simulates querying a system for security configuration data
and maps findings to NIST 800-53 controls.

Author: Kareem Martinez
Purpose: Demonstrates Python automation for cybersecurity compliance auditing.
"""

import json
import csv
import os
import datetime


NIST_CONTROLS = {
    "AC-2":  "Account Management",
    "AC-3":  "Access Enforcement",
    "AU-2":  "Audit Events",
    "AU-9":  "Protection of Audit Information",
    "CM-6":  "Configuration Settings",
    "CM-7":  "Least Functionality",
    "IA-2":  "Identification and Authentication",
    "IA-5":  "Authenticator Management",
    "SC-7":  "Boundary Protection",
    "SI-2":  "Flaw Remediation",
}


def check_user_accounts():
    findings = []
    mock_accounts = [
        {"username": "admin",       "mfa_enabled": True,  "last_login_days": 2,   "status": "active"},
        {"username": "svc_backup",  "mfa_enabled": False, "last_login_days": 90,  "status": "active"},
        {"username": "jsmith",      "mfa_enabled": True,  "last_login_days": 5,   "status": "active"},
        {"username": "old_account", "mfa_enabled": False, "last_login_days": 200, "status": "active"},
    ]
    for account in mock_accounts:
        issues = []
        if not account["mfa_enabled"]:
            issues.append("MFA not enabled")
        if account["last_login_days"] >= 90:
            issues.append(f"Inactive for {account['last_login_days']} days")
        status = "FAIL" if issues else "PASS"
        findings.append({
            "check":        "User Account Review",
            "resource":     account["username"],
            "status":       status,
            "issue":        "; ".join(issues) if issues else "None",
            "nist_control": "AC-2 | IA-2",
            "severity":     "HIGH" if status == "FAIL" else "INFO",
        })
    return findings


def check_audit_logging():
    findings = []
    mock_services = [
        {"service": "CloudTrail",    "logging_enabled": True,  "log_validation": True},
        {"service": "S3_Access_Log", "logging_enabled": False, "log_validation": False},
        {"service": "VPC_FlowLogs",  "logging_enabled": True,  "log_validation": False},
        {"service": "Config",        "logging_enabled": True,  "log_validation": True},
    ]
    for svc in mock_services:
        issues = []
        if not svc["logging_enabled"]:
            issues.append("Logging is DISABLED")
        if not svc["log_validation"]:
            issues.append("Log integrity validation not enabled")
        status = "FAIL" if issues else "PASS"
        findings.append({
            "check":        "Audit Logging Review",
            "resource":     svc["service"],
            "status":       status,
            "issue":        "; ".join(issues) if issues else "None",
            "nist_control": "AU-2 | AU-9",
            "severity":     "HIGH" if "DISABLED" in " ".join(issues) else ("MEDIUM" if issues else "INFO"),
        })
    return findings


def check_configuration_settings():
    findings = []
    mock_configs = [
        {"setting": "Default SSH port (22) exposed to 0.0.0.0/0", "compliant": False},
        {"setting": "Root login disabled",                          "compliant": True},
        {"setting": "Password complexity policy enforced",          "compliant": True},
        {"setting": "Unnecessary services disabled (FTP, Telnet)",  "compliant": False},
        {"setting": "Auto-patching enabled",                        "compliant": True},
    ]
    for cfg in mock_configs:
        status = "PASS" if cfg["compliant"] else "FAIL"
        findings.append({
            "check":        "Configuration Baseline",
            "resource":     cfg["setting"],
            "status":       status,
            "issue":        "Non-compliant configuration detected" if not cfg["compliant"] else "None",
            "nist_control": "CM-6 | CM-7",
            "severity":     "MEDIUM" if not cfg["compliant"] else "INFO",
        })
    return findings


def check_patching():
    findings = []
    mock_systems = [
        {"hostname": "web-server-01", "days_since_patch": 10,  "critical_vulns": 0},
        {"hostname": "db-server-01",  "days_since_patch": 45,  "critical_vulns": 2},
        {"hostname": "app-server-01", "days_since_patch": 7,   "critical_vulns": 0},
        {"hostname": "legacy-server", "days_since_patch": 120, "critical_vulns": 5},
    ]
    for system in mock_systems:
        issues = []
        if system["days_since_patch"] > 30:
            issues.append(f"Last patched {system['days_since_patch']} days ago")
        if system["critical_vulns"] > 0:
            issues.append(f"{system['critical_vulns']} critical vulnerabilities unpatched")
        status = "FAIL" if issues else "PASS"
        if system["critical_vulns"] >= 3:
            severity = "CRITICAL"
        elif system["critical_vulns"] > 0:
            severity = "HIGH"
        elif issues:
            severity = "MEDIUM"
        else:
            severity = "INFO"
        findings.append({
            "check":        "Patch & Vulnerability Status",
            "resource":     system["hostname"],
            "status":       status,
            "issue":        "; ".join(issues) if issues else "None",
            "nist_control": "SI-2",
            "severity":     severity,
        })
    return findings


def run_all_checks():
    print("\n[+] Starting compliance evidence collection...\n")
    all_findings = []
    all_findings.extend(check_user_accounts())
    all_findings.extend(check_audit_logging())
    all_findings.extend(check_configuration_settings())
    all_findings.extend(check_patching())
    print(f"[+] Collection complete. Total findings: {len(all_findings)}")
    return all_findings


def generate_json_report(findings, output_dir="sample_output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(output_dir, f"compliance_report_{timestamp}.json")
    report = {
        "report_metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "tool":         "Compliance Evidence Collector v1.0",
            "author":       "Kareem Martinez",
            "framework":    "NIST SP 800-53 Rev 5",
            "total_checks": len(findings),
            "pass_count":   sum(1 for f in findings if f["status"] == "PASS"),
            "fail_count":   sum(1 for f in findings if f["status"] == "FAIL"),
        },
        "findings": findings,
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] JSON report saved: {filename}")
    return filename


def generate_csv_report(findings, output_dir="sample_output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename   = os.path.join(output_dir, f"compliance_report_{timestamp}.csv")
    fieldnames = ["check", "resource", "status", "issue", "nist_control", "severity"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
    print(f"[+] CSV report saved: {filename}")
    return filename


def print_summary(findings):
    pass_count     = sum(1 for f in findings if f["status"] == "PASS")
    fail_count     = sum(1 for f in findings if f["status"] == "FAIL")
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count     = sum(1 for f in findings if f["severity"] == "HIGH")
    print("\n" + "="*60)
    print("  COMPLIANCE EVIDENCE COLLECTION — SUMMARY")
    print("="*60)
    print(f"  Total Checks : {len(findings)}")
    print(f"  PASS         : {pass_count}")
    print(f"  FAIL         : {fail_count}")
    print(f"  CRITICAL     : {critical_count}")
    print(f"  HIGH         : {high_count}")
    print("="*60)
    print("\n  FAILURES REQUIRING REMEDIATION:")
    print("-"*60)
    for f in findings:
        if f["status"] == "FAIL":
            print(f"  [{f['severity']:8}] {f['nist_control']} | {f['resource']}")
            print(f"             Issue: {f['issue']}\n")
    print("="*60 + "\n")


if __name__ == "__main__":
    findings = run_all_checks()
    print_summary(findings)
    generate_json_report(findings)
    generate_csv_report(findings)
    print("[+] Evidence collection complete. Reports saved to sample_output/\n")
