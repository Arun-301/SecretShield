
import subprocess
import json
import os
from pathlib import Path

GITLEAKS_PATH = os.environ.get(
    "GITLEAKS_PATH",
    r"C:\Tools\Gitleaks\gitleaks.exe" if os.name == "nt" else "gitleaks"
)


def sanitize_findings(findings):
    safe_fields = [
        "RuleID", "Description", "File",
        "StartLine", "EndLine",
        "StartColumn", "EndColumn",
        "Commit", "Author", "Email",
        "Date", "Tags", "Fingerprint"
    ]

    sanitized = []

    for finding in findings:
        safe_finding = {
            field: finding[field]
            for field in safe_fields
            if field in finding
        }

        safe_finding["Secret"] = "[REDACTED]"
        safe_finding["Match"] = "[REDACTED]"

        sanitized.append(safe_finding)

    return sanitized


def analyze_findings(findings):
    analyzed = []

    for finding in findings:
        rule_id = finding.get("RuleID", "").lower()
        file_path = finding.get("File", "").lower()

        if any(term in rule_id for term in [
            "private-key", "aws", "github", "gitlab"
        ]):
            risk_level = "HIGH"
            risk_reason = (
                "Potential credential that may provide access "
                "to external services."
            )
            remediation = (
                "Rotate the credential, remove it from source code, "
                "and store it securely."
            )

        elif "gcp-api-key" in rule_id:
            risk_level = "MEDIUM"
            risk_reason = (
                "Google API key pattern detected. Public Firebase "
                "configuration may trigger this rule."
            )
            remediation = (
                "Validate the key, apply API restrictions, review "
                "usage, and rotate it if sensitive."
            )

        else:
            risk_level = "MEDIUM"
            risk_reason = (
                "A credential-like pattern requires manual validation."
            )
            remediation = (
                "Verify the value. If sensitive, rotate it and remove "
                "it from source code."
            )

        if file_path.endswith((".md", ".txt", ".example")):
            risk_reason += (
                " Documentation or example content requires "
                "contextual review."
            )

        analyzed.append({
            **finding,
            "RiskLevel": risk_level,
            "RiskReason": risk_reason,
            "Remediation": remediation
        })

    return analyzed


def scan_project(project_path, config_path=None):
    project = Path(project_path).resolve()

    if not project.exists() or not project.is_dir():
        raise ValueError("Invalid project directory")

    command = [
        GITLEAKS_PATH,
        "dir",
        str(project),
        "--report-format", "json",
        "--report-path", "-",
        "--redact=100"
    ]

    if config_path:
        config = Path(config_path).resolve()

        if not config.exists() or not config.is_file():
            raise ValueError("Invalid Gitleaks configuration")

        command.extend(["--config", str(config)])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr or "Gitleaks scan failed")

    findings = json.loads(result.stdout or "[]")

    # Step 1: Remove sensitive secret values.
    safe_findings = sanitize_findings(findings)

    # Step 2: Analyze findings and assign risk information.
    safe_findings = analyze_findings(safe_findings)

    return {
        "status": "FAILED" if safe_findings else "PASSED",
        "total_secrets": len(safe_findings),
        "findings": safe_findings
    }


if __name__ == "__main__":
    target = input("Enter project folder path: ")

    try:
        report = scan_project(
            target,
            config_path="gitleaks-test.toml"
        )

        print(json.dumps(report, indent=4))

    except (ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"Scan error: {error}")
