
import subprocess
import json
from pathlib import Path

GITLEAKS_PATH = r"C:\Tools\Gitleaks\gitleaks.exe"


def scan_project(project_path):
    project = Path(project_path).resolve()

    if not project.exists() or not project.is_dir():
        raise ValueError("Invalid project directory")

    result = subprocess.run(
        [
            GITLEAKS_PATH,
            "dir",
            str(project),
            "--report-format", "json",
            "--report-path", "-"
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr or "Gitleaks scan failed")

    findings = json.loads(result.stdout or "[]")

    return {
        "status": "FAILED" if findings else "PASSED",
        "total_secrets": len(findings),
        "findings": findings
    }


if __name__ == "__main__":
    target = input("Enter project folder path: ")

    try:
        report = scan_project(target)
        print(json.dumps(report, indent=4))
    except (ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"Scan error: {error}")
