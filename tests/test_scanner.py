
import unittest
import tempfile
from pathlib import Path

from scanner.scanner import scan_project, analyze_findings


class TestSecretShield(unittest.TestCase):

    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = scan_project(temp_dir)

            self.assertEqual(result["status"], "PASSED")
            self.assertEqual(result["total_secrets"], 0)

    def test_detect_fake_github_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "app.py"

            fake_token = (
                "ghp_" + "K8vQ2mN7" + "xR4pT9wB" +
                "6cY3hJ5s" + "F1zD8aL0" + "qE2P"
            )

            test_file.write_text(
                f'GITHUB_TOKEN = "{fake_token}"',
                encoding="utf-8"
            )

            result = scan_project(temp_dir)

            self.assertEqual(result["status"], "FAILED")
            self.assertGreater(result["total_secrets"], 0)

    def test_high_risk_classification(self):
        findings = [
            {"RuleID": "github-pat", "File": "app.py"}
        ]

        result = analyze_findings(findings)

        self.assertEqual(result[0]["RiskLevel"], "HIGH")
        self.assertIn("RiskReason", result[0])
        self.assertIn("Remediation", result[0])

    def test_medium_risk_classification(self):
        findings = [
            {"RuleID": "gcp-api-key", "File": "script.js"}
        ]

        result = analyze_findings(findings)

        self.assertEqual(result[0]["RiskLevel"], "MEDIUM")
        self.assertIn("RiskReason", result[0])
        self.assertIn("Remediation", result[0])


if __name__ == "__main__":
    unittest.main()
