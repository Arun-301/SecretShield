
import unittest
import tempfile
from pathlib import Path

from scanner.scanner import scan_project


class TestSecretShield(unittest.TestCase):

    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = scan_project(temp_dir)

            self.assertEqual(result["status"], "PASSED")
            self.assertEqual(result["total_secrets"], 0)

    def test_detect_fake_github_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "app.py"

            test_file.write_text(
                'GITHUB_TOKEN = "ghp_K8vQ2mN7xR4pT9wB6cY3hJ5sF1zD8aL0qE2P"',
                encoding="utf-8"
            )

            result = scan_project(temp_dir)

            self.assertEqual(result["status"], "FAILED")
            self.assertGreater(result["total_secrets"], 0)


if __name__ == "__main__":
    unittest.main()
