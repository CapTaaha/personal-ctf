import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import hash_identifier


class HashIdentifierTests(unittest.TestCase):
    def test_identifies_ambiguous_hex_digest_candidates(self):
        self.assertEqual(
            ["MD5", "MD4", "NTLM"],
            hash_identifier.identify("d41d8cd98f00b204e9800998ecf8427e"),
        )

    def test_identifies_bcrypt_prefix(self):
        self.assertEqual(
            ["bcrypt"], hash_identifier.identify("$2b$12$example")
        )

    def test_does_not_overclaim_for_base64(self):
        self.assertIn(
            "cannot identify it",
            hash_identifier.identify("YWJjZA==")[0],
        )

    def test_reports_unrecognized_input(self):
        self.assertIn(
            "Unrecognized format",
            hash_identifier.identify("not a hash")[0],
        )

    def test_cli_prints_candidates(self):
        result = subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / "hash_identifier.py"),
                "d41d8cd98f00b204e9800998ecf8427e",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("- MD5", result.stdout)
        self.assertIn("- NTLM", result.stdout)


if __name__ == "__main__":
    unittest.main()
