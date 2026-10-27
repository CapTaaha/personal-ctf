import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import log_analyzer


class LogParsingTests(unittest.TestCase):
    def test_parses_apache_access_and_ssh_auth_failure(self):
        events = log_analyzer.parse_logs(
            '203.0.113.8 - - [27/Oct/2026:10:00:00 +0000] '
            '"GET /.env HTTP/1.1" 404 123 "-" "curl/8.0"\n'
            "Oct 27 10:01:00 host sshd[123]: Failed password for "
            "invalid user admin from 203.0.113.9 port 22 ssh2",
            "sample.log",
        )

        self.assertEqual(["web_request", "auth_failure"], [e["type"] for e in events])
        self.assertEqual("203.0.113.8", events[0]["ip"])
        self.assertEqual(404, events[0]["status"])
        self.assertEqual("203.0.113.9", events[1]["ip"])

    def test_ignores_unrecognized_lines(self):
        self.assertEqual([], log_analyzer.parse_logs("service started", "app.log"))


class AnalysisTests(unittest.TestCase):
    def test_flags_auth_failures_scanners_and_sensitive_path_probes(self):
        events = [
            {"type": "auth_failure", "ip": "192.0.2.10"}
            for _ in range(5)
        ]
        events.extend(
            [
                {
                    "type": "web_request",
                    "ip": "192.0.2.11",
                    "path": path,
                    "status": 404,
                    "user_agent": "sqlmap/1.0",
                }
                for path in ("/.env", "/.git/config", "/wp-admin")
            ]
        )

        report = log_analyzer.analyze_events(events)
        types = {finding["type"] for finding in report["findings"]}

        self.assertEqual(
            {
                "repeated_auth_failures",
                "scanner_user_agent",
                "sensitive_path_probing",
            },
            types,
        )
        self.assertEqual(8, report["summary"]["events_analyzed"])
        self.assertEqual(
            report,
            json.loads(json.dumps(report)),
        )

    def test_thresholds_do_not_flag_below_limit(self):
        events = [
            {
                "type": "web_request",
                "ip": "192.0.2.1",
                "path": "/missing",
                "status": 404,
                "user_agent": "browser",
            }
            for _ in range(9)
        ]
        self.assertEqual([], log_analyzer.analyze_events(events)["findings"])

    def test_rejects_nonpositive_threshold(self):
        with self.assertRaisesRegex(log_analyzer.LogAnalyzerError, "at least 1"):
            log_analyzer.analyze_events([], auth_threshold=0)


class CliTests(unittest.TestCase):
    def test_cli_writes_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            log_path = temp / "auth.log"
            output_path = temp / "report.json"
            log_path.write_text(
                "\n".join(
                    f"Failed password for user from 203.0.113.5 port 22 ssh2"
                    for _ in range(5)
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "log_analyzer.py"),
                    "--log",
                    str(log_path),
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(1, report["summary"]["findings"])


if __name__ == "__main__":
    unittest.main()
