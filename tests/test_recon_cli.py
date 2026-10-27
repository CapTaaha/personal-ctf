import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import recon_cli


NMAP_XML = """\
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapParserTests(unittest.TestCase):
    def test_parses_open_services_only(self):
        services = recon_cli.parse_nmap_xml(NMAP_XML, "fixture.xml")

        self.assertEqual([22, 445], [service["port"] for service in services])
        self.assertEqual("OpenSSH 7.4", services[0]["details"])
        self.assertEqual("127.0.0.1", services[0]["host"])

    def test_rejects_non_nmap_xml(self):
        with self.assertRaisesRegex(recon_cli.ReconError, "not an Nmap report"):
            recon_cli.parse_nmap_xml("<root/>", "fixture.xml")

    def test_rejects_invalid_port(self):
        xml = (
            '<nmaprun><host><ports><port protocol="tcp" portid="bogus">'
            '<state state="open"/></port></ports></host></nmaprun>'
        )
        with self.assertRaisesRegex(recon_cli.ReconError, "invalid port number"):
            recon_cli.parse_nmap_xml(xml, "fixture.xml")


class GobusterParserTests(unittest.TestCase):
    def test_parses_status_and_optional_size(self):
        paths = recon_cli.parse_gobuster_text(
            "/admin (Status: 200) [Size: 123]\n/missing (Status: 404)",
            "gobuster.txt",
        )

        self.assertEqual(
            [
                {
                    "path": "/admin",
                    "status": 200,
                    "size": 123,
                    "source": "gobuster.txt",
                },
                {
                    "path": "/missing",
                    "status": 404,
                    "size": None,
                    "source": "gobuster.txt",
                },
            ],
            paths,
        )


class ReportTests(unittest.TestCase):
    def test_includes_defensive_review_items(self):
        services = recon_cli.parse_nmap_xml(NMAP_XML, "fixture.xml")
        report = recon_cli.build_report(services, [])
        text = recon_cli.render_text(report)

        self.assertEqual(2, report["summary"]["defensive_review_items"])
        self.assertIn("SMB is reachable", text)
        self.assertIn("legacy OpenSSH", text)
        self.assertEqual(report, json.loads(json.dumps(report)))


class ScanSafetyTests(unittest.TestCase):
    def test_default_scan_uses_localhost_and_common_ports(self):
        with patch("sys.argv", ["recon_cli.py", "--scan", "--confirm-local-scan"]):
            args = recon_cli.parse_args()

        self.assertEqual("127.0.0.1", args.target)
        self.assertEqual(recon_cli.DEFAULT_SCAN_PORTS, args.ports)

    def test_custom_ports_override_defaults(self):
        with patch(
            "sys.argv",
            [
                "recon_cli.py",
                "--scan",
                "--ports",
                "8080,8443",
                "--confirm-local-scan",
            ],
        ):
            args = recon_cli.parse_args()

        self.assertEqual("8080,8443", args.ports)

    def test_rejects_non_loopback_target(self):
        with self.assertRaisesRegex(recon_cli.ReconError, "loopback"):
            recon_cli.resolve_loopback_target("192.0.2.1")

    def test_accepts_loopback_target(self):
        self.assertEqual("127.0.0.1", recon_cli.resolve_loopback_target("127.0.0.1"))

    def test_scan_requires_explicit_confirmation(self):
        with patch("sys.argv", ["recon_cli.py", "--scan"]):
            with self.assertRaises(SystemExit) as error:
                recon_cli.parse_args()

        self.assertEqual(2, error.exception.code)

    def test_cli_writes_json_report_from_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            input_path = temp / "scan.xml"
            output_path = temp / "report.json"
            input_path.write_text(NMAP_XML, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / "recon_cli.py"),
                    "--nmap-xml",
                    str(input_path),
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
            self.assertEqual(2, report["summary"]["open_services"])


if __name__ == "__main__":
    unittest.main()
