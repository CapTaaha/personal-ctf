#!/usr/bin/env python3
"""Parse authorized Nmap and Gobuster output into a defensive triage report."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


GOBUSTER_LINE = re.compile(
    r"^\s*(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?"
)
DEFAULT_SCAN_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,"
    "1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017"
)


class ReconError(Exception):
    """An expected input or scanning error suitable for CLI output."""


def parse_nmap_xml(xml_text: str, source: str) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise ReconError(f"{source}: invalid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ReconError(f"{source}: XML document is not an Nmap report")

    services: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addresses = [
            address.get("addr", "")
            for address in host.findall("address")
            if address.get("addr")
        ]
        address_text = ", ".join(addresses) or "unknown host"
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = port.get("portid", "")
            if not port_id.isdecimal() or not 1 <= int(port_id) <= 65535:
                raise ReconError(f"{source}: invalid port number {port_id!r}")

            service = port.find("service")
            details = ""
            service_name = "unknown"
            if service is not None:
                service_name = service.get("name", service_name)
                details = " ".join(
                    part
                    for part in (
                        service.get("product", ""),
                        service.get("version", ""),
                        service.get("extrainfo", ""),
                    )
                    if part
                )

            services.append(
                {
                    "host": address_text,
                    "port": int(port_id),
                    "protocol": port.get("protocol", "unknown"),
                    "service": service_name,
                    "details": details,
                    "source": source,
                }
            )
    return services


def parse_gobuster_text(text: str, source: str) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = GOBUSTER_LINE.match(line)
        if match is None:
            continue
        paths.append(
            {
                "path": match.group("path"),
                "status": int(match.group("status")),
                "size": int(match.group("size")) if match.group("size") else None,
                "source": source,
            }
        )
    return paths


def resolve_loopback_target(target: str) -> str:
    try:
        addresses = [ipaddress.ip_address(target)]
    except ValueError:
        try:
            resolved = socket.getaddrinfo(
                target, None, type=socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise ReconError(f"Could not resolve scan target {target!r}: {exc}") from exc
        addresses = list(
            dict.fromkeys(ipaddress.ip_address(item[4][0]) for item in resolved)
        )

    if not addresses:
        raise ReconError(f"Scan target {target!r} did not resolve to an address")
    if any(not address.is_loopback for address in addresses):
        raise ReconError(
            "Active scans are limited to localhost/loopback targets; "
            f"{target!r} resolved to a non-loopback address"
        )
    return str(addresses[0])


def validate_ports(value: str) -> str:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item.isdecimal():
            raise argparse.ArgumentTypeError(
                "ports must be a comma-separated list of explicit numbers"
            )
        port = int(item)
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("provide at least one port")
    if len(ports) > 128:
        raise argparse.ArgumentTypeError("provide no more than 128 ports per scan")
    return ",".join(str(port) for port in ports)


def run_local_nmap_scan(target: str, ports: str) -> str:
    resolved_target = resolve_loopback_target(target)
    nmap = shutil.which("nmap")
    if nmap is None:
        for candidate in (
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
            Path(r"C:\Program Files\Nmap\nmap.exe"),
        ):
            if candidate.is_file():
                nmap = str(candidate)
                break
    if nmap is None:
        raise ReconError("Nmap was not found on PATH; install Nmap to use --scan")

    command = [
        nmap,
        "-sV",
        "--version-light",
        "-T3",
        "-oX",
        "-",
        "-p",
        ports,
        resolved_target,
    ]
    if ipaddress.ip_address(resolved_target).version == 6:
        command.insert(1, "-6")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReconError("Nmap scan timed out after 120 seconds") from exc
    except OSError as exc:
        raise ReconError(f"Could not start Nmap: {exc}") from exc

    if result.returncode != 0:
        message = result.stderr.strip() or f"Nmap exited with status {result.returncode}"
        raise ReconError(f"Nmap scan failed: {message}")
    return result.stdout


def make_findings(services: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for service in services:
        port = service["port"]
        details = service["details"]
        if port in (139, 445):
            findings.append(
                {
                    "priority": "Review",
                    "title": f"SMB is reachable on port {port}",
                    "host": service["host"],
                    "evidence": f"{service['protocol']}/{port} {service['service']}",
                    "note": (
                        "Confirm this service is required and restrict access to "
                        "trusted networks; review SMB configuration and patch status."
                    ),
                }
            )

        if service["service"].lower() in {"ssh", "sshv1"} and details:
            old_banner = re.search(
                r"openssh[_ /-](?:[1-7])(?:\.|p)", details, re.IGNORECASE
            )
            if old_banner:
                findings.append(
                    {
                        "priority": "Review",
                        "title": "SSH banner may indicate a legacy OpenSSH release",
                        "host": service["host"],
                        "evidence": details,
                        "note": (
                            "Verify the installed package against vendor support "
                            "information and plan an update if it is out of support."
                        ),
                    }
                )
    return findings


def build_report(
    services: list[dict[str, Any]], paths: list[dict[str, Any]]
) -> dict[str, Any]:
    findings = make_findings(services)
    return {
        "summary": {
            "open_services": len(services),
            "web_paths": len(paths),
            "defensive_review_items": len(findings),
        },
        "services": services,
        "web_paths": paths,
        "findings": findings,
    }


def render_text(report: dict[str, Any]) -> str:
    lines = [
        "Recon summary (defensive triage)",
        f"Open services: {report['summary']['open_services']}",
        f"Web paths: {report['summary']['web_paths']}",
        f"Items to review: {report['summary']['defensive_review_items']}",
        "",
        "Services",
    ]
    if report["services"]:
        for service in report["services"]:
            details = f" — {service['details']}" if service["details"] else ""
            lines.append(
                f"- {service['host']} {service['protocol']}/{service['port']} "
                f"{service['service']}{details}"
            )
    else:
        lines.append("- None found")

    lines.extend(["", "Web paths"])
    if report["web_paths"]:
        for path in report["web_paths"]:
            size = f", {path['size']} bytes" if path["size"] is not None else ""
            lines.append(f"- {path['path']} (HTTP {path['status']}{size})")
    else:
        lines.append("- None found")

    lines.extend(["", "Defensive review"])
    if report["findings"]:
        for finding in report["findings"]:
            lines.extend(
                [
                    f"- [{finding['priority']}] {finding['title']} ({finding['host']})",
                    f"  Evidence: {finding['evidence']}",
                    f"  Note: {finding['note']}",
                ]
            )
    else:
        lines.append("- No rule-based review items found")
    return "\n".join(lines) + "\n"


def read_input(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ReconError(f"Could not read {path}: {exc}") from exc


def write_output(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ReconError(f"Could not write {path}: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Parse authorized Nmap XML and Gobuster text output into a defensive "
            "triage report. Parsing is the default; active scanning is opt-in."
        )
    )
    parser.add_argument("--nmap-xml", type=Path, action="append", default=[])
    parser.add_argument("--gobuster", type=Path, action="append", default=[])
    parser.add_argument(
        "--scan",
        action="store_true",
        help="explicitly run Nmap against a localhost/loopback target",
    )
    parser.add_argument(
        "--target",
        help="localhost/loopback address or hostname (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--ports",
        type=validate_ports,
        help=(
            "comma-separated port numbers for --scan (maximum 128; "
            "default: common service ports)"
        ),
    )
    parser.add_argument(
        "--confirm-local-scan",
        action="store_true",
        help="confirm that the requested scan is authorized and local",
    )
    parser.add_argument("--format", choices=("text", "json", "both"), default="text")
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "write report here; with --format both, writes <name>.txt and <name>.json"
        ),
    )
    args = parser.parse_args()

    if args.scan:
        if not args.confirm_local_scan:
            parser.error("--scan requires --confirm-local-scan")
        args.target = args.target or "127.0.0.1"
        args.ports = args.ports or validate_ports(DEFAULT_SCAN_PORTS)
    elif args.target or args.ports or args.confirm_local_scan:
        parser.error("--target, --ports, and --confirm-local-scan require --scan")

    if not (args.scan or args.nmap_xml or args.gobuster):
        parser.error("provide --nmap-xml, --gobuster, or explicitly request --scan")
    if args.format == "both" and args.output is None:
        parser.error("--format both requires --output")
    return args


def main() -> int:
    args = parse_args()
    services: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []

    try:
        for file_path in args.nmap_xml:
            services.extend(
                parse_nmap_xml(read_input(file_path), str(file_path))
            )
        for file_path in args.gobuster:
            paths.extend(
                parse_gobuster_text(read_input(file_path), str(file_path))
            )
        if args.scan:
            scan_xml = run_local_nmap_scan(args.target, args.ports)
            services.extend(parse_nmap_xml(scan_xml, "local Nmap scan"))
    except ReconError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = build_report(services, paths)
    text = render_text(report)
    json_text = json.dumps(report, indent=2) + "\n"

    try:
        if args.format == "text":
            if args.output:
                write_output(args.output, text)
            else:
                sys.stdout.write(text)
        elif args.format == "json":
            if args.output:
                write_output(args.output, json_text)
            else:
                sys.stdout.write(json_text)
        else:
            text_path = args.output.with_suffix(".txt")
            json_path = args.output.with_suffix(".json")
            write_output(text_path, text)
            write_output(json_path, json_text)
    except ReconError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
