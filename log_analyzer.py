#!/usr/bin/env python3
"""Flag rule-based anomalies in local web and authentication logs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ACCESS_LINE = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z]+\s+)?(?P<path>\S+)?(?:\s+HTTP/[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+\S+(?:\s+"[^"]*")?\s+"(?P<user_agent>[^"]*)"'
)
SSH_FAILURE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE
)
PAM_FAILURE = re.compile(
    r"authentication failure;.*?\brhost=(?P<ip>\S+)", re.IGNORECASE
)
GENERIC_FAILURE = re.compile(
    r"(?:failed login|login failed|authentication failed).*?\bfrom\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+)",
    re.IGNORECASE,
)
SCANNER_USER_AGENT = re.compile(
    r"\b(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|"
    r"wpscan|acunetix|nessus)\b",
    re.IGNORECASE,
)
SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.env|\.git(?:/|$)|wp-admin(?:/|$)|phpmyadmin(?:/|$)|"
    r"server-status(?:/|$)|\.DS_Store(?:/|$))",
    re.IGNORECASE,
)


class LogAnalyzerError(Exception):
    """An expected input error suitable for CLI output."""


def parse_logs(text: str, source: str) -> list[dict[str, Any]]:
    """Extract recognizable web requests and authentication failures."""
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        access = ACCESS_LINE.match(line)
        if access:
            events.append(
                {
                    "type": "web_request",
                    "ip": access.group("client"),
                    "path": access.group("path") or "",
                    "status": int(access.group("status")),
                    "user_agent": access.group("user_agent"),
                    "source": source,
                    "line": line_number,
                }
            )
            continue

        failure = SSH_FAILURE.search(line) or INVALID_USER.search(line)
        if failure is None:
            failure = PAM_FAILURE.search(line) or GENERIC_FAILURE.search(line)
        if failure:
            events.append(
                {
                    "type": "auth_failure",
                    "ip": failure.group("ip"),
                    "source": source,
                    "line": line_number,
                }
            )
    return events


def analyze_events(
    events: list[dict[str, Any]],
    auth_threshold: int = 5,
    scan_threshold: int = 10,
) -> dict[str, Any]:
    if auth_threshold < 1 or scan_threshold < 1:
        raise LogAnalyzerError("thresholds must be at least 1")

    failed_auth: Counter[str] = Counter()
    not_found: Counter[str] = Counter()
    scanner_agents: dict[str, set[str]] = defaultdict(set)
    sensitive_paths: dict[str, set[str]] = defaultdict(set)

    for event in events:
        ip = event["ip"]
        if event["type"] == "auth_failure":
            failed_auth[ip] += 1
            continue

        if event["type"] != "web_request":
            continue
        if event["status"] == 401:
            failed_auth[ip] += 1
        if event["status"] == 404:
            not_found[ip] += 1
        agent_match = SCANNER_USER_AGENT.search(event["user_agent"])
        if agent_match:
            scanner_agents[ip].add(agent_match.group(0).lower())
        if SENSITIVE_PATH.search(event["path"]):
            sensitive_paths[ip].add(event["path"])

    findings: list[dict[str, Any]] = []
    for ip, count in sorted(failed_auth.items()):
        if count >= auth_threshold:
            findings.append(
                {
                    "severity": "high",
                    "type": "repeated_auth_failures",
                    "ip": ip,
                    "count": count,
                    "threshold": auth_threshold,
                    "evidence": f"{count} authentication failures",
                    "recommendation": (
                        "Review the account and source activity, verify whether "
                        "the attempts were authorized, and apply appropriate "
                        "account and access protections."
                    ),
                }
            )

    for ip, agents in sorted(scanner_agents.items()):
        findings.append(
            {
                "severity": "medium",
                "type": "scanner_user_agent",
                "ip": ip,
                "count": len(agents),
                "evidence": "Known scanner user-agent marker(s): "
                + ", ".join(sorted(agents)),
                "recommendation": (
                    "Confirm whether the scanner is authorized and correlate "
                    "its requests with other activity."
                ),
            }
        )

    for ip, count in sorted(not_found.items()):
        if count >= scan_threshold:
            findings.append(
                {
                    "severity": "medium",
                    "type": "repeated_not_found",
                    "ip": ip,
                    "count": count,
                    "threshold": scan_threshold,
                    "evidence": f"{count} HTTP 404 responses",
                    "recommendation": (
                        "Review requested paths and surrounding activity for "
                        "automated discovery or a misconfigured client."
                    ),
                }
            )

    for ip, paths in sorted(sensitive_paths.items()):
        if len(paths) >= 3:
            findings.append(
                {
                    "severity": "high",
                    "type": "sensitive_path_probing",
                    "ip": ip,
                    "count": len(paths),
                    "evidence": "Requests for sensitive paths: "
                    + ", ".join(sorted(paths)),
                    "recommendation": (
                        "Check whether any requests succeeded and ensure "
                        "sensitive files and administrative endpoints are not "
                        "publicly exposed."
                    ),
                }
            )

    severity_order = {"high": 0, "medium": 1}
    findings.sort(
        key=lambda item: (
            severity_order[item["severity"]],
            item["ip"],
            item["type"],
        )
    )
    return {
        "summary": {
            "events_analyzed": len(events),
            "authentication_failures": sum(failed_auth.values()),
            "web_requests": sum(event["type"] == "web_request" for event in events),
            "findings": len(findings),
        },
        "findings": findings,
    }


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "Log anomaly summary (rule-based triage)",
        f"Events analyzed: {summary['events_analyzed']}",
        f"Web requests: {summary['web_requests']}",
        f"Authentication failures: {summary['authentication_failures']}",
        f"Findings: {summary['findings']}",
        "",
        "Findings",
    ]
    for finding in report["findings"]:
        lines.append(
            f"- [{finding['severity'].upper()}] {finding['type']} "
            f"from {finding['ip']}: {finding['evidence']}"
        )
        lines.append(f"  Recommendation: {finding['recommendation']}")
    if not report["findings"]:
        lines.append("- No configured anomaly rules were triggered")
    return "\n".join(lines) + "\n"


def read_input(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise LogAnalyzerError(f"Could not read {path}: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze local web and authentication logs for rule-based "
            "anomalies. This tool reads files only; it does not contact hosts."
        )
    )
    parser.add_argument("--log", type=Path, action="append", required=True)
    parser.add_argument(
        "--auth-threshold",
        type=int,
        default=5,
        help="failed authentication events from one IP to flag (default: 5)",
    )
    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=10,
        help="HTTP 404 responses from one IP to flag (default: 10)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.auth_threshold < 1 or args.scan_threshold < 1:
        parser.error("thresholds must be at least 1")
    return args


def main() -> int:
    args = parse_args()
    try:
        events: list[dict[str, Any]] = []
        for path in args.log:
            events.extend(parse_logs(read_input(path), str(path)))
        report = analyze_events(events, args.auth_threshold, args.scan_threshold)
        output = (
            json.dumps(report, indent=2) + "\n"
            if args.format == "json"
            else render_text(report)
        )
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
    except (LogAnalyzerError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
