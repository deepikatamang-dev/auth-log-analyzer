"""
Automated Authentication Log Analyzer & Incident Detection Tool
Author: Deepika Tamang
License: MIT
Description:
    Parses standard Linux auth/secure logs, detects potential brute-force attacks
    and suspicious credential stuffing patterns, and outputs structured summary reports.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class AuthEvent:
    """Represents a single parsed authentication event from auth.log."""
    timestamp: str
    hostname: str
    process: str
    pid: Optional[int]
    status: str  # 'SUCCESS' or 'FAILED'
    user: str
    ip: str
    port: Optional[int]
    is_invalid_user: bool = False


@dataclass
class ThreatReport:
    """Consolidated threat detection statistics and flagged incidents."""
    total_events: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    flagged_ips: Dict[str, Dict] = field(default_factory=dict)
    targeted_users: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    unique_attacker_ips: int = 0


class AuthLogAnalyzer:
    """
    Parses syslog/auth.log entries, tracks authentication attempts,
    and identifies anomalous or malicious activity based on configurable thresholds.
    """

    # Matches standard sshd log formats:
    # Accepted publickey for deepika from 192.168.1.50 port 52341 ssh2
    # Failed password for invalid user admin from 203.0.113.45 port 41201 ssh2
    # Failed password for root from 203.0.113.45 port 41210 ssh2
    SSHD_ACCEPTED_PATTERN = re.compile(
        r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Accepted\s+(?P<auth_type>\S+)\s+"
        r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
    )

    SSHD_FAILED_PATTERN = re.compile(
        r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Failed\s+password\s+for\s+"
        r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+"
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)"
    )

    def __init__(self, failure_threshold: int = 5):
        """
        :param failure_threshold: Number of failed attempts from a single IP to trigger alert.
        """
        self.failure_threshold = failure_threshold
        self.events: List[AuthEvent] = []
        self.ip_failures: Dict[str, List[AuthEvent]] = defaultdict(list)
        self.ip_successes: Dict[str, List[AuthEvent]] = defaultdict(list)

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """Parses a single line of log text into an AuthEvent."""
        line = line.strip()
        if not line:
            return None

        # Check Accepted
        m = self.SSHD_ACCEPTED_PATTERN.match(line)
        if m:
            gd = m.groupdict()
            ts = f"{gd['month']} {gd['day']} {gd['time']}"
            return AuthEvent(
                timestamp=ts,
                hostname=gd["hostname"],
                process="sshd",
                pid=int(gd["pid"]),
                status="SUCCESS",
                user=gd["user"],
                ip=gd["ip"],
                port=int(gd["port"]),
                is_invalid_user=False,
            )

        # Check Failed
        m = self.SSHD_FAILED_PATTERN.match(line)
        if m:
            gd = m.groupdict()
            ts = f"{gd['month']} {gd['day']} {gd['time']}"
            return AuthEvent(
                timestamp=ts,
                hostname=gd["hostname"],
                process="sshd",
                pid=int(gd["pid"]),
                status="FAILED",
                user=gd["user"],
                ip=gd["ip"],
                port=int(gd["port"]),
                is_invalid_user=bool(gd.get("invalid")),
            )

        return None

    def analyze_file(self, file_path: str) -> ThreatReport:
        """Reads a log file line by line and generates a ThreatReport."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    self.events.append(event)
                    if event.status == "FAILED":
                        self.ip_failures[event.ip].append(event)
                    else:
                        self.ip_successes[event.ip].append(event)

        return self.generate_report()

    def generate_report(self) -> ThreatReport:
        """Evaluates collected events against threat thresholds."""
        report = ThreatReport()
        report.total_events = len(self.events)

        for ip, fails in self.ip_failures.items():
            report.failed_logins += len(fails)
            for event in fails:
                report.targeted_users[event.user] += 1

            if len(fails) >= self.failure_threshold:
                unique_users = sorted(list(set(e.user for e in fails)))
                success_count = len(self.ip_successes.get(ip, []))
                first_seen = fails[0].timestamp
                last_seen = fails[-1].timestamp

                report.flagged_ips[ip] = {
                    "fail_count": len(fails),
                    "success_count": success_count,
                    "first_attempt": first_seen,
                    "last_attempt": last_seen,
                    "targeted_usernames": unique_users,
                    "severity": "CRITICAL" if len(fails) >= (self.failure_threshold * 2) else "HIGH",
                    "attack_type": "Brute Force / Credential Stuffing"
                    if len(unique_users) > 1
                    else "Targeted Password Guessing",
                }

        for ip, succs in self.ip_successes.items():
            report.successful_logins += len(succs)

        report.unique_attacker_ips = len(report.flagged_ips)
        report.targeted_users = dict(
            sorted(report.targeted_users.items(), key=lambda x: x[1], reverse=True)
        )
        return report

    def render_markdown(self, report: ThreatReport) -> str:
        """Formats the report into a clean, human-readable Markdown summary."""
        lines = [
            "# 🛡️ Security Incident & Threat Analysis Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Threshold:** {self.failure_threshold} failed attempts",
            "",
            "## 📊 Executive Summary",
            f"- **Total Authentication Events Analyzed:** `{report.total_events}`",
            f"- **Successful Authentications:** `{report.successful_logins}`",
            f"- **Failed Authentications:** `{report.failed_logins}`",
            f"- **High-Risk Flagged IPs:** `{report.unique_attacker_ips}`",
            "",
            "## 🚨 Flagged Suspicious IP Addresses",
        ]

        if not report.flagged_ips:
            lines.append("_No IP addresses exceeded the failure threshold. All systems normal._")
        else:
            lines.append("| IP Address | Failures | Severity | Attack Type | Targeted Accounts |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for ip, data in report.flagged_ips.items():
                users = ", ".join(f"`{u}`" for u in data["targeted_usernames"][:5])
                if len(data["targeted_usernames"]) > 5:
                    users += f" (+{len(data['targeted_usernames']) - 5} more)"
                lines.append(
                    f"| `{ip}` | **{data['fail_count']}** | `{data['severity']}` | {data['attack_type']} | {users} |"
                )

        lines.extend([
            "",
            "## 🎯 Most Frequently Targeted Accounts",
        ])
        if not report.targeted_users:
            lines.append("_No failed attempts recorded._")
        else:
            lines.append("| Username | Failed Attempt Count |")
            lines.append("| :--- | :--- |")
            for user, count in list(report.targeted_users.items())[:8]:
                lines.append(f"| `{user}` | **{count}** |")

        lines.append("")
        lines.append("---")
        lines.append("*Report generated automatically by `auth-log-analyzer` (Deepika Tamang)*")
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Automated Security Log Monitor & Incident Detection CLI"
    )
    parser.add_argument("log_file", help="Path to auth.log file to analyze")
    parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        default=5,
        help="Number of failed attempts to trigger incident alert (default: 5)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format: text, json, or markdown (default: text)",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=str,
        default=None,
        help="Optional output file destination",
    )

    args = parser.parse_args()

    analyzer = AuthLogAnalyzer(failure_threshold=args.threshold)
    try:
        report = analyzer.analyze_file(args.log_file)
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        output = json.dumps(asdict(report), indent=2)
    elif args.format == "markdown":
        output = analyzer.render_markdown(report)
    else:
        # Standard CLI Text Output
        lines = [
            "============================================================",
            " [AUTH LOG SECURITY INCIDENT REPORT]",
            "============================================================",
            f" Total Events:       {report.total_events}",
            f" Successful Logins:  {report.successful_logins}",
            f" Failed Logins:      {report.failed_logins}",
            f" Flagged IPs (>={args.threshold} fails): {report.unique_attacker_ips}",
            "------------------------------------------------------------",
        ]
        if report.flagged_ips:
            lines.append(" FLAGGED INCIDENTS:")
            for ip, d in report.flagged_ips.items():
                lines.append(
                    f"  [!] {ip:<15} | Severity: {d['severity']:<8} | Fails: {d['fail_count']:<3} | Type: {d['attack_type']}"
                )
                lines.append(f"      Users: {', '.join(d['targeted_usernames'])}")
        else:
            lines.append(" No threats detected above threshold.")
        lines.append("============================================================")
        output = "\n".join(lines)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
