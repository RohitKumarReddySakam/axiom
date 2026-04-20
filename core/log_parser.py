"""
Multi-format Log Parser
Handles syslog, Apache, JSON, Windows Event, firewall, and SSH auth logs
"""
import re
import json
import gzip
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Regex patterns for different log formats
PATTERNS = {
    "syslog": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"
        r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+(?P<message>.+)"
    ),
    "apache_access": re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]+)")?\s*(?:"(?P<ua>[^"]+)")?'
    ),
    "ssh_auth": re.compile(
        r"(?P<ts>\w+ \d+ \d+:\d+:\d+).*?"
        r"(?P<action>Failed password|Accepted password|Invalid user|Disconnected)"
        r"(?:\s+for\s+(?:invalid user\s+)?(?P<user>\S+))?"
        r"(?:\s+from\s+(?P<ip>[\d\.]+))?(?:\s+port\s+(?P<port>\d+))?"
    ),
    "json": None,  # handled separately
    "windows": re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*?EventID:\s*(?P<event_id>\d+)"
        r".*?(?:User|Account):\s*(?P<user>\S+)"
    ),
    "firewall": re.compile(
        r"(?P<ts>[\w\s:]+)\s+(?:DENY|ACCEPT|DROP|BLOCK)\s+\w+\s+"
        r"(?P<src>[\d\.]+)(?::(?P<sport>\d+))?\s+->\s+"
        r"(?P<dst>[\d\.]+)(?::(?P<dport>\d+))?"
    ),
}

FORMAT_SIGNATURES = {
    "syslog": [r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}", r"sshd\[", r"kernel:"],
    "apache_access": [r'GET|POST|PUT|DELETE.*HTTP', r'" \d{3} \d+'],
    "json": [r'^\s*\{', r'"timestamp"', r'"level"'],
    "windows": [r"EventID", r"Security\s+ID", r"Account Name"],
    "firewall": [r"DENY|ACCEPT|DROP|BLOCK", r"SRC=|DST=", r"->.*\d{1,5}"],
}


class LogParser:
    def __init__(self):
        self.detected_type = None

    def parse(self, filepath: str, log_type: str, filename: str) -> list:
        try:
            if filepath.endswith(".gz"):
                with gzip.open(filepath, "rt", errors="replace") as f:
                    content = f.read()
            else:
                with open(filepath, "r", errors="replace") as f:
                    content = f.read()
        except Exception as e:
            logger.error(f"Failed to read log file: {e}")
            return []

        lines = content.splitlines()
        if log_type == "auto":
            log_type = self._detect_format(lines[:50])
        self.detected_type = log_type

        parsers = {
            "syslog": self._parse_syslog,
            "apache": self._parse_apache,
            "ssh": self._parse_ssh,
            "json": self._parse_json,
            "windows": self._parse_windows,
            "firewall": self._parse_firewall,
        }
        parser_fn = parsers.get(log_type, self._parse_generic)
        events = []
        for line in lines[:50000]:  # Cap at 50k lines
            line = line.strip()
            if not line:
                continue
            event = parser_fn(line)
            if event:
                event["raw_log"] = line[:500]
                event["log_type"] = log_type
                events.append(event)

        logger.info(f"Parsed {len(events)} events from {filename} [{log_type}]")
        return events

    def _detect_format(self, sample_lines: list) -> str:
        sample = "\n".join(sample_lines)
        scores = {}
        for fmt, patterns in FORMAT_SIGNATURES.items():
            score = sum(1 for p in patterns if re.search(p, sample, re.IGNORECASE))
            scores[fmt] = score
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "syslog"

    def _parse_syslog(self, line: str) -> dict | None:
        m = PATTERNS["syslog"].match(line)
        if not m:
            return self._parse_generic(line)
        d = m.groupdict()
        ip = self._extract_ip(d.get("message", ""))
        return {
            "timestamp": f"{d.get('month','')} {d.get('day','')} {d.get('time','')}",
            "host": d.get("host", ""),
            "process": d.get("process", ""),
            "pid": d.get("pid", ""),
            "message": d.get("message", ""),
            "source_ip": ip,
            "user": self._extract_user(d.get("message", "")),
            "action": self._extract_action(d.get("message", "")),
        }

    def _parse_apache(self, line: str) -> dict | None:
        m = PATTERNS["apache_access"].match(line)
        if not m:
            return None
        d = m.groupdict()
        return {
            "timestamp": d.get("time", ""),
            "source_ip": d.get("ip", ""),
            "method": d.get("method", ""),
            "path": d.get("path", ""),
            "status_code": int(d.get("status", 0) or 0),
            "bytes": d.get("size", "0"),
            "user_agent": d.get("ua", ""),
            "message": f"{d.get('method')} {d.get('path')} → {d.get('status')}",
        }

    def _parse_ssh(self, line: str) -> dict | None:
        m = PATTERNS["ssh_auth"].match(line)
        if not m:
            return self._parse_syslog(line)
        d = m.groupdict()
        return {
            "timestamp": d.get("ts", ""),
            "source_ip": d.get("ip", ""),
            "user": d.get("user", ""),
            "action": d.get("action", ""),
            "port": d.get("port", ""),
            "message": line,
            "failed": "Failed" in (d.get("action") or "") or "Invalid" in (d.get("action") or ""),
        }

    def _parse_json(self, line: str) -> dict | None:
        try:
            data = json.loads(line)
            return {
                "timestamp": str(data.get("timestamp", data.get("@timestamp", data.get("time", "")))),
                "source_ip": data.get("src_ip", data.get("source_ip", data.get("clientip", ""))),
                "user": data.get("user", data.get("username", "")),
                "message": data.get("message", data.get("msg", str(data))),
                "level": data.get("level", data.get("severity", "INFO")),
                "action": data.get("action", data.get("event_type", "")),
                "_raw": data,
            }
        except json.JSONDecodeError:
            return None

    def _parse_windows(self, line: str) -> dict | None:
        m = PATTERNS["windows"].match(line)
        if not m:
            return self._parse_generic(line)
        d = m.groupdict()
        return {
            "timestamp": d.get("ts", ""),
            "event_id": d.get("event_id", ""),
            "user": d.get("user", ""),
            "message": line,
            "source_ip": self._extract_ip(line),
        }

    def _parse_firewall(self, line: str) -> dict | None:
        ip_match = re.search(r"SRC=([\d\.]+).*DST=([\d\.]+)", line)
        if not ip_match:
            m = PATTERNS["firewall"].match(line)
            if not m:
                return self._parse_generic(line)
            d = m.groupdict()
            return {
                "timestamp": d.get("ts", ""),
                "source_ip": d.get("src", ""),
                "dest_ip": d.get("dst", ""),
                "src_port": d.get("sport", ""),
                "dst_port": d.get("dport", ""),
                "action": "DENY" if "DENY" in line or "DROP" in line or "BLOCK" in line else "ACCEPT",
                "message": line,
            }
        return {
            "timestamp": "",
            "source_ip": ip_match.group(1),
            "dest_ip": ip_match.group(2),
            "action": "DENY" if "DENY" in line or "DROP" in line else "ACCEPT",
            "message": line,
        }

    def _parse_generic(self, line: str) -> dict:
        return {
            "timestamp": self._extract_timestamp(line),
            "source_ip": self._extract_ip(line),
            "user": self._extract_user(line),
            "message": line,
            "action": self._extract_action(line),
        }

    def _extract_ip(self, text: str) -> str:
        match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
        return match.group(1) if match else ""

    def _extract_user(self, text: str) -> str:
        for pattern in [r"for\s+(?:invalid user\s+)?(\S+)\s+from", r"user[=:\s]+(\S+)", r"USER=(\S+)"]:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""

    def _extract_action(self, text: str) -> str:
        actions = ["Failed password", "Accepted password", "Invalid user", "Connection refused",
                   "sudo", "su:", "login", "logout", "session opened", "session closed"]
        for a in actions:
            if a.lower() in text.lower():
                return a
        return ""

    def _extract_timestamp(self, text: str) -> str:
        patterns = [
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
            r"\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}",
            r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",
        ]
        for p in patterns:
            m = re.search(p, text)
            if m:
                return m.group()
        return ""
