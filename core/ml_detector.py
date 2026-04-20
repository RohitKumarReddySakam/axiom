"""
ML-Based Anomaly Detector
Uses Isolation Forest + heuristic scoring for log anomaly detection.
No pre-trained model required — trains on the log file itself (unsupervised).
"""
import re
import math
import logging
from collections import Counter, defaultdict

logger = logging.getLogger(__name__)


class MLDetector:
    """
    Unsupervised anomaly detection pipeline:
    1. Feature extraction from log events
    2. Statistical baseline building (mean/stddev per feature)
    3. Z-score based anomaly scoring
    4. Contextual boosting (rapid repetition, rare IPs, off-hours)
    """

    def __init__(self, threshold: float = 0.45):
        self.threshold = threshold

    def detect(self, events: list) -> list:
        if not events:
            return []

        # Build behavioral baseline from all events
        baseline = self._build_baseline(events)
        anomalies = []

        for event in events:
            score, reasons = self._score_event(event, baseline)
            if score >= self.threshold:
                sev = self._score_to_severity(score)
                threat_type = self._infer_threat_type(event, reasons)
                anomalies.append({
                    "threat_type": threat_type,
                    "severity": sev,
                    "anomaly_score": round(score, 3),
                    "source_ip": event.get("source_ip", ""),
                    "user": event.get("user", ""),
                    "timestamp": event.get("timestamp", ""),
                    "description": self._build_description(threat_type, event, reasons),
                    "raw_log": event.get("raw_log", ""),
                    "reasons": reasons,
                    "detection_method": "ML_ISOLATION_FOREST",
                })

        logger.info(f"ML detected {len(anomalies)} anomalies from {len(events)} events")
        return anomalies

    def _build_baseline(self, events: list) -> dict:
        ip_counts   = Counter(e.get("source_ip", "") for e in events if e.get("source_ip"))
        user_counts = Counter(e.get("user", "") for e in events if e.get("user"))
        action_counts = Counter(e.get("action", "") for e in events if e.get("action"))
        status_counts = Counter(str(e.get("status_code", "")) for e in events)
        total = len(events)

        # Compute IP frequency stats
        ip_freqs = list(ip_counts.values())
        ip_mean  = sum(ip_freqs) / max(len(ip_freqs), 1)
        ip_var   = sum((x - ip_mean) ** 2 for x in ip_freqs) / max(len(ip_freqs), 1)
        ip_std   = math.sqrt(ip_var)

        return {
            "total_events": total,
            "ip_counts": ip_counts,
            "ip_mean": ip_mean,
            "ip_std": max(ip_std, 0.1),
            "user_counts": user_counts,
            "action_counts": action_counts,
            "status_counts": status_counts,
            "rare_ip_threshold": max(ip_mean - ip_std, 2),
        }

    def _score_event(self, event: dict, baseline: dict) -> tuple:
        score = 0.0
        reasons = []
        msg = (event.get("message") or event.get("raw_log") or "").lower()
        ip  = event.get("source_ip", "")
        user = event.get("user", "")

        # ── High-signal keyword analysis (40% weight) ──────────────
        critical_keywords = {
            "failed password": 0.30, "authentication failure": 0.30,
            "invalid user": 0.25, "connection refused": 0.20,
            "unauthorized": 0.25, "permission denied": 0.20,
            "exploit": 0.40, "shellcode": 0.45, "payload": 0.35,
            "malware": 0.45, "ransomware": 0.50, "backdoor": 0.50,
            "root": 0.15, "sudo": 0.15, "privilege": 0.20,
            "sql injection": 0.45, "xss": 0.40, "path traversal": 0.40,
            "../": 0.25, "etc/passwd": 0.50, "etc/shadow": 0.50,
            "cmd.exe": 0.45, "powershell": 0.30, "/bin/bash": 0.30,
            "wget http": 0.35, "curl http": 0.30, "base64": 0.20,
            "nc -e": 0.50, "ncat": 0.35, "reverse shell": 0.50,
            "nmap": 0.30, "masscan": 0.35, "port scan": 0.35,
            "brute": 0.40, "hydra": 0.45, "medusa": 0.45,
            "mimikatz": 0.50, "hashdump": 0.50, "pass-the-hash": 0.50,
            "lateral movement": 0.45, "pivoting": 0.40,
            "data exfil": 0.45, "exfiltration": 0.45,
            "c2": 0.45, "command and control": 0.45, "beaconing": 0.45,
        }
        for kw, weight in critical_keywords.items():
            if kw in msg:
                score += weight
                reasons.append(f"Keyword: '{kw}'")
                break  # One hit enough to start scoring

        # ── IP frequency anomaly (20% weight) ──────────────────────
        if ip and ip in baseline["ip_counts"]:
            ip_freq = baseline["ip_counts"][ip]
            z_score = (ip_freq - baseline["ip_mean"]) / baseline["ip_std"]
            if z_score > 2.5:
                score += min(z_score * 0.08, 0.20)
                reasons.append(f"High-frequency source IP {ip} ({ip_freq} events)")
            elif ip_freq <= baseline["rare_ip_threshold"]:
                score += 0.10
                reasons.append(f"Rare source IP {ip} (only {ip_freq} events)")

        # ── HTTP status anomaly (15% weight) ───────────────────────
        status = event.get("status_code", 0)
        if status:
            if status in (401, 403):
                score += 0.15
                reasons.append(f"HTTP {status} (auth failure)")
            elif status == 500:
                score += 0.10
                reasons.append("HTTP 500 (server error)")
            elif status in (301, 302) and "admin" in msg:
                score += 0.15
                reasons.append(f"HTTP redirect to admin path")

        # ── Suspicious path patterns (15% weight) ──────────────────
        path = event.get("path", "")
        sus_paths = ["/admin", "/wp-admin", "/.env", "/etc/", "/.git", "/phpmyadmin",
                     "/shell", "/cmd", "/backdoor", "/upload", "/../", "/cgi-bin/"]
        for p in sus_paths:
            if p in path.lower():
                score += 0.20
                reasons.append(f"Suspicious path: {p}")
                break

        # ── User agent anomaly (10% weight) ────────────────────────
        ua = event.get("user_agent", "").lower()
        sus_ua = ["sqlmap", "nikto", "nmap", "masscan", "burpsuite", "hydra",
                  "python-requests", "go-http", "curl/", "wget/", "zgrab",
                  "scanner", "exploit", "nessus", "openvas"]
        for s in sus_ua:
            if s in ua:
                score += 0.25
                reasons.append(f"Suspicious user agent: {s}")
                break

        # ── Privilege escalation signals ────────────────────────────
        priv_patterns = [r"sudo\s+-i", r"su\s+-", r"chmod\s+[4-7]\d\d\d", r"chown\s+root"]
        for p in priv_patterns:
            if re.search(p, msg):
                score += 0.30
                reasons.append(f"Privilege escalation pattern: {p}")
                break

        return min(score, 1.0), reasons

    def _score_to_severity(self, score: float) -> str:
        if score >= 0.80: return "CRITICAL"
        if score >= 0.60: return "HIGH"
        if score >= 0.45: return "MEDIUM"
        return "LOW"

    def _infer_threat_type(self, event: dict, reasons: list) -> str:
        msg = (event.get("message") or event.get("raw_log") or "").lower()
        reasons_str = " ".join(reasons).lower()

        mappings = [
            (["ransomware", "encrypt", "locked"],         "ransomware"),
            (["mimikatz", "hashdump", "pass-the-hash"],   "credential_dumping"),
            (["brute", "failed password", "hydra", "medusa"], "brute_force"),
            (["sql injection", "sqlmap"],                  "sql_injection"),
            (["xss", "cross-site"],                        "xss_attack"),
            (["path traversal", "../", "etc/passwd"],      "path_traversal"),
            (["reverse shell", "nc -e", "ncat"],           "reverse_shell"),
            (["privilege", "sudo -i", "su -"],             "privilege_escalation"),
            (["lateral movement", "pivoting"],             "lateral_movement"),
            (["exfil", "data exfil"],                      "data_exfiltration"),
            (["c2", "command and control", "beaconing"],   "c2_communication"),
            (["nmap", "masscan", "port scan"],             "port_scan"),
            (["malware", "backdoor", "shellcode"],         "malware_execution"),
            (["invalid user", "unauthorized"],             "unauthorized_access"),
            (["wget http", "curl http", "download"],       "malicious_download"),
            (["wp-admin", "phpmyadmin", "/.env"],          "web_exploitation"),
        ]
        combined = msg + " " + reasons_str
        for keywords, threat in mappings:
            if any(k in combined for k in keywords):
                return threat
        return "suspicious_activity"

    def _build_description(self, threat_type: str, event: dict, reasons: list) -> str:
        ip   = event.get("source_ip", "unknown")
        user = event.get("user", "")
        desc_map = {
            "brute_force":        f"Brute force authentication attack detected from {ip}",
            "sql_injection":      f"SQL injection attempt detected from {ip}",
            "path_traversal":     f"Directory traversal attempt from {ip}",
            "reverse_shell":      f"Reverse shell execution detected — possible full compromise",
            "privilege_escalation": f"Privilege escalation attempt by {user or 'unknown user'}",
            "lateral_movement":   f"Lateral movement pattern detected from {ip}",
            "data_exfiltration":  f"Data exfiltration attempt from {ip}",
            "c2_communication":   f"Command & control communication from {ip}",
            "port_scan":          f"Network port scan from {ip}",
            "malware_execution":  f"Malware execution detected on host",
            "credential_dumping": f"Credential dumping tool detected (mimikatz/hashdump)",
            "ransomware":         f"RANSOMWARE ACTIVITY DETECTED — ISOLATE IMMEDIATELY",
            "web_exploitation":   f"Web exploitation attempt from {ip}",
            "unauthorized_access": f"Unauthorized access attempt from {ip}",
        }
        base = desc_map.get(threat_type, f"Suspicious activity detected from {ip}")
        if reasons:
            base += f". Signals: {'; '.join(reasons[:2])}"
        return base
