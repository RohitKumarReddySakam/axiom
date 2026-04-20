"""
Signature-Based Pattern Matcher
Rule-based detection for known attack patterns — complements ML anomaly detection.
"""
import re
import logging

logger = logging.getLogger(__name__)

# Attack signatures: (name, severity, regex, mitre_tactic, mitre_tech, description)
SIGNATURES = [
    # ── Brute Force ──────────────────────────────────────────────
    ("brute_force_ssh",       "HIGH",     r"Failed password for .+ from \d+\.\d+\.\d+\.\d+",
     "TA0006 Credential Access", "T1110 Brute Force",
     "SSH brute force authentication failure"),

    ("brute_force_invalid",   "HIGH",     r"Invalid user .+ from \d+\.\d+\.\d+\.\d+",
     "TA0006 Credential Access", "T1110.001 Password Guessing",
     "SSH login attempt with invalid username"),

    # ── Web Attacks ───────────────────────────────────────────────
    ("sql_injection",         "CRITICAL", r"(?i)(union\s+select|or\s+1=1|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell|information_schema)",
     "TA0001 Initial Access", "T1190 Exploit Public-Facing Application",
     "SQL injection attack detected in request"),

    ("path_traversal",        "HIGH",     r"(?:\.\.\/){2,}|(?:%2e%2e%2f){2,}|etc/passwd|etc/shadow|proc/self",
     "TA0005 Defense Evasion", "T1083 File and Directory Discovery",
     "Directory traversal / path traversal attack"),

    ("xss_attack",            "MEDIUM",   r"(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",
     "TA0001 Initial Access", "T1059.007 JavaScript",
     "Cross-site scripting (XSS) payload detected"),

    ("rfi_lfi",               "HIGH",     r"(?i)(include|require).*?(https?://|file://|/etc/|/proc/)",
     "TA0001 Initial Access", "T1190 Exploit Public-Facing Application",
     "Remote/Local file inclusion attempt"),

    ("web_shell",             "CRITICAL", r"(?i)(cmd\.exe|/bin/bash|/bin/sh|system\(|shell_exec|passthru|eval\(base64)",
     "TA0002 Execution", "T1505.003 Web Shell",
     "Web shell command execution detected"),

    ("scanner_ua",            "MEDIUM",   r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|burpsuite|nessus|openvas)",
     "TA0043 Reconnaissance", "T1595 Active Scanning",
     "Known security scanner/exploitation tool detected"),

    # ── Privilege Escalation ──────────────────────────────────────
    ("sudo_abuse",            "HIGH",     r"sudo(?::\s+\S+\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=root)",
     "TA0004 Privilege Escalation", "T1548.003 Sudo and Sudo Caching",
     "Sudo execution as root user"),

    ("suid_abuse",            "HIGH",     r"chmod\s+[u+]s|chmod\s+[4-7][0-7][0-7][0-7]",
     "TA0004 Privilege Escalation", "T1548.001 Setuid and Setgid",
     "SUID/SGID bit manipulation detected"),

    ("su_root",               "MEDIUM",   r"(?:^|\s)su\s+-\s*$|su\s+root",
     "TA0004 Privilege Escalation", "T1548 Abuse Elevation Control Mechanism",
     "Switch user to root attempted"),

    # ── Persistence ───────────────────────────────────────────────
    ("cron_persistence",      "HIGH",     r"(?i)(crontab\s+-[el]|/etc/cron|/var/spool/cron)",
     "TA0003 Persistence", "T1053.003 Cron",
     "Cron job modification — possible persistence mechanism"),

    ("ssh_authorized_keys",   "HIGH",     r"authorized_keys",
     "TA0003 Persistence", "T1098.004 SSH Authorized Keys",
     "SSH authorized_keys modification detected"),

    ("systemd_service",       "MEDIUM",   r"systemctl\s+(?:enable|start|daemon-reload).*\.service",
     "TA0003 Persistence", "T1543.002 Systemd Service",
     "New systemd service created or enabled"),

    # ── Discovery ─────────────────────────────────────────────────
    ("nmap_scan",             "MEDIUM",   r"(?i)(nmap|masscan|unicornscan|zmap)\s+",
     "TA0043 Reconnaissance", "T1595.001 Scanning IP Blocks",
     "Network scanning tool executed"),

    ("passwd_access",         "HIGH",     r"cat\s+/etc/passwd|cat\s+/etc/shadow|getent\s+passwd",
     "TA0006 Credential Access", "T1003.008 /etc/passwd and /etc/shadow",
     "Password file enumeration detected"),

    # ── Lateral Movement ─────────────────────────────────────────
    ("psexec_lateral",        "CRITICAL", r"(?i)(psexec|wmiexec|smbexec|dcomexec)",
     "TA0008 Lateral Movement", "T1021.002 SMB/Windows Admin Shares",
     "PsExec/WMI lateral movement tool detected"),

    ("ssh_lateral",           "MEDIUM",   r"Accepted publickey for .+ from .+ port \d+",
     "TA0008 Lateral Movement", "T1021.004 SSH",
     "SSH publickey authentication — possible lateral movement"),

    # ── Exfiltration & C2 ────────────────────────────────────────
    ("dns_exfil",             "HIGH",     r"(?i)(\b\w{30,}\.\w{2,6}\b|TXT\s+record.*base64)",
     "TA0010 Exfiltration", "T1048.003 Exfiltration Over Unencrypted Protocol",
     "DNS-based data exfiltration pattern"),

    ("wget_download",         "HIGH",     r"wget\s+https?://|curl\s+-[oO]\s+\S+\s+https?://",
     "TA0011 Command and Control", "T1105 Ingress Tool Transfer",
     "Suspicious file download from internet"),

    ("base64_payload",        "HIGH",     r"(?:bash|python|perl|php|python3)\s+.*\|\s*base64\s+-d|echo\s+[A-Za-z0-9+/]{40,}.*\|\s*base64",
     "TA0002 Execution", "T1027 Obfuscated Files or Information",
     "Base64-encoded payload execution"),

    ("reverse_shell",         "CRITICAL", r"(?i)(bash\s+-i\s*>&?\s*/dev/tcp|nc\s+-e\s*/bin|python.*os\.dup2|mkfifo.*nc)",
     "TA0002 Execution", "T1059.004 Unix Shell",
     "REVERSE SHELL — immediate containment required"),

    # ── Credential Theft ─────────────────────────────────────────
    ("mimikatz",              "CRITICAL", r"(?i)(mimikatz|sekurlsa|kerberos::|lsadump|wdigest|privilege::debug)",
     "TA0006 Credential Access", "T1003.001 LSASS Memory",
     "Mimikatz credential dumping tool detected"),

    ("pass_the_hash",         "CRITICAL", r"(?i)(pass.?the.?hash|pth|overpass.?the.?hash|sekurlsa::pth)",
     "TA0006 Credential Access", "T1550.002 Pass the Hash",
     "Pass-the-Hash attack detected"),

    # ── Malware Indicators ───────────────────────────────────────
    ("ransomware_indicator",  "CRITICAL", r"(?i)(\.encrypted$|\.locked$|\.crypt$|ransom|all your files|bitcoin|decrypt_instructions)",
     "TA0040 Impact", "T1486 Data Encrypted for Impact",
     "RANSOMWARE INDICATORS — ISOLATE SYSTEM IMMEDIATELY"),

    ("crypto_miner",          "HIGH",     r"(?i)(xmrig|minerd|cpuminer|stratum\+tcp|mining pool|hashrate)",
     "TA0040 Impact", "T1496 Resource Hijacking",
     "Cryptocurrency miner detected"),
]


class PatternMatcher:
    def __init__(self):
        self._compiled = [
            (name, sev, re.compile(pattern), tactic, tech, desc)
            for name, sev, pattern, tactic, tech, desc in SIGNATURES
        ]

    def match(self, events: list) -> list:
        hits = []
        for event in events:
            text = (event.get("message") or event.get("raw_log") or "")
            for name, severity, regex, tactic, tech, base_desc in self._compiled:
                if regex.search(text):
                    hits.append({
                        "threat_type": name,
                        "severity": severity,
                        "anomaly_score": self._sev_to_score(severity),
                        "source_ip": event.get("source_ip", ""),
                        "user": event.get("user", ""),
                        "timestamp": event.get("timestamp", ""),
                        "description": base_desc,
                        "raw_log": event.get("raw_log", ""),
                        "mitre_tactic": tactic,
                        "mitre_tech": tech,
                        "detection_method": "SIGNATURE",
                    })
                    break  # One signature match per event is enough

        logger.info(f"Pattern matcher: {len(hits)} signature hits from {len(events)} events")
        return hits

    def _sev_to_score(self, sev: str) -> float:
        return {"CRITICAL": 0.95, "HIGH": 0.75, "MEDIUM": 0.55, "LOW": 0.35}.get(sev, 0.35)
