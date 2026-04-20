"""
MITRE ATT&CK Mapper
Maps threat types to MITRE ATT&CK tactics and techniques
"""

THREAT_MITRE_MAP = {
    "brute_force":          ("TA0006 Credential Access",    "T1110 Brute Force",                        "TA0001 Initial Access"),
    "brute_force_ssh":      ("TA0006 Credential Access",    "T1110.001 Password Guessing",              "TA0001 Initial Access"),
    "sql_injection":        ("TA0001 Initial Access",       "T1190 Exploit Public-Facing Application",  "TA0009 Collection"),
    "xss_attack":           ("TA0001 Initial Access",       "T1059.007 JavaScript",                     None),
    "path_traversal":       ("TA0005 Defense Evasion",      "T1083 File and Directory Discovery",       "TA0009 Collection"),
    "rfi_lfi":              ("TA0001 Initial Access",       "T1190 Exploit Public-Facing Application",  None),
    "web_shell":            ("TA0002 Execution",            "T1505.003 Web Shell",                      "TA0003 Persistence"),
    "reverse_shell":        ("TA0002 Execution",            "T1059.004 Unix Shell",                     "TA0011 C2"),
    "privilege_escalation": ("TA0004 Privilege Escalation", "T1548 Abuse Elevation Control Mechanism",  None),
    "sudo_abuse":           ("TA0004 Privilege Escalation", "T1548.003 Sudo and Sudo Caching",          None),
    "lateral_movement":     ("TA0008 Lateral Movement",     "T1021 Remote Services",                    None),
    "psexec_lateral":       ("TA0008 Lateral Movement",     "T1021.002 SMB/Windows Admin Shares",       None),
    "data_exfiltration":    ("TA0010 Exfiltration",         "T1048 Exfiltration Over Alt Protocol",     None),
    "dns_exfil":            ("TA0010 Exfiltration",         "T1048.003 Unencrypted Protocol",           None),
    "c2_communication":     ("TA0011 Command and Control",  "T1071 Application Layer Protocol",         None),
    "port_scan":            ("TA0043 Reconnaissance",       "T1595.001 Scanning IP Blocks",             None),
    "nmap_scan":            ("TA0043 Reconnaissance",       "T1595 Active Scanning",                    None),
    "malware_execution":    ("TA0002 Execution",            "T1204 User Execution",                     "TA0040 Impact"),
    "ransomware":           ("TA0040 Impact",               "T1486 Data Encrypted for Impact",          "TA0011 C2"),
    "ransomware_indicator": ("TA0040 Impact",               "T1486 Data Encrypted for Impact",          None),
    "credential_dumping":   ("TA0006 Credential Access",    "T1003.001 LSASS Memory",                   None),
    "mimikatz":             ("TA0006 Credential Access",    "T1003.001 LSASS Memory",                   None),
    "pass_the_hash":        ("TA0006 Credential Access",    "T1550.002 Pass the Hash",                  None),
    "cron_persistence":     ("TA0003 Persistence",          "T1053.003 Cron",                           None),
    "ssh_authorized_keys":  ("TA0003 Persistence",          "T1098.004 SSH Authorized Keys",            None),
    "crypto_miner":         ("TA0040 Impact",               "T1496 Resource Hijacking",                 None),
    "web_exploitation":     ("TA0001 Initial Access",       "T1190 Exploit Public-Facing Application",  None),
    "unauthorized_access":  ("TA0001 Initial Access",       "T1078 Valid Accounts",                     None),
    "malicious_download":   ("TA0011 Command and Control",  "T1105 Ingress Tool Transfer",              None),
    "base64_payload":       ("TA0002 Execution",            "T1027 Obfuscated Files or Information",    None),
    "suspicious_activity":  ("TA0001 Initial Access",       "T1190 Exploit Public-Facing Application",  None),
    "scanner_ua":           ("TA0043 Reconnaissance",       "T1595 Active Scanning",                    None),
}


class MITREMapper:
    def map(self, threat_type: str) -> dict:
        entry = THREAT_MITRE_MAP.get(threat_type, (
            "TA0001 Initial Access",
            "T1190 Exploit Public-Facing Application",
            None
        ))
        return {
            "mitre_tactic": entry[0],
            "mitre_tech":   entry[1],
        }

    def get_all_tactics(self, threat_types: list) -> list:
        tactics = set()
        for tt in threat_types:
            entry = THREAT_MITRE_MAP.get(tt)
            if entry:
                tactics.add(entry[0])
        return sorted(tactics)
