"""
Threat Correlator
Correlates individual anomalies into multi-stage attack chains
"""
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

# Attack chain definitions: sequences of threat types that form a kill chain
ATTACK_CHAINS = [
    {
        "name": "SSH Brute Force → Compromise",
        "severity": "CRITICAL",
        "stages": ["brute_force", "brute_force_ssh", "unauthorized_access"],
        "description": "Successful SSH brute force attack leading to system compromise",
        "mitre": "TA0006 → TA0001",
    },
    {
        "name": "Web Exploitation → Web Shell",
        "severity": "CRITICAL",
        "stages": ["sql_injection", "xss_attack", "rfi_lfi", "web_shell"],
        "description": "Web application exploitation leading to web shell deployment",
        "mitre": "TA0001 → TA0002",
    },
    {
        "name": "Recon → Exploitation → Privilege Escalation",
        "severity": "CRITICAL",
        "stages": ["port_scan", "web_exploitation", "privilege_escalation"],
        "description": "Full kill chain: reconnaissance → exploitation → privilege escalation",
        "mitre": "TA0043 → TA0001 → TA0004",
    },
    {
        "name": "Credential Theft → Lateral Movement",
        "severity": "CRITICAL",
        "stages": ["credential_dumping", "mimikatz", "pass_the_hash", "lateral_movement"],
        "description": "Credential harvesting enabling lateral movement through network",
        "mitre": "TA0006 → TA0008",
    },
    {
        "name": "Malware → Ransomware Deployment",
        "severity": "CRITICAL",
        "stages": ["malware_execution", "ransomware", "ransomware_indicator"],
        "description": "Malware execution leading to ransomware deployment",
        "mitre": "TA0002 → TA0040",
    },
    {
        "name": "Persistence → C2 Communication",
        "severity": "HIGH",
        "stages": ["cron_persistence", "ssh_authorized_keys", "c2_communication"],
        "description": "Persistence mechanism established for long-term C2 access",
        "mitre": "TA0003 → TA0011",
    },
    {
        "name": "Data Discovery → Exfiltration",
        "severity": "HIGH",
        "stages": ["path_traversal", "passwd_access", "data_exfiltration", "dns_exfil"],
        "description": "Sensitive data discovery followed by exfiltration attempt",
        "mitre": "TA0009 → TA0010",
    },
]


class ThreatCorrelator:
    def correlate(self, findings: list) -> list:
        if not findings:
            return []

        detected_types = set(f.get("threat_type", "") for f in findings)
        correlations = []

        for chain in ATTACK_CHAINS:
            matched_stages = [s for s in chain["stages"] if s in detected_types]
            if len(matched_stages) >= 2:
                correlations.append({
                    "chain_name": chain["name"],
                    "severity": chain["severity"],
                    "description": chain["description"],
                    "mitre_chain": chain["mitre"],
                    "matched_stages": matched_stages,
                    "confidence": "HIGH" if len(matched_stages) >= 3 else "MEDIUM",
                })
                logger.info(f"Attack chain detected: {chain['name']} [{matched_stages}]")

        return correlations
