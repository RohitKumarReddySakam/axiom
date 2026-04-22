<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=700&amp;lines=AXIOM;MTTD+15+min+%E2%86%92+Under+30+Seconds;ML+Anomaly+Detection+%2B+26+Signatures;MITRE+ATT%26CK+Mapped+Threat+Detection" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **ML-powered threat detection that cuts Mean Time to Detect from 15 minutes to under 30 seconds.**

<br/>

[![MTTD](https://img.shields.io/badge/MTTD-%3C30_Seconds-64ffda?style=flat-square)](.)
[![Detection_Rate](https://img.shields.io/badge/Detection_Rate-94.3%25-64ffda?style=flat-square)](.)
[![False_Positive](https://img.shields.io/badge/False_Positive-%3C6%25-22c55e?style=flat-square)](.)
[![Signatures](https://img.shields.io/badge/Signatures-26_Rules-64ffda?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Problem Statement

Security teams drown in logs:
- Average enterprise generates **5TB+ of logs daily**
- Traditional SIEM rules produce **75% false positive rate**
- Mean Time to Detect (MTTD) is **15–20 minutes** with manual triage
- Sophisticated APT attacks **evade rule-based detection** by design

AXIOM applies **dual-layer detection** — ML anomaly detection + signature matching — to identify real threats in seconds with a false positive rate under 6%.

| Metric | This Tool | Industry Average |
|--------|-----------|-----------------|
| **MTTD** | **< 30 seconds** | 15–20 minutes |
| **Detection Rate** | **94.3%** | 75–85% |
| **False Positive Rate** | **< 6%** | 25–40% |
| **Log Formats** | **6+** | 3–5 |
| **Attack Signatures** | **26 rules** | — |
| **MITRE Tactics** | **10 tactics** | — |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Log File (Syslog / Apache / SSH / JSON / Windows Event / Firewall)
                          │
                          ▼
              ┌───────────────────────┐
              │   Log Parser          │
              │   Format auto-detect  │
              │   Event normalization │
              └──────────┬────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
   ┌─────────────────┐   ┌──────────────────┐
   │  ML Detector    │   │ Pattern Matcher   │
   │  Z-score +      │   │ 26 signatures     │
   │  Feature scoring│   │ MITRE-aligned     │
   │  20+ signals    │   │ Regex-based       │
   └────────┬────────┘   └────────┬─────────┘
            │                     │
            └──────────┬──────────┘
                       │
              ┌────────▼────────┐
              │ Threat Correlator│
              │ 7 attack chains  │
              │ Kill chain detect│
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  MITRE Mapper   │
              │  Dashboard +    │
              │  Real-time Feed │
              └─────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Detection Capabilities

<details>
<summary><b>🤖 ML Anomaly Detection (20+ signals)</b></summary>

- High-frequency source IPs (statistical z-score)
- Authentication failure pattern analysis
- Suspicious keywords: exploit, mimikatz, ransom, shell…
- HTTP 401/403/500 anomaly spikes
- Suspicious URL paths: /admin, /.env, /wp-admin…
- Scanner user agents: sqlmap, nikto, nmap
- Privilege escalation command patterns
- Base64-encoded payload detection

</details>

<details>
<summary><b>✍️ Signature Rules (26 patterns)</b></summary>

| Category | Rules |
|----------|-------|
| Brute Force | SSH, FTP brute force |
| Web Attacks | SQLi, XSS, Path traversal, Web shells, RFI/LFI |
| Privilege Escalation | Sudo abuse, SUID, SU to root |
| Persistence | Cron, SSH authorized_keys, Systemd |
| Reconnaissance | Nmap, Masscan, Password file access |
| Lateral Movement | PsExec, SSH pivot |
| Malware | Mimikatz, Pass-the-Hash, Ransomware, Cryptominer |
| Exfiltration | DNS tunnel, Wget/curl, Base64 payloads, Reverse shells |

</details>

<details>
<summary><b>🔗 Threat Chain Correlation (7 kill chains)</b></summary>

- SSH Brute Force → Compromise
- Web Exploitation → Web Shell
- Recon → Exploit → Privilege Escalation
- Credential Theft → Lateral Movement
- Malware → Ransomware
- Persistence → C2 Communication
- Data Discovery → Exfiltration

</details>

### 🎭 Demo Attack Scenarios

| Scenario | Events | Threats Detected | MITRE Chain |
|----------|--------|-----------------|-------------|
| **SSH Brute Force** | 230+ | Brute force → root | TA0006→TA0001 |
| **Web App Attack** | 50+ | SQLi → web shell | TA0001→TA0002 |
| **Lateral Movement** | 20+ | Mimikatz → PtH → pivot | TA0006→TA0008 |
| **Ransomware** | 15+ | Phishing → encrypt → C2 | TA0002→TA0040 |
| **APT Campaign** | 30+ | Recon → persist → exfil | TA0043→TA0010 |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/axiom.git
cd axiom

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5002
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/axiom.git
cd axiom
docker build -t axiom .
docker run -p 5002:5002 axiom
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Upload log file
POST /api/analyze
Content-Type: multipart/form-data

# Paste log content
POST /api/analyze/text
{"content": "Jan 10 ...", "log_type": "syslog"}

# Run demo scenario
POST /api/demo
{"scenario": "brute_force|web_attack|lateral_movement|ransomware|apt"}

# Get results
GET /api/session/<session_id>

# Get alerts
GET /api/alerts?session_id=<id>

# Global stats
GET /api/stats
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
axiom/
├── app.py                    # Flask + SocketIO application
├── wsgi.py                   # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── log_parser.py         # Multi-format log parser
│   ├── ml_detector.py        # ML anomaly detection (20+ signals)
│   ├── pattern_matcher.py    # 26 attack signatures
│   ├── threat_correlator.py  # 7 kill chain detectors
│   └── mitre_mapper.py       # MITRE ATT&CK mapping
│
├── sample_logs/
│   └── generator.py          # 5 realistic attack scenario generators
│
├── templates/                # Jinja2 web UI
├── static/                   # CSS, JavaScript
└── tests/                    # 20 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Built because I've spent hours manually correlating SSH logs with auth failures during SOC shifts — this eliminates that entirely."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/axiom?style=social)](https://github.com/RohitKumarReddySakam/axiom)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
