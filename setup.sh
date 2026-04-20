#!/bin/bash
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[✓]${NC} $1"; }
log() { echo -e "${CYAN}[→]${NC} $1"; }

REPO_NAME="axiom"
PROJECT_DIR="$HOME/projects/$REPO_NAME"

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   AXIOM — AI-POWERED LOG INTELLIGENCE 🧠║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

mkdir -p "$PROJECT_DIR"
DOWNLOADS="$HOME/Downloads/$REPO_NAME"
[ -d "$DOWNLOADS" ] && cp -r "$DOWNLOADS"/. "$PROJECT_DIR"/ && ok "Files copied"
cd "$PROJECT_DIR"

python3 -m venv venv
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null || true
pip install --upgrade pip -q
pip install -r requirements.txt pytest -q
ok "Dependencies installed"

[ ! -d .git ] && git init && ok "Git initialized"
git add -A
git commit -m "🧠 feat: AXIOM — AI-Powered Log Intelligence v2.0

- ML anomaly detection (z-score + feature scoring on 20+ signals)
- 26 attack signature rules (MITRE ATT&CK aligned)
- 5 attack scenarios: SSH brute force, web attack, lateral movement, ransomware, APT
- Threat chain correlation (7 multi-stage attack patterns)
- Full MITRE ATT&CK mapping (TA0001–TA0043)
- Multi-format: syslog, Apache, SSH auth, JSON, Windows Event, firewall
- Real-time WebSocket dashboard
- 20 pytest tests across all core modules" 2>/dev/null || true

if command -v gh &>/dev/null; then
  gh repo create "$REPO_NAME" \
    --public \
    --description "🧠 AXIOM: AI-powered log intelligence — ML anomaly detection, 26 attack signatures, MITRE ATT&CK mapping, threat chain correlation. Reduces MTTD from 15min to <30sec." \
    --push --source . 2>&1 && ok "Pushed to GitHub" || true
else
  echo "Create repo at github.com/new named '$REPO_NAME' then: git push -u origin main"
fi

echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   AXIOM STARTING 🧠                     ║"
echo "  ║   Dashboard: http://localhost:5002       ║"
echo "  ║   Click '⚡ Demo Attack' to test now    ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"
command -v open &>/dev/null && sleep 2 && open "http://localhost:5002" &
python3 app.py
