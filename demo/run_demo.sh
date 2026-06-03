#!/bin/bash
# DFIRLlama-SIFT — Script de demo para video
# Simula una investigación forense completa en ~3 minutos

CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
MAGENTA='\033[95m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pause() { sleep "${1:-1}"; }

typeout() {
    local text="$1"
    local delay="${2:-0.04}"
    echo -n "$text" | while IFS= read -r -n1 char; do
        echo -n "$char"
        sleep "$delay"
    done
    echo
}

banner() {
    echo -e "\n${1}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${1}${BOLD}  $2${RESET}"
    echo -e "${1}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

clear

# ── Portada ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
  ██████  ███████ ██ ██████  ██      ██      █████  ███    ███  █████
  ██   ██ ██      ██ ██   ██ ██      ██     ██   ██ ████  ████ ██   ██
  ██   ██ █████   ██ ██████  ██      ██     ███████ ██ ████ ██ ███████
  ██   ██ ██      ██ ██   ██ ██      ██     ██   ██ ██  ██  ██ ██   ██
  ██████  ██      ██ ██   ██ ███████ ███████ ██   ██ ██      ██ ██   ██
EOF
echo -e "${RESET}"
echo -e "${CYAN}${BOLD}                        S I F T${RESET}"
echo -e "${DIM}         Evidence Interrogation Loop — Protocol SIFT Extension${RESET}"
echo -e "${DIM}              SANS FIND EVIL! Hackathon 2026${RESET}"
pause 3

# ── Setup del caso ────────────────────────────────────────────────────────────
clear
echo -e "${DIM}analyst@sift:~\$${RESET} ${BOLD}ls /cases/IR-2024-0622/${RESET}"
pause 0.5
echo -e "${CYAN}Security.evtx${RESET}   ${CYAN}System.evtx${RESET}   ${CYAN}memory.raw${RESET}   ${CYAN}Amcache.hve${RESET}   ${CYAN}SYSTEM${RESET}"
pause 1.5

echo -e "\n${DIM}analyst@sift:~\$${RESET} ${BOLD}cd /cases/IR-2024-0622 && claude${RESET}"
pause 1

echo -e "\n${DIM}[Claude Code] Reading ~/.claude/skills/dfirllama-eil/SKILL.md...${RESET}"
pause 0.8
echo -e "${DIM}[Claude Code] MCP server: DFIRLlama-SIFT connected (22 tools)${RESET}"
pause 0.8
echo -e "${DIM}[Claude Code] Starting Evidence Interrogation Loop...${RESET}"
pause 1.5

# ── FASE 1 ────────────────────────────────────────────────────────────────────
banner "$CYAN" "PHASE 1 — INVENTORY"
pause 0.5

echo -e "${DIM}[07:14:01 UTC]${RESET} ${GREEN}Mapping evidence artifacts...${RESET}"
pause 0.3
echo -e "  ${CYAN}→ file_hash${RESET}(Security.evtx)"
pause 0.4
echo -e "    ${DIM}SHA256: a3f8b2c19d4e5f67890ab12cd34ef567... ✓${RESET}"
echo -e "  ${CYAN}→ file_hash${RESET}(System.evtx)"
pause 0.3
echo -e "    ${DIM}SHA256: b7c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6... ✓${RESET}"
echo -e "  ${CYAN}→ file_hash${RESET}(memory.raw)"
pause 0.5
echo -e "    ${DIM}SHA256: c8d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7... ✓${RESET}"
echo -e "  ${CYAN}→ file_hash${RESET}(Amcache.hve)"
pause 0.3
echo -e "    ${DIM}SHA256: d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8... ✓${RESET}"
pause 0.5
echo -e "${GREEN}✓ evidence_manifest.json written — 4 artifacts hashed${RESET}"
pause 1.5

# ── FASE 2 ────────────────────────────────────────────────────────────────────
banner "$CYAN" "PHASE 2 — ORIENT"
pause 0.5

echo -e "${DIM}[07:14:08 UTC]${RESET} ${GREEN}Parsing EVTX logs → SQLite...${RESET}"
echo -e "  ${CYAN}→ evtx_to_sqlite${RESET}(Security.evtx)"
pause 1.2
echo -e "    ${DIM}✓ 44,281 events | 2024-01-01 → 2024-06-28 | parser: EvtxECmd${RESET}"
echo -e "  ${CYAN}→ evtx_to_sqlite${RESET}(System.evtx)"
pause 0.8
echo -e "    ${DIM}✓ 8,847 events | 2024-01-01 → 2024-06-28${RESET}"
pause 0.5
echo -e "\n${DIM}[07:14:12 UTC]${RESET} ${GREEN}Analyzing memory image...${RESET}"
echo -e "  ${CYAN}→ volatility_run${RESET}(memory.raw, windows.pslist)"
pause 1.0
echo -e "    ${DIM}✓ 87 processes listed${RESET}"
echo -e "  ${CYAN}→ volatility_run${RESET}(memory.raw, windows.netscan)"
pause 0.8
echo -e "    ${DIM}✓ 23 network connections (3 ESTABLISHED to external IPs)${RESET}"
pause 1.5

# ── FASE 3 ────────────────────────────────────────────────────────────────────
banner "$YELLOW" "PHASE 3 — INTERROGATE  (NL→SQL)"
pause 0.5

echo -e "${DIM}[07:14:18 UTC]${RESET} ${YELLOW}Running forensic triage queries...${RESET}"
pause 0.5

# Query 1
echo -e "\n${BOLD}Q: Were there any logons from external IPs?${RESET}"
echo -e "  ${CYAN}→ query_forensic_db${RESET}(Security.db, \"external logons?\")"
pause 1.0
echo -e "  ${DIM}SQL: SELECT TimeCreated, UserName, IpAddress FROM events${RESET}"
echo -e "  ${DIM}     WHERE EventId=4624 AND IpAddress NOT LIKE '10.%'${RESET}"
echo -e "  ${DIM}     ORDER BY TimeCreated${RESET}"
pause 0.8
echo -e "  ${GREEN}→ 234 rows returned${RESET}"
pause 0.5

# Query 2
echo -e "\n${BOLD}Q: Did administrator connect from multiple IPs on the same day?${RESET}"
echo -e "  ${CYAN}→ query_forensic_db${RESET}(Security.db, \"admin multiple IPs same day?\")"
pause 1.2
echo -e "  ${DIM}SQL: SELECT date(TimeCreated), COUNT(DISTINCT IpAddress) as ips${RESET}"
echo -e "  ${DIM}     FROM events WHERE EventId=4624 AND UserName='administrator'${RESET}"
echo -e "  ${DIM}     GROUP BY date(TimeCreated) HAVING ips > 1${RESET}"
pause 0.8
echo -e ""
echo -e "  ${RED}${BOLD}★ FINDING: Administrator connected from 2 IPs on same day:${RESET}"
echo -e "    ${DIM}2024-06-22: 10.0.0.1 (internal) + 102.20.90.8 (EXTERNAL)${RESET}"
echo -e "    ${DIM}2024-06-25: 10.0.0.1 (internal) + 102.20.90.8 (EXTERNAL)${RESET}"
pause 1.5

# Query 3
echo -e "\n${BOLD}Q: Were any logs cleared?${RESET}"
echo -e "  ${CYAN}→ query_forensic_db${RESET}(Security.db, \"log clearing events?\")"
pause 0.8
echo -e "  ${DIM}SQL: SELECT TimeCreated, UserName FROM events WHERE EventId=1102${RESET}"
pause 0.5
echo -e "  ${RED}${BOLD}★ FINDING: 1 log clearing event — 2024-06-22 19:45:33 UTC${RESET}"
pause 0.5

# Amcache
echo -e "\n${BOLD}Checking execution artifacts...${RESET}"
echo -e "  ${CYAN}→ amcache_parse${RESET}(Amcache.hve)"
pause 1.0
echo -e "  ${RED}${BOLD}★ FINDING: lm32.exe executed 2024-06-19 09:47 from C:\\Users\\jparker\\AppData\\Temp${RESET}"
echo -e "  ${DIM}  SHA1: 47b7b2dd88050cd7224a5542ae8d5bce928bfc08${RESET}"
pause 1.5

# ── FASE 4 ────────────────────────────────────────────────────────────────────
banner "$YELLOW" "PHASE 4 — ENRICH"
pause 0.5

echo -e "${DIM}[07:14:35 UTC]${RESET} ${YELLOW}Investigating suspicious IOCs with ReAct agent...${RESET}"
pause 0.5

echo -e "\n${BOLD}IOC: 102.20.90.8${RESET}"
echo -e "  ${MAGENTA}Thought: External IP found in admin RDP sessions. Check geolocation.${RESET}"
echo -e "  ${CYAN}→ geoip_lookup${RESET}({\"ip\": \"102.20.90.8\"})"
pause 0.8
echo -e "    ${DIM}Obs: {\"country\": \"NG\", \"org\": \"AS37282 MTN Nigeria\", \"city\": \"Lagos\"}${RESET}"
echo -e "  ${MAGENTA}Thought: Nigeria. Suspicious for a Mexican company. Check threat intel.${RESET}"
echo -e "  ${CYAN}→ threat_list_check${RESET}({\"ip\": \"102.20.90.8\"})"
pause 0.6
echo -e "    ${DIM}Obs: {\"in_blocklist\": true, \"score\": 7}${RESET}"
echo -e "  ${MAGENTA}Thought: Score 7/10 on IPSum (30+ sources). Confirmed malicious.${RESET}"
pause 0.5
echo -e "  ${RED}${BOLD}Final Answer: MALICIOUS (high confidence)${RESET}"
echo -e "  ${DIM}  Nigeria | AS37282 MTN | IPSum score 7/10 | Block immediately${RESET}"
pause 1.5

echo -e "\n${BOLD}IOC: lm32.exe (SHA1: 47b7b2dd...)${RESET}"
echo -e "  ${MAGENTA}Thought: Suspicious executable in AppData\\Temp. Extract strings.${RESET}"
echo -e "  ${CYAN}→ strings_extract${RESET}(lm32.exe)"
pause 0.8
echo -e "    ${DIM}Obs: URLs: ['diamondrushed.com/pass-this-step', 'c2panel.onion']${RESET}"
echo -e "    ${DIM}     PowerShell: ['Invoke-WebRequest', 'DownloadString', 'IEX']${RESET}"
echo -e "  ${RED}${BOLD}★ FINDING: Lumma Stealer indicators — C2 communication confirmed${RESET}"
pause 1.5

# ── FASE 5 ────────────────────────────────────────────────────────────────────
banner "$MAGENTA" "PHASE 5 — VALIDATE"
pause 0.5

echo -e "${DIM}[07:14:52 UTC]${RESET} ${MAGENTA}Validating 18 findings against evidence...${RESET}"
echo -e "  ${CYAN}→ validate_findings${RESET}(18 findings, evidence_db=Security.db)"
pause 1.5
echo -e ""
echo -e "  Confirmed:     ${GREEN}17 / 18${RESET}"
echo -e "  Unverified:    ${YELLOW}0 / 18${RESET}"
echo -e "  Contradicted:  ${RED}1 / 18${RESET}  ← auto-correcting..."
pause 0.8
echo -e "  ${MAGENTA}Self-correction: lm32.exe timestamp off by 1 day → re-querying...${RESET}"
echo -e "  ${CYAN}→ query_forensic_db${RESET}(\"exact timestamp lm32.exe execution?\")"
pause 0.6
echo -e "    ${DIM}Corrected: 2024-06-19 09:47:22 UTC ✓${RESET}"
pause 0.5
echo -e ""
echo -e "  ${GREEN}${BOLD}Hallucination score: 0.056 (5.6%) — ACCEPTABLE${RESET}"
echo -e "  ${GREEN}Self-corrections: 1/1 successful (100%)${RESET}"
pause 1.5

# ── FASE 6 ────────────────────────────────────────────────────────────────────
banner "$GREEN" "PHASE 6 — REPORT"
pause 0.5

echo -e "${DIM}[07:14:58 UTC]${RESET} ${GREEN}Generating ATT&CK mapping and final report...${RESET}"
echo -e "  ${CYAN}→ map_to_mitre${RESET}(findings, incident_id=\"IR-2024-0622\")"
pause 1.5
echo -e ""
echo -e "  ${YELLOW}MITRE ATT&CK Techniques identified:${RESET}"
echo -e "  ${DIM}  T1566.001  Spearphishing Link        [Initial Access]   high${RESET}"
echo -e "  ${DIM}  T1059.001  PowerShell                [Execution]        high${RESET}"
echo -e "  ${DIM}  T1204.002  Malicious File            [Execution]        high${RESET}"
echo -e "  ${DIM}  T1547.001  Registry Run Keys         [Persistence]      medium${RESET}"
echo -e "  ${DIM}  T1021.001  Remote Desktop Protocol   [Lateral Movement] high${RESET}"
echo -e "  ${DIM}  T1078.003  Local Accounts            [Privilege Escal.] high${RESET}"
echo -e "  ${DIM}  T1070.001  Clear Windows Event Logs  [Defense Evasion]  high${RESET}"
echo -e "  ${DIM}  T1003.001  LSASS Memory              [Credential Access] medium${RESET}"
echo -e "  ${DIM}  T1071.001  Web Protocols (C2)        [C&C]              high${RESET}"
echo -e "  ${DIM}  T1041      Exfil over C2 Channel     [Exfiltration]     medium${RESET}"
echo -e "  ${DIM}  ... 4 more techniques${RESET}"
pause 1.0
echo -e ""
echo -e "  ${GREEN}✓ IR-2024-0622_findings.json${RESET}"
echo -e "  ${GREEN}✓ IR-2024-0622_navigator.json  (import at attack-navigator)${RESET}"
echo -e "  ${GREEN}✓ IR-2024-0622_executive_summary.md${RESET}"
echo -e "  ${GREEN}✓ forensic_audit.log  (47 tool calls logged)${RESET}"
pause 1.5

# ── Resumen final ─────────────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║            INVESTIGATION COMPLETE                               ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo -e ""
echo -e "  ${BOLD}Total time:${RESET}           ${GREEN}12 minutes${RESET}  (manual: 3–4 hours)"
echo -e "  ${BOLD}Findings:${RESET}             ${GREEN}18 verified${RESET}"
echo -e "  ${BOLD}ATT&CK techniques:${RESET}    ${GREEN}14${RESET}"
echo -e "  ${BOLD}Hallucination score:${RESET}  ${GREEN}5.6%${RESET}  (industry baseline: 59-82%)"
echo -e "  ${BOLD}Self-corrections:${RESET}     ${GREEN}1/1 (100%)${RESET}"
echo -e "  ${BOLD}Tool calls logged:${RESET}    ${GREEN}47 (JSONL audit trail)${RESET}"
echo -e ""
echo -e "  ${DIM}Key finding: Administrator credentials compromised.${RESET}"
echo -e "  ${DIM}Threat actor: Nigerian IP (AS37282), active Jun 22-28, 2024.${RESET}"
echo -e "  ${DIM}Malware: Lumma Stealer via ClickFix (jparker, Jun 19 09:47).${RESET}"
echo -e ""
echo -e "  ${DIM}github.com/robdinovil/dfirllama-sift${RESET}"
echo -e "  ${DIM}MIT License — TLP:CLEAR${RESET}"
echo ""
pause 3
