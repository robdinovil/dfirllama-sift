# DFIRLlama-SIFT — Installation Guide
## Setup, Configuration and Usage

**Version:** 1.0 — SANS FIND EVIL! Hackathon 2026  
**Estimated install time:** 15–20 minutes  
**Required level:** DFIR analyst with basic Python knowledge

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Installation — 5 Steps](#2-installation--5-steps)
3. [Mode 1 — Claude Code + MCP](#3-mode-1--claude-code--mcp-recommended)
4. [Mode 2 — Standalone agent (Ollama / air-gap)](#4-mode-2--standalone-agent-ollama--air-gap)
5. [Mode 3 — Web UI](#5-mode-3--web-ui)
6. [Supported Evidence Types](#6-supported-evidence-types)
7. [Real Usage Examples](#7-real-usage-examples)
8. [Reading the Outputs](#8-reading-the-outputs)
9. [Troubleshooting](#9-troubleshooting)
10. [Tool Quick Reference](#10-tool-quick-reference)

---

## 1. Requirements

### Minimum Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB+ |
| Free disk | 2 GB | 10 GB+ |
| CPU | Any x86-64 | 4+ cores |
| GPU | Not required | Optional (accelerates Ollama) |

### Required Software

| Software | Min version | How to verify |
|---------|-------------|---------------|
| SANS SIFT Workstation | Ubuntu 20.04+ | `lsb_release -a` |
| Python | 3.10+ | `python3 --version` |
| Claude Code CLI | Any | `claude --version` |
| pip | 21+ | `pip3 --version` |

### Optional Software (for air-gap mode)

| Software | Purpose | Install |
|---------|---------|---------|
| Ollama | Local LLM without internet | `curl -fsSL https://ollama.ai/install.sh \| sh` |
| mistral:7b | Recommended model | `ollama pull mistral:7b` |

### Verify Claude Code is authenticated

```bash
claude --version
# Should print version without error
# If it fails: claude auth login
```

---

## 2. Installation — 5 Steps

### Step 1 — Clone the repository

```bash
cd ~
git clone https://github.com/robdinovil/dfirllama-sift
cd dfirllama-sift
```

### Step 2 — Create virtual environment and install dependencies

```bash
# On SIFT (python3-venv not pre-installed, but virtualenv is available):
virtualenv .venv

# On other Ubuntu/Debian systems where python3-venv is installed:
# python3 -m venv .venv

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

This installs: `fastmcp`, `vanna[chromadb]`, `pandas`, `anthropic`, `openai`, `flask`, `yara-python`, `python-whois`, `requests`

> **Note:** Using a virtual environment avoids conflicts with SIFT's system Python packages. Always activate it with `source .venv/bin/activate` before running any command.

**If any package fails:**

```bash
pip install fastmcp
pip install "vanna[chromadb]"
pip install pandas flask anthropic openai requests python-whois yara-python
```

### Step 3 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your preferred editor:

```bash
nano .env
```

`.env` contents:

```bash
# Choose your LLM backend:

# Option A — Auto-detect (recommended: tries claude-cli first, then claude-api, then ollama)
LLM_BACKEND=auto

# Option B — Ollama local (air-gap, 100% offline)
# LLM_BACKEND=ollama
# OLLAMA_MODEL=mistral:7b

# Root directory for forensic cases (path guardrail)
EVIDENCE_ROOT=/cases

# Where to store the audit trail
AUDIT_LOG=/tmp/dfirllama_audit.log
```

### Step 4 — Register the MCP server with Claude Code

Open the Claude Code settings file:

```bash
nano ~/.claude/settings.json
```

Add the `mcpServers` section (if the file already exists, add it inside the JSON object):

```json
{
  "mcpServers": {
    "dfirllama-sift": {
      "command": "python3",
      "args": ["/home/YOUR_USERNAME/dfirllama-sift/server.py"],
      "env": {
        "LLM_BACKEND": "auto",
        "EVIDENCE_ROOT": "/cases",
        "AUDIT_LOG": "/tmp/dfirllama_audit.log"
      }
    }
  }
}
```

> **Important:** Replace `/home/YOUR_USERNAME/` with the actual path.  
> To find it: run `pwd` from the project directory.

### Step 5 — Install the EIL skill in Claude Code

```bash
# The skills/dfirllama-eil/ directory is already included in the repo.
# Only copy it if it is not yet in ~/.claude/skills/
ls ~/.claude/skills/dfirllama-eil/SKILL.md

# If the file does not exist:
mkdir -p ~/.claude/skills/dfirllama-eil
cp skills/dfirllama-eil/SKILL.md ~/.claude/skills/dfirllama-eil/
```

### Verify installation

```bash
# Check all modules import correctly
python3 -c "
import server, agent, webui, guardrails
from tools import nlsql, evtx_tools, ioc_tools, validator
from llm import client
print('All modules OK')
"

# Run the dry-run benchmark (no LLM required)
python3 benchmark/run_benchmark.py --dry-run
# Expected output: Correct: 20 (100.0%)

# Verify the MCP server starts
python3 server.py --help
```

---

## 3. Mode 1 — Claude Code + MCP (Recommended)

This is the primary mode. Claude Code acts as the orchestrator, reads the EIL protocol, and calls the 22 MCP server tools autonomously.

### How it works internally

```
Your terminal
    │
    ▼ claude
Claude Code
    │  reads → ~/.claude/CLAUDE.md (base behavior)
    │  reads → ~/.claude/skills/dfirllama-eil/SKILL.md (EIL protocol)
    │
    │  JSON-RPC stdio
    ▼
server.py (DFIRLlama-SIFT MCP Server)
    │
    ▼
22 forensic tools → EVTX, memory, registry, network, IOCs...
```

### Basic usage

```bash
# 1. Navigate to the case directory
cd /cases/IR-2024-0622

# 2. Open Claude Code
claude

# 3. Describe what you need in natural language
```

### Example prompts

**Full autonomous investigation:**

```
Investigate all artifacts in this directory. Look for evidence of
compromise, lateral movement, persistence, and exfiltration.
Generate a report with identified ATT&CK techniques.
```

**EVTX-specific analysis:**

```
Analyze the Security.evtx file. Look for external logons,
account creation, and suspicious PowerShell execution.
```

**Direct forensic question:**

```
In the EVTX files in this directory, did the administrator
connect from more than one different IP on the same day?
```

**Investigate a specific IP:**

```
Investigate IP 102.20.90.8. Is it malicious?
What country does it belong to? Is it on any threat lists?
```

**Memory analysis:**

```
Run Volatility against the memory.raw file.
Show processes, active network connections,
and look for injected code with malfind.
```

### The EIL runs autonomously — what you will see

Claude Code will automatically execute all 6 phases of the Evidence Interrogation Loop:

```
[EIL Phase 1 — INVENTORY]
  Hashing all artifacts...
  → Security.evtx (44,281 events)
  → memory.raw (2.1 GB)
  → Amcache.hve

[EIL Phase 2 — ORIENT]
  Parsing Security.evtx → SQLite...
  44,281 events | 2024-01-01 → 2024-06-28
  Analyzing memory: windows.pslist, windows.netscan

[EIL Phase 3 — INTERROGATE]
  Q: Were there logons from external IPs?
  SQL: SELECT TimeCreated, UserName, RemoteHost FROM events
       WHERE EventId=21 AND RemoteHost NOT LIKE '10.%'
  → 234 results

  FINDING: administrator connected from 102.20.90.8 (Africa)

[EIL Phase 4 — ENRICH]
  Investigating 102.20.90.8...
  → Country: Nigeria, AS37282
  → On IPSum blocklist: score 7/10 (MALICIOUS)

[EIL Phase 5 — VALIDATE]
  18 findings validated. Hallucination score: 5.6%
  1 self-correction applied.

[EIL Phase 6 — REPORT]
  14 ATT&CK techniques identified.
  Navigator layer generated.
  Report written to ./analysis/

Total time: 12 minutes
```

---

## 4. Mode 2 — Standalone Agent (Ollama / Air-Gap)

For cases where evidence **cannot leave the network**. Operates identically to Mode 1 but with a local model.

### Configure Ollama

```bash
# Install Ollama (requires internet once)
curl -fsSL https://ollama.ai/install.sh | sh

# Download the model (requires internet once)
ollama pull mistral:7b          # 4 GB, good for most tasks
# or
ollama pull qwen2.5:14b         # 9 GB, better quality if you have RAM

# Verify Ollama is running
ollama list
```

### Configure for air-gap mode

```bash
# Edit .env
LLM_BACKEND=ollama
OLLAMA_MODEL=mistral:7b
```

Once configured, Ollama does not require internet. The model is stored on disk.

### Usage

```bash
# Full investigation
python3 agent.py /cases/IR-2024-0622

# With a specific incident ID
python3 agent.py /cases/IR-2024-0622 --id IR-2024-0622

# Start from a specific phase (if EVTX is already parsed)
python3 agent.py /cases/IR-2024-0622 --phase interrogate

# Only the final report
python3 agent.py /cases/IR-2024-0622 --phase report

# Immediate demo with the included dataset (no real evidence needed)
python3 agent.py demo/data --demo
```

### Terminal output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 1 — INVENTORY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[07:14:22] Mapping available evidence...
  → file_hash(Security.evtx)
    Obs: SHA256: a3f8b2c19d4e5f67...
[07:14:23] Inventory: 3 artifacts → ./analysis/evidence_manifest.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 3 — INTERROGATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Thought: Looking for external logons first...
  → query_forensic_db("external RDP connections?")
    Obs: {'row_count': 234, 'results': [...]}

FINDING: [external_logons] 234 results

  Thought: External IPs found, investigate the most frequent one
  → query_forensic_db("administrator from multiple IPs same day?")
    Obs: {'row_count': 2, 'results': [{'date': '2024-06-22', ...}]}

FINDING: [admin_multiple_ips] 2 results
```

---

## 5. Mode 3 — Web UI

Local web interface for using DFIRLlama-SIFT from a browser. Ideal for demos or users less comfortable with the terminal.

### Start

```bash
python3 webui.py
# Open http://localhost:7860 in your browser
```

### Available UI functions

**Left panel — Controls:**

| Section | What it does |
|---------|-------------|
| Evidence Interrogation Loop | Launches the full EIL. Enter the case path and click "Run EIL" |
| Demo mode | Uses the included synthetic dataset. No real evidence required |
| NL→SQL Query | Type a natural language question about any EVTX |
| IOC Analyzer | Investigate an IP, domain, hash, or PowerShell command |

**Right panel — Results:**

| Tab | What it shows |
|-----|--------------|
| Terminal | EIL running in real time (streaming) |
| Findings | List of findings with confidence levels |
| ATT&CK | Identified MITRE techniques. Button to open Navigator |
| NL→SQL | Generated SQL + query results |

### Typical workflow in the Web UI

1. Enter the case path in "Case directory": `/cases/IR-2024-0622`
2. Assign an Incident ID: `IR-2024-0622`
3. Click **Run EIL**
4. Watch the analysis in real time in the Terminal tab
5. When done, go to Findings and ATT&CK for results
6. Click **Open in Navigator** to visualize in MITRE ATT&CK Navigator

---

## 6. Supported Evidence Types

### Windows Artifacts (full analysis)

| File | Tool | What it finds |
|------|------|--------------|
| `*.evtx` | EvtxECmd + NL→SQL | Logons, PowerShell, log clearing, scheduled tasks, services |
| `Amcache.hve` | AmcacheParser | Execution history with SHA1 hashes and timestamps |
| `*.pf` (prefetch) | PECmd | How many times each executable ran and when |
| `SYSTEM` hive | AppCompatCacheParser | Files that interacted with the OS |
| `NTUSER.DAT` / `UsrClass.dat` | SBECmd | Folders visited by the user (shellbags) |
| `SOFTWARE`, `SYSTEM` hives | RECmd | Persistence, USB history, network configuration |
| `$MFT` | MFTECmd | All files with 4 timestamps + timestomping detection |
| `*.lnk` | LECmd | Files opened, including from external media |
| `AutomaticDestinations/` | JLECmd | Recent files per application (Jump Lists) |
| `$Recycle.Bin` | RBCmd | Deleted files with original path and timestamp |

### Memory and Network

| File | Tool | What it finds |
|------|------|--------------|
| `*.raw`, `*.vmem`, `*.lime` | Volatility 3 | Processes, connections, injected code, DLLs |
| `*.pcap`, `*.pcapng` | tshark | Conversations, DNS, HTTP hosts, external IPs |

### Files and Binaries

| File | Tool | What it finds |
|------|------|--------------|
| `*.exe`, `*.dll`, `*.bin` | strings + YARA + bulk_extractor | Embedded IOCs, malware patterns, carved artifacts |
| Any file | file_hash | MD5/SHA1/SHA256/SHA512/ssdeep |
| Disk image `.E01` | log2timeline (plaso) | Full supertimeline |

### Text and Threat Intelligence

| Input | Tool | Output |
|-------|------|--------|
| TI report (text) | extract_iocs | JSON with IPs, domains, hashes, URLs |
| Triage notes | map_to_mitre | ATT&CK Navigator layer |
| IP / domain / hash / PowerShell | analyze_ioc | Malicious/suspicious/benign verdict |

---

## 7. Real Usage Examples

### Case 1: You have an .evtx and want to know what happened

```bash
# Option A — direct question in Claude Code
cd /cases/my_case
claude
> "Analyze the Security.evtx. Were there external accesses? Were logs cleared?"

# Option B — NL→SQL directly from terminal
python3 -c "
from tools.nlsql import query_nl
r = query_nl('/tmp/my_evtx.db', 'Were there logon failures from external IPs?')
print(r['sql'])
print(r['results'])
"
```

### Case 2: You have a suspicious IP from the logs

```bash
# From terminal
python3 -c "
from tools.ioc_tools import analyze_ioc
r = analyze_ioc('102.20.90.8', 'ip')
print(r['verdict'])
"

# Or from the Web UI: paste the IP into IOC Analyzer and click Investigate
python3 webui.py
```

### Case 3: You want to know what the user ran on the compromised machine

```bash
# Parse Amcache
python3 -c "
from tools.zimmerman_tools import amcache_parse
r = amcache_parse('/cases/IR-001/Amcache.hve')
for entry in r['summary']['suspicious_paths']:
    print(entry.get('FullPath'), entry.get('SHA1'))
"
```

### Case 4: Full air-gap investigation (offline)

```bash
# 1. Ensure Ollama is running
ollama serve &

# 2. Set the backend
export LLM_BACKEND=ollama
export OLLAMA_MODEL=mistral:7b

# 3. Run the agent
python3 agent.py /cases/IR-2024-0622 --id IR-2024-0622

# 4. Review outputs
ls ./analysis/
# IR-2024-0622_findings.json
# IR-2024-0622_navigator.json
# IR-2024-0622_executive_summary.md
# evidence_manifest.json
# forensic_audit.log
```

### Case 5: Quick demo to show the system (no real evidence)

```bash
# Demo mode — uses the included synthetic RDP compromise dataset
python3 agent.py demo/data --demo

# Or from the Web UI with the "Demo mode" button
python3 webui.py
# → Click "Demo mode"
```

---

## 8. Reading the Outputs

All outputs go to `./analysis/` (relative to where you ran the command).

### `evidence_manifest.json` — Evidence inventory

```json
{
  "case_dir": "/cases/IR-2024-0622",
  "artifacts": [
    {
      "name": "Security.evtx",
      "type": "Windows Event Log",
      "size_mb": 45.2,
      "sha256": "a3f8b2c19d4e..."
    }
  ]
}
```

### `IR-XXXX_findings.json` — Verified findings

```json
{
  "total_findings": 18,
  "hallucination_score": 0.056,
  "technique_count": 14,
  "findings": [
    {
      "phase": "interrogate",
      "description": "administrator connected from external IP 102.20.90.8",
      "confidence": "high",
      "ioc_value": "102.20.90.8",
      "evidence_sample": [...]
    }
  ]
}
```

### `IR-XXXX_navigator.json` — ATT&CK Navigator layer

Import at https://mitre-attack.github.io/attack-navigator/:

1. Open the Navigator
2. "Open Existing Layer" → "Upload from local"
3. Select the `.json` file

### `IR-XXXX_executive_summary.md` — Client report

Markdown ready to convert to PDF or Word. Contains:

- Executive summary
- ATT&CK techniques with evidence
- Key findings
- Recommended actions

### `forensic_audit.log` — Full audit trail

```jsonl
{"ts":"2026-06-03T07:14:22Z","tool":"evtx_to_sqlite","args":{"evtx_path":"/cases/..."},"result":"ok, 44281 events"}
{"ts":"2026-06-03T07:14:35Z","tool":"query_forensic_db","args":{"question":"external IPs?"},"result":"234 rows"}
```

Each line = one tool call. Useful for chain of custody.

### `hallucination_score` — How to interpret it

| Score | Meaning | Action |
|-------|---------|--------|
| 0.0–10% | Clean | Trust the findings |
| 10–25% | Review | Manually validate the `contradicted` items |
| >25% | High risk | Re-investigate before reporting |

---

## 9. Troubleshooting

### "No module named 'fastmcp'"

```bash
pip3 install fastmcp>=3.4.0
```

### "No module named 'vanna'"

```bash
pip3 install "vanna[chromadb]"
```

### "EvtxECmd not found" when parsing EVTX

The system will automatically use `python-evtx` as a fallback. To install EvtxECmd on SIFT:

```bash
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll --help
```

### "claude: command not found"

Claude Code CLI is not installed or not in PATH:

```bash
which claude
# If nothing appears, follow install instructions at claude.ai/code
```

### MCP server does not connect to Claude Code

Verify the path in `settings.json` is absolute and correct:

```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 "dfirllama"
# Should show the full path to server.py
```

### Ollama not responding

```bash
ollama serve       # start the server
ollama list        # check installed models
ollama pull mistral:7b  # download the model if missing
```

### "timeout" in analyze_ioc

The ReAct agent waits for external API responses (ipinfo.io, Google DNS). In air-gap environments these calls will fail. The agent will continue without those results and mark the IOC as "unverified". To force full air-gap mode, block the calls at the network level.

### Benchmark results do not match the paper

The `--dry-run` benchmark uses ground truth SQL directly (F1=100%). For results with a live LLM, configure Ollama first:

```bash
python3 benchmark/run_benchmark.py --model mistral:7b --db demo/data/tslsm_demo.db
```

---

## 10. Tool Quick Reference

### Calling tools directly from Python

```python
import sys
sys.path.insert(0, '/path/to/dfirllama-sift')

# NL→SQL over EVTX
from tools.nlsql import query_nl
result = query_nl('/tmp/Security.db', 'Were there mass login failures?')
print(result['sql'])          # generated SQL
print(result['row_count'])    # rows returned
print(result['results'])      # data

# Parse EVTX
from tools.evtx_tools import evtx_to_sqlite
r = evtx_to_sqlite('/cases/Security.evtx')
db_path = r['db_path']        # use this in query_nl

# Investigate IOC
from tools.ioc_tools import analyze_ioc
r = analyze_ioc('102.20.90.8', 'ip')
print(r['verdict'])

# Extract IOCs from text
from tools.ioc_tools import extract_iocs
r = extract_iocs("IP 192.168.1.1 connected to evil.com on 2024-06-22")
print(r['iocs'])

# Map to MITRE ATT&CK
from tools.sift_tools import map_to_mitre
r = map_to_mitre("PowerShell executed Base64 payload. African IP in RDP logs.", "IR-001")
print(r['technique_count'])
# r['navigator_layer'] → import in attack-navigator

# Validate findings
from tools.validator import validate_findings
findings = [
    {"description": "Admin from 102.20.90.8", "ioc_type": "ip",
     "ioc_value": "102.20.90.8", "confidence": "high",
     "evidence_citation": "EventId=21 RemoteHost=102.20.90.8"}
]
r = validate_findings(findings, evidence_db='/tmp/Security.db')
print(r['hallucination_score'])  # 0.0 = all verified
print(r['needs_correction'])     # True if contradictions found
```

### Zimmerman Tools from Python

```python
from tools.zimmerman_tools import amcache_parse, prefetch_parse, registry_query

# Program execution history
r = amcache_parse('/cases/Amcache.hve')
print(r['summary']['suspicious_paths'])   # executables in suspicious paths

# Execution timestamps
r = prefetch_parse('/cases/Windows/Prefetch/')
print(r['suspicious_executables'])        # powershell, cmd, mshta, etc.

# Registry persistence
r = registry_query('/cases/NTUSER.DAT',
                   'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
print(r['data'])
```

### Available Environment Variables

| Variable | Default | Description |
|---------|---------|-------------|
| `LLM_BACKEND` | `auto` | `auto`, `claude-cli`, `claude-api`, `ollama` |
| `ANTHROPIC_API_KEY` | — | Anthropic API key (if LLM_BACKEND=claude-api) |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama server URL |
| `OLLAMA_MODEL` | `mistral:7b` | Model to use with Ollama |
| `CLAUDE_MODEL` | `claude-haiku-4-5-20251001` | Claude model to use |
| `EVIDENCE_ROOT` | `/cases` | Evidence root directory (path guardrail) |
| `AUDIT_LOG` | `/tmp/dfirllama_audit.log` | Audit trail path |
| `CHROMA_PATH` | `/tmp/dfirllama_chroma` | Vanna vector database path |

---

## Output File Structure

```
./analysis/                          ← output directory
├── evidence_manifest.json           ← inventory with SHA256 hashes
├── orient_results.json              ← temporal axis and EVTX stats
├── interrogate_findings.json        ← NL→SQL triage findings
├── enrich_results.json              ← IOC investigation results
├── validation_results.json          ← validate_findings with hallucination_score
├── eil_session.json                 ← EIL session metadata
├── IR-XXXX_findings.json            ← full JSON report
├── IR-XXXX_navigator.json           ← ATT&CK Navigator layer
├── IR-XXXX_executive_summary.md     ← client report
└── forensic_audit.log               ← JSONL audit trail of every tool call
```

---

*DFIRLlama-SIFT v1.0 — SANS FIND EVIL! Hackathon 2026*  
*DFIRLlama Research*  
*MIT License — TLP:CLEAR*
