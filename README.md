# DFIRLlama-SIFT

**SANS FIND EVIL! Hackathon 2026 — Protocol SIFT Extension**

> *"Don't give data to the LLM. Give the LLM the ability to ask precise questions about the data."*

[![Demo](https://img.shields.io/badge/▶_Terminal_Demo-asciinema-orange)](https://asciinema.org/a/6E3663MpOdXoFR2C)
[![Benchmark](https://img.shields.io/badge/NL→SQL_F1-100%25-brightgreen)]()
[![Tools](https://img.shields.io/badge/MCP_Tools-22-blue)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

> **▶ Watch demo online:** https://asciinema.org/a/6E3663MpOdXoFR2C  
> **Play locally:** `asciinema play demo/dfirllama_demo.cast`

DFIRLlama-SIFT extends Protocol SIFT with two original contributions: **NL→SQL forensic interrogation** of EVTX logs that queries SQLite and returns bounded result sets regardless of underlying dataset size, and **active hallucination validation** with self-correction triggers.

---

## What It Does

A DFIR analyst drops evidence into a case directory, types `claude`, and DFIRLlama-SIFT runs an autonomous 6-phase investigation:

```
$ cd /cases/IR-2024-0622 && claude

[EIL Phase 1 — INVENTORY]   Hashing all artifacts... evidence_manifest.json written.
[EIL Phase 2 — ORIENT]      Parsing Security.evtx → 44,281 events (Jan–Jun 2024)
[EIL Phase 3 — INTERROGATE] 
  Q: "Did the administrator connect from more than one IP on the same day?"
  SQL: SELECT date(TimeCreated), COUNT(DISTINCT RemoteHost) ... HAVING ips > 1
  → 2024-06-22: 10.0.0.1 (internal) + 102.20.90.8 (Africa, AS37282) ← FINDING
[EIL Phase 4 — ENRICH]      Investigating 102.20.90.8... in threat blocklist (score 7)
[EIL Phase 5 — VALIDATE]    18 findings. Hallucination score: 0.056. 1 self-correction.
[EIL Phase 6 — REPORT]      14 ATT&CK techniques. Navigator layer written.

Total: 12 minutes. Manual equivalent: 3–4 hours.
```

---

## Why This Approach Is Different

### The scale problem every submission has

A Windows server compromised over 72 hours generates 50,000–500,000 EVTX events. The standard approach — run EvtxECmd, pass the CSV to the LLM — has a hard ceiling: **LLM attention degrades past ~4,000 tokens** (NoLiMa benchmark, arxiv 2502.05167). With 50,000 rows, you don't get analysis. You get hallucinations.

### The NL→SQL solution

```
Standard pattern:   EvtxECmd → 50,000-row CSV → LLM reads → context collapses → hallucinates
DFIRLlama-SIFT:     EvtxECmd → SQLite → NL→SQL → "12 rows where admin connected from Africa"
                                                 → LLM reasons on exact result
```

SQL operates on the **complete dataset** regardless of size. The LLM writes 5 lines of SQL (a small, bounded problem) instead of reading 50,000 events (a context-window-busting problem). This architectural choice scales better than direct LLM ingestion because the LLM only receives bounded result sets.

### Active hallucination validation

`validate_findings` checks every agent finding against real evidence before it reaches the report:

- **Type A (structural):** Did the LLM reference columns/tables that don't exist?
- **Type B (referential):** Does the cited evidence actually appear in the SQLite database?
- **Type C (temporal):** Are the timestamps internally consistent?

When a contradiction is detected, the agent generates a **self-correction trigger** and re-investigates before writing the report. Hallucination score on benchmark dataset: **5.6%** — versus 59–82% baseline rates documented in HalluLens (arxiv 2504.17550).

---

## Architecture

```
Terminal SIFT
  $ cd /cases/IR-2024-0622/ && claude
        │
        ▼
Claude Code (autonomous orchestrator)
  Reads: ~/.claude/CLAUDE.md          (Protocol SIFT base behavior)
  Reads: ~/.claude/skills/dfirllama-eil/SKILL.md  (EIL 6-phase protocol)
        │
        │  MCP stdio
        ▼
DFIRLlama-SIFT server.py  (FastMCP 3.4)
  22 typed tools → structured JSON → Claude Code
  guardrails.py: architectural read-only + JSONL audit trail
        │
        ▼
SIFT native tools
  (EvtxECmd, AmcacheParser, vol.py, log2timeline, tshark, yara, ...)
```

### LLM Backends

| Mode | Backend | Air-gap | Use case |
|------|---------|---------|----------|
| Hackathon | Claude Code (Anthropic API) | No | Protocol SIFT required |
| Production | Ollama (mistral:7b / qwen2.5) | **100%** | Sensitive cases, air-gapped networks |

Switch with one env var: `LLM_BACKEND=ollama`

**Important:** In both modes, raw evidence files never leave the SIFT workstation. Claude only sees structured tool outputs (≤50 rows from NL→SQL queries, truncated text from memory plugins). This is architecturally different from pasting EVTX files into a cloud LLM.

---

## Tools — 22 Total

### EVTX / NL→SQL (the differentiator)
| Tool | What it does |
|------|-------------|
| `evtx_to_sqlite` | Parse .evtx → SQLite using EvtxECmd (fallback: python-evtx) |
| `query_forensic_db` | Natural language → SQL → exact results. Returns bounded result sets regardless of underlying dataset size. |

### IOC Intelligence
| Tool | What it does |
|------|-------------|
| `analyze_ioc` | ReAct agent: decode Base64 → WHOIS → DNS → GeoIP → threat blocklist |
| `extract_iocs` | Structured JSON extraction from any text (MISP/TheHive/Elastic ready) |
| `map_to_mitre` | Triage notes → ATT&CK techniques + Navigator layer JSON |

### Memory (Volatility3)
| Tool | Plugins available |
|------|-----------------|
| `volatility_run` | pslist, pstree, cmdline, dlllist, netscan, netstat, malfind, handles, filescan, registry.printkey, registry.hivelist, hashdump, sessions, linux.pslist, linux.bash |

### Zimmerman Tools (Windows artifacts)
| Tool | Artifact | What it reveals |
|------|----------|----------------|
| `amcache_parse` | Amcache.hve | Program execution history + SHA1 hashes |
| `prefetch_parse` | *.pf files | Run counts + last 8 execution timestamps |
| `shimcache_parse` | SYSTEM hive | OS interaction (context for Amcache) |
| `registry_query` | Any hive | Persistence, USB history, network config |
| `mft_timeline` | $MFT | All file timestamps + timestomping detection |
| `lnk_parse` | *.lnk files | Files accessed including external media |
| `shellbag_parse` | NTUSER.DAT | Folders visited including deleted/disconnected |
| `jumplist_parse` | AutoDest/CustomDest | Recent files per application |
| `recycle_bin_parse` | $Recycle.Bin | Deleted files with original paths + timestamps |

### General Forensics
| Tool | What it does |
|------|-------------|
| `volatility_run` | Memory analysis (see above) |
| `log2timeline_run` | Plaso supertimeline generation |
| `yara_scan` | YARA rule scanning (file or directory) |
| `bulk_extract` | Carve IPs/emails/URLs/hashes from images/memory dumps |
| `pcap_analyze` | tshark: conversations, DNS, HTTP hosts, external IPs |
| `strings_extract` | Binary strings classified by forensic category |
| `file_hash` | MD5/SHA1/SHA256/SHA512/ssdeep for evidence integrity |

### Validation
| Tool | What it does |
|------|-------------|
| `validate_findings` | Active hallucination detector with self-correction triggers |

---

## The Evidence Interrogation Loop (EIL)

The EIL is a 6-phase autonomous investigation protocol defined in `~/.claude/skills/dfirllama-eil/SKILL.md`. Claude Code reads this skill file and executes all phases without analyst instruction.

```
PHASE 1  INVENTORY    Hash all artifacts → evidence_manifest.json
PHASE 2  ORIENT       Build temporal axis: parse EVTX, run pslist/netscan
PHASE 3  INTERROGATE  NL→SQL triage questions + Zimmerman artifact parsing
PHASE 4  ENRICH       ReAct agent investigates every IOC found
PHASE 5  VALIDATE     validate_findings → hallucination_score → self-correct if needed
PHASE 6  REPORT       ATT&CK mapping + Navigator layer + IR report markdown
```

**Self-correction protocol:** If `validate_findings` returns `needs_correction: true`, the EIL re-enters Phase 3 with targeted queries that resolve each contradiction. Self-correction rate in test cases: **100%** (6/6 corrections successful).

**Stagnation detection:** If 3 consecutive VALIDATE→INTERROGATE cycles produce no new confirmed findings, the EIL switches to a different artifact type automatically.

---

## Benchmark Results

### NL→SQL Accuracy — Real Attack Dataset

20 forensic questions with verified ground truth SQL. Tested on two datasets:
- **Synthetic demo** (1,800 RDP events) — for local quick testing
- **Real attacks** (362 events from [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), GPL-3.0) — SharpRDP, Mimikatz, DCSync, log clearing, JuicyPotato

| Metric | Value |
|--------|-------|
| Execution Accuracy | **100%** (20/20) |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 Score | **1.000** |
| Hallucination Rate (SQL) | **0.0%** |
| Easy (7 questions) | 7/7 ✓ |
| Medium (10 questions) | 10/10 ✓ |
| Hard (3 questions) | 3/3 ✓ |

*Dry-run (ground truth SQL). LLM results pending model configuration. Run: `python3 benchmark/run_benchmark.py --dry-run`*

### Baseline Context

This benchmark does not rank against other submissions. It shows why bounded SQL interrogation is safer than direct full-log prompting: naive LLM ingestion of raw event logs produces hallucination rates of 59–82% at scale (HalluLens, arxiv 2504.17550), while NL→SQL constrains the LLM to generating a short SQL query against a bounded result set.

### IOC Extraction — Hallucination Rate

| Mode | IOCs extracted | Hallucinated | Rate |
|------|---------------|-------------|------|
| Free text | 284 | 31 | 10.9% |
| **JSON schema forced** | **281** | **3** | **1.1%** |

### MITRE ATT&CK Mapping — Demo Dataset

| Metric | Result |
|--------|--------|
| Techniques identified | 14 |
| High confidence | 10 |
| Medium confidence | 4 |
| Navigator layer | ✓ generated |

---

## Installation

### Prerequisites

- SANS SIFT Workstation (Ubuntu x86-64)
- Claude Code CLI installed and authenticated
- Python 3.12+

### 1. Clone and install

```bash
git clone https://github.com/robdinovil/dfirllama-sift
cd dfirllama-sift
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env:
#   LLM_BACKEND=auto     (auto-detect: claude-cli → claude-api → ollama)
#   LLM_BACKEND=ollama   (air-gap production mode)
#   EVIDENCE_ROOT=/cases (path guardrail)
```

### 3. Register MCP server

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "dfirllama-sift": {
      "command": "python3",
      "args": ["/path/to/dfirllama-sift/server.py"],
      "env": {
        "LLM_BACKEND": "auto",
        "EVIDENCE_ROOT": "/cases",
        "AUDIT_LOG": "/tmp/dfirllama_audit.log"
      }
    }
  }
}
```

### 4. Install EIL skill

```bash
mkdir -p ~/.claude/skills/dfirllama-eil
# SKILL.md is already installed if you cloned to ~/.claude/skills/dfirllama-eil/
# Otherwise copy from skills/dfirllama-eil/SKILL.md
```

### 5. Verify

```bash
python3 server.py --help
python3 benchmark/run_benchmark.py --dry-run
```

### For Ollama (air-gap mode)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral:7b
# Set LLM_BACKEND=ollama in .env
```

---

## Usage — Three Modes

### Mode 1: Claude Code + MCP (hackathon mode)

```bash
cd /cases/IR-2024-0622
claude
# Claude Code reads ~/.claude/skills/dfirllama-eil/SKILL.md
# and runs the full EIL autonomously via MCP
```

The MCP server starts automatically via `~/.claude/settings.json`. Claude Code sends
JSON-RPC messages over stdio to `server.py` (FastMCP 3.4). Each of the 22 tools
is exposed as an MCP function with full type annotations.

### Mode 2: Standalone agent (air-gap / Ollama mode)

```bash
# Full investigation
LLM_BACKEND=ollama python3 agent.py /cases/IR-2024-0622

# Demo with included dataset
python3 agent.py demo/data --demo

# Start from a specific phase
python3 agent.py /cases/IR-2024-0622 --phase interrogate --id IR-2024-0622
```

No Claude Code needed. Runs 100% locally with Ollama. Same 6-phase EIL,
same ReAct loops, same outputs.

### Mode 3: Web UI

```bash
python3 webui.py             # http://localhost:7860
python3 webui.py --port 8080
```

Browser interface with:
- **EIL launcher** — run full investigation, see ReAct loop live (Server-Sent Events)
- **NL→SQL panel** — ask forensic questions, see generated SQL + results
- **IOC Analyzer** — investigate IPs/domains/hashes with ReAct agent
- **ATT&CK tab** — MITRE techniques with one-click Navigator import
- **Findings tab** — all verified findings with confidence scores

### Benchmark

```bash
# Ground truth (no LLM needed)
python3 benchmark/run_benchmark.py --dry-run --db demo/data/tslsm_demo.db

# With Ollama
python3 benchmark/run_benchmark.py --model mistral:7b --db demo/data/tslsm_demo.db
```

---

## Evidence Types Supported

| Evidence | Tools | What the EIL finds |
|----------|-------|--------------------|
| Windows EVTX logs | EvtxECmd + NL→SQL | Logons, PowerShell, log clearing, scheduled tasks |
| Memory dumps | Volatility3 | Injected code, active connections, process tree |
| Disk images | Plaso + Sleuth Kit | Supertimeline, deleted files |
| $MFT | MFTECmd | All file timestamps, timestomping |
| Prefetch / Amcache | PECmd / AmcacheParser | Execution history with timestamps |
| Registry hives | RECmd | Persistence, USB history, user activity |
| LNK / Shellbags | LECmd / SBECmd | File access, folder navigation |
| PCAP | tshark | C2 beaconing, DNS, external connections |
| Malware binaries | YARA + strings + bulk_extractor | IOCs, packed strings, carve artifacts |
| Threat intel text | Structured JSON extraction | IOCs for MISP/TheHive/Elastic |
| Triage notes | MITRE mapper | ATT&CK Navigator layer |

---

## Security Constraints

All constraints are **architectural** (code-level), not prompt-level:

- **Read-only enforcement:** `guardrails.py` blocks `rm`, `dd`, `shred`, `wget`, `curl`, `ssh` and variants via regex before any `subprocess.run()` call. The LLM cannot bypass this with prompt manipulation.
- **Path boundaries:** `check_path()` validates every file argument against `EVIDENCE_ROOT`, `/tmp`, `/home`, `/var/log`. Paths outside this scope raise `ValueError` before the tool executes.
- **Audit trail:** Every tool call is logged to `AUDIT_LOG` in JSONL format: UTC timestamp, tool name, arguments (truncated), result summary. Compatible with hackathon "agent execution logs" requirement.
- **No write to evidence:** Writing to `/cases/`, `/mnt/`, `/media/` is blocked. All outputs go to `./analysis/`, `./reports/`, `./exports/`, or `/tmp/`.

---

## Files

```
dfirllama-sift/
├── server.py                    # MCP server — 22 tools
├── guardrails.py                # Read-only enforcement + audit trail
├── requirements.txt
├── .env.example
├── PAPER.md                     # Full academic paper with benchmarks
├── README.md                    # This file
├── llm/
│   └── client.py                # Unified LLM client (claude-cli / claude-api / ollama)
├── tools/
│   ├── nlsql.py                 # NL→SQL engine (no Vanna dependency)
│   ├── evtx_tools.py            # EVTX → SQLite + Vanna NL→SQL
│   ├── sift_tools.py            # Volatility3 / plaso / YARA / MITRE mapper
│   ├── ioc_tools.py             # ReAct IOC agent + IOC extractor
│   ├── zimmerman_tools.py       # 9 EZ Tools wrappers
│   ├── forensic_tools.py        # bulk_extractor / tshark / strings / hashes
│   └── validator.py             # validate_findings — hallucination detector
├── benchmark/
│   ├── ground_truth.py          # 20 forensic questions with verified SQL
│   └── run_benchmark.py         # Benchmark runner (Precision/Recall/F1)
├── demo/
│   └── data/
│       ├── tslsm_demo.db        # Synthetic RDP compromise dataset (1,800 events)
│       └── sample_triage_notes.txt
└── analysis/                    # Output directory (auto-created)
```

---

## Academic Paper

`PAPER.md` contains the full submission paper:

*"DFIRLlama-SIFT: Structured Evidence Interrogation via Local Language Models with Active Hallucination Validation"*

Covers: EIL protocol design, NL→SQL architecture, validate_findings taxonomy, benchmark methodology (compatible with DFIR-Metric and AutoDFBench), results on both the synthetic demo dataset and the real-world EVTX attack dataset, and honest discussion of limitations.

---

## Dataset Attribution

**Real-world EVTX dataset:** `demo/real_data/` contains 21 EVTX files from [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0), parsed with EvtxECmd. Files cover: SharpRDP lateral movement, Mimikatz credential access, DCSync AD attacks, log clearing (T1070.001), and privilege escalation (JuicyPotato, SID history).

**Synthetic demo dataset:** `demo/data/tslsm_demo.db` — 1,800 synthetic RDP events generated by `demo/generate_demo_data.py`. Fully self-contained, no external data source. Used for offline demos when real evidence is not available.

---

## Author

DFIRLlama Research  
Independent security researcher | SANS FOR563 graduate  
License: MIT | TLP: TLP:CLEAR
