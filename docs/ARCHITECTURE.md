# DFIRLlama-SIFT — System Architecture

## Overview

DFIRLlama-SIFT extends Protocol SIFT as a Model Context Protocol (MCP) server that gives Claude Code structured, bounded access to SIFT forensic tools. The system separates three concerns: orchestration (Claude Code), structured evidence interrogation (MCP server + NL→SQL engine), and evidence access (SIFT native tools via subprocess).

---

## Component Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│  SANS SIFT Workstation (Ubuntu x86-64)                                │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  Claude Code  (autonomous orchestrator)                        │    │
│  │                                                                │    │
│  │  ~/.claude/CLAUDE.md                 ← Protocol SIFT base     │    │
│  │  ~/.claude/skills/dfirllama-eil/     ← EIL 6-phase protocol   │    │
│  │    SKILL.md                                                    │    │
│  └───────────────────────┬────────────────────────────────────-─┘    │
│                           │  JSON-RPC over stdio (MCP)                │
│  ┌────────────────────────▼───────────────────────────────────────┐  │
│  │  DFIRLlama-SIFT MCP Server  (server.py / FastMCP 3.4)          │  │
│  │  22 typed tools — structured JSON responses                     │  │
│  │                                                                  │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐  │  │
│  │  │  nlsql.py  │ │ ioc_tools  │ │ sift_tools │ │ zimmerman  │  │  │
│  │  │  NL→SQL    │ │ IOC/MITRE  │ │ Vol/Plaso  │ │ 9 EZ Tools │  │  │
│  │  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘  │  │
│  │        │               │               │               │          │  │
│  │  ┌─────▼───────────────▼───────────────▼───────────────▼──────┐ │  │
│  │  │  guardrails.py — path validation + command blocklist        │ │  │
│  │  │                  JSONL audit trail (every tool call)        │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  └────────────────────────┬───────────────────────────────────────-┘  │
│                            │  subprocess calls (read-only)              │
│  ┌─────────────────────────▼──────────────────────────────────────┐   │
│  │  SIFT Native Tools                                               │   │
│  │  EvtxECmd · AmcacheParser · MFTECmd · RECmd · SBECmd           │   │
│  │  Volatility 3 · log2timeline (plaso) · YARA                    │   │
│  │  bulk_extractor · tshark · strings                              │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Evidence (read-only)              Outputs                              │
│  /cases/  /mnt/  /media/           ./analysis/   ./reports/            │
│                                    ./exports/    /tmp/dfirllama/        │
└─────────────────────────────────────────────────────────────────────-─┘
```

---

## Data Flow

```
1. Analyst  →  cd /cases/IR-2024-0622 && claude
2. Claude Code reads ~/.claude/CLAUDE.md (Protocol SIFT base behavior)
3. Claude Code reads ~/.claude/skills/dfirllama-eil/SKILL.md (EIL protocol)
4. Claude Code initiates the 6-phase EIL autonomously
5. Each tool call → MCP JSON-RPC → server.py
6. guardrails.py validates path + command before any subprocess.run()
7. SIFT tool executes against read-only evidence → structured result (≤50 rows)
8. Result returns to Claude Code as typed JSON
9. validate_findings cross-checks every finding before the report
10. Self-correction: if needs_correction=true → re-enter Phase 3 with targeted queries
11. Report + audit trail write to ./analysis/
```

---

## Evidence Interrogation Loop (EIL)

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1  INVENTORY                                               │
│  file_hash all artifacts → evidence_manifest.json                │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2  ORIENT                                                  │
│  evtx_to_sqlite + volatility_run (pslist, netscan)               │
│  Build temporal axis; identify artifact types                    │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3  INTERROGATE                 ◄──── self-correction loop │
│  query_forensic_db (NL→SQL triage questions)                     │
│  Zimmerman artifact parsing (Amcache, Prefetch, MFT, LNK...)    │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 4  ENRICH                                                  │
│  analyze_ioc — ReAct loop for every IOC discovered              │
│  WHOIS · DNS · GeoIP · threat blocklist                         │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 5  VALIDATE                                                │
│  validate_findings → hallucination_score                         │
│  Type A (structural) · Type B (referential) · Type C (temporal) │
│  needs_correction=true → loop back to PHASE 3                   │
│  Stagnation guard: 3 dry cycles → switch artifact type          │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 6  REPORT                                                  │
│  map_to_mitre → ATT&CK Navigator layer                          │
│  generate_ir_report → structured markdown + findings JSON        │
└─────────────────────────────────────────────────────────────────┘
```

---

## NL→SQL Engine

```
Analyst question (natural language)
          │
          ▼
  LLM generates SQL
  (bounded problem: 5 lines vs 50,000 rows)
          │
          ▼
  SQLite execution against EVTX-derived database
          │
          ▼
  Result: ≤50 rows returned to Claude Code
  (LLM never sees the raw event log)
```

**Why this matters:** Direct LLM ingestion of a 50,000-event CSV exceeds the effective attention window (~4,000 tokens, NoLiMa arxiv 2502.05167) and produces hallucination rates of 59–82% (HalluLens arxiv 2504.17550). NL→SQL keeps the LLM task small and deterministic.

---

## LLM Backend Architecture

```
llm/client.py  (unified interface)
  │
  ├── claude-cli   →  spawn `claude` subprocess  (Protocol SIFT mode)
  ├── claude-api   →  Anthropic SDK direct        (claude-haiku-4-5 default)
  └── ollama       →  OpenAI-compatible endpoint  (air-gap / production)

LLM_BACKEND=auto  →  tries claude-cli first, then claude-api, then ollama
```

In all modes, raw evidence files stay on the SIFT workstation. Claude only receives structured tool outputs (bounded result sets, truncated plugin output).

---

## Security Architecture

```
Evidence integrity
  guardrails.py blocks writes to /cases/, /mnt/, /media/
  All outputs routed to ./analysis/, ./exports/, ./reports/, /tmp/dfirllama/

Command injection prevention
  Regex blocklist applied before every subprocess.run():
  rm · dd · shred · wget · curl · nc · ssh · mkfs · chmod · chown · ...

Path traversal prevention
  check_path() validates every file argument against:
  → EVIDENCE_ROOT (read-only source)
  → allowed output dirs (write targets)
  → /tmp/dfirllama (scratch space)
  Paths outside scope raise ValueError before the tool executes

Audit trail (JSONL, one entry per tool call)
  Fields: ts (UTC) · tool · args (truncated) · result_summary
          phase · duration_ms · token_usage · output_hash · finding_ids
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| NL→SQL instead of direct log ingestion | LLM attention degrades at scale; SQL constrains the LLM to a small, bounded task |
| MCP over LangChain/CrewAI | Protocol SIFT requirement; MCP provides typed tool schemas and stdio transport |
| guardrails.py at subprocess level | Architectural enforcement; cannot be bypassed by prompt injection |
| Structured JSON output schema | Reduces IOC hallucination from 10.9% (free text) to 1.1% (schema-enforced) |
| JSONL audit trail per tool call | Chain-of-custody requirement; each entry is an immutable timestamped record |
| validate_findings before report | Findings are cross-checked against actual evidence, not just LLM claims |
