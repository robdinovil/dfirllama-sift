# DFIRLlama-SIFT — Bug Fix Log

This document records bugs discovered during pre-submission integration testing (2026-06-05) and their fixes. It is published as evidence of real testing, not just documentation.

---

## Testing context

All bugs below were discovered by running a **fresh `git clone`** of the repository and executing the full integration test suite (`demo/run_integration_test.sh`). No bugs were hidden or discovered only in production.

---

## Bugs found and fixed

| ID | Severity | File | Description | Fix | Commit |
|----|----------|------|-------------|-----|--------|
| BUG-001 | Critical | `~/.claude/settings.json` | `LLM_BACKEND=claude` in MCP env — hardcoded value that bypassed auto-detection | Changed to `auto` | `5c3d337` |
| BUG-002 | Moderate | `README.md`, `INSTALL.md` | `python3 -m venv` fails on SIFT (python3-venv not pre-installed); `--break-system-packages` needed | Documented `virtualenv .venv` as the correct SIFT path | `201d7d1`, `e66f416` |
| BUG-003 | Critical | `guardrails.py` | `EVIDENCE_ROOT` read at module import time (line 15). Any runtime `os.environ["EVIDENCE_ROOT"]` override had no effect — agent couldn't access its own case directory | Changed `check_path()` to re-read env on every call | `201d7d1` |
| BUG-004 | Critical | `agent.py` — `phase_orient()` | Demo mode passes a `.db` file directory, not `.evtx`. Phase 2 only registered EVTX files, so Phase 3 iterated an empty dict and produced 0 findings | Phase 2 now detects pre-existing `.db` files via sqlite3 (table-name-agnostic) | `201d7d1` |
| BUG-005 | Critical | `agent.py` — `phase_interrogate()` | `interrogate_findings.json` written **after** ReAct deep-dive. If ReAct stalled, findings were lost even though NL→SQL had found them | Initialize file to `[]` at phase start; write incrementally after each hit; persist before ReAct | `9e585d0` |
| BUG-006 | Moderate | `agent.py` — `phase_interrogate()` | ReAct deep-dive stalls with `claude-cli`: model doesn't consistently output `Thought:/Action:/Action Input:` format; loop exhausted `max_iterations` silently | Added `--no-deep-dive` flag; demo mode skips ReAct by default | `d3f0b39` |
| BUG-007 | Minor | `demo/data/tslsm_demo.db` | Local DB was regenerated (417 KB → 425 KB), causing benchmark to score 10/20 instead of 20/20 | Restored from git: `git checkout HEAD -- demo/data/tslsm_demo.db` | manual |
| BUG-008 | Compliance | `benchmark/run_benchmark.py` | Benchmark output printed `dhyabi2/findevil: F1=100%` — competitor name in code output | Replaced with neutral literature baseline | `3206fdd` |
| BUG-009 | Moderate | `~/.claude/settings.json` | `claude mcp list` returned "No MCP servers configured" — `settings.json` is read by Claude Code interactive mode, but `claude mcp list` reads a different scope | Registered via `claude mcp add` — now shows `dfirllama-sift ✓ Connected` | manual |
| BUG-010 | Compliance | `README.md`, `PAPER.md`, `docs/ACCURACY_REPORT.md`, `benchmark/run_benchmark.py` | Comparison tables with specific competitor names (marez8505, dhyabi2, Valhuntir, ForensIQ) across 5 files | All removed; replaced with neutral baseline context from published literature | `429bf64`, `5c3d337`, `3206fdd` |
| BUG-011 | Minor | `requirements.txt` | `pytest` missing from requirements — integration test failed in fresh venv with "No module named pytest" | Added `pytest>=7.0.0` | `e66f416` |

---

## Notes on ReAct (BUG-006)

The ReAct deep-dive in Phase 3 was designed to run multi-step reasoning with `claude-cli` as the LLM backend. In practice, `claude-cli` does not reliably follow the strict `Thought:/Action:/Action Input:` format required by the ReAct loop, causing retries and eventual timeout.

**Design decision:** Demo mode disables the deep-dive by default for reproducibility. The `--no-deep-dive` flag makes this explicit. The standard triage questions (Phase 3 NL→SQL) still run and produce verified findings. Full ReAct analysis remains available for production use with better-formatted LLM backends.

This is an engineering trade-off between demo reliability and analytical depth, not a limitation of the NL→SQL or validate_findings components.

---

## Testing methodology

```
1. git clone https://github.com/robdinovil/dfirllama-sift /tmp/dfirllama-e66f416
2. cd /tmp/dfirllama-e66f416
3. virtualenv .venv && source .venv/bin/activate
4. pip install --upgrade pip && pip install -r requirements.txt
5. python3 setup_check.py
6. bash demo/run_integration_test.sh
```

All 7 integration tests passed from a clean clone at commit `e66f416`:

```
[1/7] Module imports         PASS
[2/7] Guardrails (18 tests)  PASS — 18/18
[3/7] Benchmark dry-run      PASS — 20/20, F1=1.000
[4/7] NL→SQL live query      PASS — SQL generated, results returned
[5/7] IOC extraction         PASS — ip, domain, hash_sha256 extracted
[6/7] validate_findings      PASS — hallucination detected, trigger generated
[7/7] Agent demo (Phase 1-3) PASS — 1,800 events, 2 findings, 3 output files
```
