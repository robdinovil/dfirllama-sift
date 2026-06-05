# Third-Party Notices

This file documents third-party components included in or used by DFIRLlama-SIFT, along with their licenses.

---

## Runtime Dependencies

All Python runtime dependencies are listed in `requirements.txt`. Each package retains its original license. Key dependencies:

| Package | License | Notes |
|---------|---------|-------|
| FastMCP | MIT | MCP server framework |
| Vanna.ai | MIT | NL→SQL training framework |
| ChromaDB | Apache 2.0 | Vector database for Vanna |
| pandas | BSD 3-Clause | Data manipulation |
| anthropic | MIT | Anthropic Python SDK |
| flask | BSD 3-Clause | Web UI |
| yara-python | Apache 2.0 | YARA Python bindings |
| python-whois | MIT | WHOIS lookups |
| requests | Apache 2.0 | HTTP client |

---

## Dataset Attribution

### Real-World EVTX Attack Samples (GPL-3.0)

**Source:** [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)  
**Author:** Samir Bousseaden  
**License:** GNU General Public License v3.0 (GPL-3.0)

**Files derived from this source:**

| File | Description |
|------|-------------|
| `demo/real_data/evtx/` | 21 EVTX files (SharpRDP, Mimikatz, DCSync, log clearing, JuicyPotato, Neshta 1.0) |
| `demo/real_data/real_attack.db` | SQLite database derived from the above EVTX files by parsing with EvtxECmd |

**GPL-3.0 notice:** These files are distributed under GPL-3.0. The derived SQLite database (`real_attack.db`) is a derivative work and also falls under GPL-3.0. Redistribution of these files must comply with GPL-3.0 terms. The full GPL-3.0 license text is available at: https://www.gnu.org/licenses/gpl-3.0.txt

**Scope:** The GPL-3.0 applies exclusively to the files listed above in `demo/real_data/`. The remainder of DFIRLlama-SIFT — including all source code, the synthetic dataset, and documentation — is licensed under MIT.

---

### Synthetic Demo Dataset (MIT)

**File:** `demo/data/tslsm_demo.db`  
**Generator:** `demo/generate_demo_data.py` (included in this repo)  
**License:** MIT (same as project)  
**Description:** 1,800 synthetic RDP compromise events. No real evidence, no third-party data, no SANS courseware content.

---

## SIFT Workstation Tools (Invoked as External Processes)

DFIRLlama-SIFT invokes SIFT-native tools as external subprocesses. These tools are **not bundled** with this repository and retain their original licenses:

| Tool | License | Notes |
|------|---------|-------|
| Volatility 3 | AGPL-3.0 | Not bundled; invoked via `python3 /opt/volatility3-2.20.0/vol.py` |
| EZ Tools (Zimmerman) | MIT | Not bundled; invoked via `dotnet /opt/zimmermantools/...` |
| Plaso / log2timeline | Apache 2.0 | Not bundled; invoked via `log2timeline.py` |
| YARA | BSD 3-Clause | Not bundled; invoked via `/usr/local/bin/yara` |
| bulk_extractor | Public Domain | Not bundled; invoked via `bulk_extractor` |
| tshark / Wireshark | GPL-2.0 | Not bundled; invoked via `tshark` |
| EvtxECmd | MIT | Not bundled; part of EZ Tools |

No SIFT tool source code or compiled binaries are included in this repository.

---

## Academic References

The benchmark methodology in this project references:

- **DFIR-Metric** — framework for evaluating DFIR LLM accuracy (cited as baseline)
- **AutoDFBench** — automated DFIR benchmarking framework
- **NoLiMa** (arxiv 2502.05167) — LLM attention degradation at scale
- **HalluLens** (arxiv 2504.17550) — LLM hallucination rates

These are cited for context only. No code or data from these works is included.
