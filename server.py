#!/usr/bin/env python3
"""
DFIRLlama-SIFT — MCP Server
SANS FIND EVIL! Hackathon 2026

Un servidor MCP que conecta agentes AI a capacidades forenses de SIFT,
incluyendo análisis NL→SQL sobre EVTX (diferenciador único).

Uso:
    python3 server.py                  # stdio mode (Claude Desktop)
    python3 server.py --http :8080     # HTTP mode (testing)

Variables de entorno:
    LLM_BACKEND         auto | claude-cli | claude-api | ollama  (default: auto)
    ANTHROPIC_API_KEY   required if LLM_BACKEND=claude-api
    OLLAMA_BASE_URL     default: http://localhost:11434/v1
    OLLAMA_MODEL        default: mistral:7b
    EVIDENCE_ROOT       directorio raíz de evidencia (guardrail)
"""

import sys
import os
from pathlib import Path

# Agregar el directorio raíz al path para que las herramientas se importen bien
sys.path.insert(0, str(Path(__file__).parent))

from fastmcp import FastMCP

# Importar herramientas
from tools.evtx_tools import evtx_to_sqlite, query_evtx_nl
from tools.nlsql import query_nl
from tools.ioc_tools import analyze_ioc, extract_iocs
from tools.sift_tools import volatility_run, log2timeline_run, yara_scan, map_to_mitre
from tools.zimmerman_tools import (
    amcache_parse, prefetch_parse, shimcache_parse, registry_query,
    mft_timeline, lnk_parse, shellbag_parse, jumplist_parse, recycle_bin_parse,
)
from tools.forensic_tools import bulk_extract, pcap_analyze, strings_extract, file_hash
from tools.validator import validate_findings
from llm.client import get_model_name

# ── Inicializar servidor ──────────────────────────────────────────────────────

mcp = FastMCP(
    name="DFIRLlama-SIFT",
    instructions=(
        "You are a DFIR analyst assistant with access to forensic tools from the SIFT workstation "
        "and the DFIRLlama NL→SQL engine for EVTX analysis. "
        "All evidence access is read-only. All tool calls are logged to an audit trail. "
        "Available tools:\n"
        "- evtx_to_sqlite: parse .evtx to SQLite\n"
        "- query_evtx_nl: ask forensic questions in natural language over EVTX events\n"
        "- volatility_run: run Volatility3 plugins on memory images\n"
        "- log2timeline_run: build supertimeline with plaso\n"
        "- yara_scan: scan files with YARA rules\n"
        "- analyze_ioc: investigate IPs, domains, URLs, hashes with a ReAct agent\n"
        "- extract_iocs: extract structured IOCs from text\n"
        "- map_to_mitre: map triage findings to MITRE ATT&CK techniques\n\n"
        "Workflow for 'find evil' investigations:\n"
        "1. Parse EVTX files with evtx_to_sqlite\n"
        "2. Ask forensic questions with query_evtx_nl to find suspicious activity\n"
        "3. Investigate suspicious IPs/domains with analyze_ioc\n"
        "4. Map findings to MITRE ATT&CK with map_to_mitre\n"
        "5. If memory image available, run volatility_run plugins\n"
    ),
)


# ── Registrar herramientas ────────────────────────────────────────────────────

@mcp.tool()
def evtx_to_sqlite_tool(evtx_path: str, output_db: str = "") -> dict:
    """
    Parse a Windows .evtx event log file into a SQLite database for analysis.
    Uses EvtxECmd (Zimmerman tools) when available, falls back to python-evtx.
    Returns the SQLite path and basic statistics (event count, time range, top Event IDs).

    Args:
        evtx_path: Absolute path to the .evtx file to parse.
        output_db: Optional output SQLite path. Defaults to /tmp/<name>.db
    """
    return evtx_to_sqlite(evtx_path, output_db or None)


@mcp.tool()
def query_evtx_nl_tool(db_path: str, question: str, train_first: bool = False) -> dict:
    """
    (alias → query_forensic_db_tool: usa el motor NL→SQL propio cuando Vanna no está disponible)
    """
    r = query_nl(db_path, question)
    if r["ok"]:
        return r
    # fallback a Vanna si está disponible
    return query_evtx_nl(db_path, question, train_first)


@mcp.tool()
def query_forensic_db_tool(db_path: str, question: str) -> dict:
    """
    Ask a forensic question in natural language about a parsed EVTX SQLite database.
    Translates the question to SQL using the DFIRLlama NL→SQL engine, executes it,
    and returns the exact results. Works with any configured LLM backend.
    This is the DFIRLlama differentiator — no other SIFT tool provides this capability.

    Example questions:
    - "Were there any external RDP connections?"
    - "Show PowerShell executions with -ExecutionPolicy Bypass"
    - "Did the administrator account connect from multiple different IPs on the same day?"
    - "Were there any log clearing events (EventId 1102)?"

    Args:
        db_path:     Path to the SQLite database created by evtx_to_sqlite.
        question:    Forensic question in English or Spanish.
        train_first: Unused (kept for compatibility). NL→SQL engine auto-detects schema.
    """
    return query_nl(db_path, question)


@mcp.tool()
def volatility_run_tool(image_path: str, plugin: str, plugin_args: str = "") -> dict:
    """
    Run a Volatility3 plugin on a memory image (read-only).
    Safe plugins only — no write operations permitted.

    Available plugins: windows.pslist, windows.pstree, windows.cmdline, windows.dlllist,
    windows.netscan, windows.netstat, windows.malfind, windows.handles, windows.filescan,
    windows.registry.printkey, windows.registry.hivelist, windows.hashdump, windows.sessions,
    linux.pslist, linux.bash, linux.check_modules.

    Args:
        image_path:  Absolute path to the memory image (.raw, .vmem, .lime, .mem).
        plugin:      Volatility3 plugin name (e.g., "windows.pslist").
        plugin_args: Additional plugin arguments as a string (e.g., "--pid 1234").
    """
    return volatility_run(image_path, plugin, plugin_args)


@mcp.tool()
def log2timeline_run_tool(artifact_path: str, output_dir: str = "",
                           filter_str: str = "") -> dict:
    """
    Run plaso (log2timeline) on an artifact to generate a supertimeline.
    Processes the artifact read-only and writes output to a temporary directory.

    Args:
        artifact_path: Path to artifact (EVTX file, disk image, or directory).
        output_dir:    Optional output directory. Defaults to /tmp/dfirllama_plaso_*/
        filter_str:    Optional time filter (e.g., "2024-06-01 00:00:00 2024-06-30 23:59:59").
    """
    return log2timeline_run(artifact_path, output_dir or None, filter_str)


@mcp.tool()
def yara_scan_tool(target_path: str, rules_path: str,
                   recursive: bool = True, timeout: int = 60) -> dict:
    """
    Scan a file or directory with YARA rules (read-only).

    Args:
        target_path: Path to the file or directory to scan.
        rules_path:  Path to a .yar file or directory containing YARA rules.
        recursive:   If True, scan subdirectories recursively.
        timeout:     Per-file scan timeout in seconds.
    """
    return yara_scan(target_path, rules_path, recursive, timeout)


@mcp.tool()
def analyze_ioc_tool(ioc_value: str, ioc_type: str = "auto") -> dict:
    """
    Investigate an IOC using a ReAct agent with threat intelligence tools.
    The agent autonomously decides which tools to use (base64 decode, WHOIS, DNS, GeoIP,
    threat blocklist) and provides a final verdict with confidence level.

    Best for: suspicious IPs, domains, URLs, PowerShell commands with encoded payloads.

    Args:
        ioc_value: The IOC to analyze — IP address, domain, URL, PowerShell command, or SHA256 hash.
        ioc_type:  Hint for the agent: "ip", "domain", "url", "hash", "powershell", or "auto".
    """
    return analyze_ioc(ioc_value, ioc_type)


@mcp.tool()
def extract_iocs_tool(text: str) -> dict:
    """
    Extract all Indicators of Compromise from a block of text using structured JSON output.
    Identifies IPs, domains, URLs, SHA256/MD5 hashes, registry keys, and filenames.
    Output is directly importable to MISP, TheHive, and Elastic SIEM.

    Args:
        text: Text from a threat intelligence report, EDR alert, triage notes, or any IR text.
    """
    return extract_iocs(text)


@mcp.tool()
def map_to_mitre_tool(findings_text: str, incident_id: str = "IR-UNKNOWN") -> dict:
    """
    Map forensic triage findings (free text) to MITRE ATT&CK techniques using structured output.
    Returns a JSON with technique IDs, tactics, evidence, confidence levels, and
    an ATT&CK Navigator layer ready to import at mitre-attack.github.io/attack-navigator.

    Args:
        findings_text: Free-form triage notes as written by an analyst.
        incident_id:   Case identifier (e.g., "IR-2024-0622").
    """
    return map_to_mitre(findings_text, incident_id)


# ── Resources (contexto estático para el agente) ──────────────────────────────

@mcp.tool()
def amcache_parse_tool(hive_path: str, output_dir: str = "") -> dict:
    """
    Parse Windows Amcache.hve to extract program execution history.
    Returns executable names, SHA1 hashes, first execution timestamps, and paths.
    Key artifact for confirming malware execution with timestamps.

    Args:
        hive_path:  Path to Amcache.hve file.
        output_dir: Optional output directory for CSV files.
    """
    return amcache_parse(hive_path, output_dir or None)


@mcp.tool()
def prefetch_parse_tool(path: str, output_dir: str = "") -> dict:
    """
    Parse Windows Prefetch files (.pf) to recover execution history.
    Returns: executable name, last run time, run count, referenced files.
    Confirms execution and timing — stronger than ShimCache alone.

    Args:
        path:       Single .pf file or C:\\Windows\\Prefetch directory.
        output_dir: Optional output directory.
    """
    return prefetch_parse(path, output_dir or None)


@mcp.tool()
def shimcache_parse_tool(system_hive: str, output_dir: str = "") -> dict:
    """
    Parse AppCompatCache (ShimCache) from the SYSTEM registry hive.
    Records files that interacted with the OS — not proof of execution,
    but presence + Amcache/Prefetch together confirms execution.

    Args:
        system_hive: Path to SYSTEM hive (e.g., /mnt/case/Windows/System32/config/SYSTEM).
        output_dir:  Optional output directory.
    """
    return shimcache_parse(system_hive, output_dir or None)


@mcp.tool()
def registry_query_tool(hive_path: str, key_path: str = "",
                         output_dir: str = "") -> dict:
    """
    Query Windows registry hives with RECmd.
    If key_path is provided, extracts that specific key.
    If empty, runs RECmd batch files for full forensic extraction
    (persistence, USB history, network config, timezone, etc.)

    Args:
        hive_path: Path to registry hive (SYSTEM, SOFTWARE, NTUSER.DAT, etc.)
        key_path:  Specific registry key path (optional).
        output_dir: Optional output directory.
    """
    return registry_query(hive_path, key_path, output_dir or None)


@mcp.tool()
def mft_timeline_tool(mft_path: str, output_dir: str = "",
                       filter_path: str = "") -> dict:
    """
    Parse the Master File Table ($MFT) from an NTFS volume.
    Extracts all file timestamps (CREATED, MODIFIED, ACCESSED, ENTRY_MODIFIED).
    Automatically detects timestomping by comparing $STANDARD_INFORMATION vs $FILE_NAME timestamps.
    Includes records for deleted files.

    Args:
        mft_path:    Path to extracted $MFT file.
        output_dir:  Optional output directory.
        filter_path: Optional path filter (e.g., "Users\\victim\\AppData").
    """
    return mft_timeline(mft_path, output_dir or None, filter_path)


@mcp.tool()
def lnk_parse_tool(path: str, output_dir: str = "") -> dict:
    """
    Parse Windows LNK (shortcut) files with LECmd.
    Reveals: files opened by the user, source path, timestamps, volume serial numbers.
    Useful for establishing access to files on external media even after disconnection.

    Args:
        path:       Single .lnk file or directory (e.g., C:\\Users\\X\\AppData\\Roaming\\Microsoft\\Windows\\Recent).
        output_dir: Optional output directory.
    """
    return lnk_parse(path, output_dir or None)


@mcp.tool()
def shellbag_parse_tool(hive_path: str, output_dir: str = "") -> dict:
    """
    Parse Windows Shellbags from NTUSER.DAT or UsrClass.dat with SBECmd.
    Records every folder the user visited — including on disconnected external drives
    and deleted folders. Evidence of access even without LNK files.

    Args:
        hive_path:  Path to NTUSER.DAT or UsrClass.dat.
        output_dir: Optional output directory.
    """
    return shellbag_parse(hive_path, output_dir or None)


@mcp.tool()
def jumplist_parse_tool(path: str, output_dir: str = "") -> dict:
    """
    Parse Windows Jump Lists with JLECmd.
    Shows recently accessed files per application — including files on network
    shares or USB drives. Stronger than browser history for document access.

    Args:
        path:       AutomaticDestinations or CustomDestinations directory, or single file.
        output_dir: Optional output directory.
    """
    return jumplist_parse(path, output_dir or None)


@mcp.tool()
def recycle_bin_parse_tool(path: str, output_dir: str = "") -> dict:
    """
    Parse Windows Recycle Bin ($Recycle.Bin) with RBCmd.
    Recovers: original filename, original path, deletion timestamp, file size.
    Evidence of anti-forensics attempts or deleted exfiltration staging files.

    Args:
        path:       $Recycle.Bin directory or specific $I file.
        output_dir: Optional output directory.
    """
    return recycle_bin_parse(path, output_dir or None)


@mcp.tool()
def bulk_extract_tool(target_path: str, output_dir: str = "",
                       carvers: list = []) -> dict:
    """
    Run bulk_extractor to carve forensic artifacts from disk images or memory dumps.
    Automatically extracts: IPs, email addresses, URLs, domains, MD5 hashes,
    Base64 chunks, JSON blobs. Works on raw binaries where file structure is unknown.

    Args:
        target_path: Disk image, memory dump, or large binary file.
        output_dir:  Optional output directory for feature files.
        carvers:     List of carvers to activate (default: ip, email, url, domain, md5, json, base64).
    """
    return bulk_extract(target_path, output_dir or None, carvers or None)


@mcp.tool()
def pcap_analyze_tool(pcap_path: str, filter_expr: str = "") -> dict:
    """
    Analyze a PCAP file with tshark and return a structured network summary.
    Includes: protocol hierarchy, top IP conversations, DNS queries,
    HTTP hosts, and external IPs (non-RFC1918).

    Args:
        pcap_path:   Path to .pcap or .pcapng file.
        filter_expr: Optional Wireshark display filter (e.g., "tcp.port == 443").
    """
    return pcap_analyze(pcap_path, filter_expr)


@mcp.tool()
def strings_extract_tool(file_path: str, min_len: int = 6,
                           encoding: str = "both") -> dict:
    """
    Extract strings from a binary, executable, or memory dump.
    Automatically classifies by forensic category: IPs, URLs, domains,
    registry keys, file paths, PowerShell patterns, emails, Base64 chunks.

    Args:
        file_path: Binary file, PE executable, or memory dump.
        min_len:   Minimum string length (default 6).
        encoding:  "ascii", "unicode", or "both" (default).
    """
    return strings_extract(file_path, min_len, encoding)


@mcp.tool()
def file_hash_tool(file_path: str) -> dict:
    """
    Calculate cryptographic and fuzzy hashes for evidence integrity verification.
    Returns MD5, SHA1, SHA256, SHA512, ssdeep (fuzzy hash), and file type.
    Use ssdeep to find similar malware variants even with minor modifications.

    Args:
        file_path: Path to the file to hash.
    """
    return file_hash(file_path)


@mcp.tool()
def validate_findings_tool(findings: list, evidence_db: str = "",
                             source_text: str = "") -> dict:
    """
    Validate investigation findings against real evidence to detect hallucinations.

    For each finding, verifies:
    - IOC format validity (IP octets, hash lengths, domain syntax, MITRE IDs)
    - Evidence exists in the SQLite database (if provided)
    - IOC values appear in the source text (if provided)
    - Timestamp format and date range validity

    Returns hallucination_score (0.0-1.0) and self_correction_triggers
    for findings that need re-investigation.

    When needs_correction=True: re-run the flagged queries in INTERROGATE phase
    before proceeding to REPORT.

    Args:
        findings:    List of finding dicts with keys: description, ioc_value,
                     ioc_type, mitre_technique, evidence_citation, timestamp, confidence.
        evidence_db: Path to SQLite DB from evtx_to_sqlite (optional but recommended).
        source_text: Raw source text for IOC presence verification (optional).
    """
    return validate_findings(
        findings,
        evidence_db or None,
        source_text or None,
    )


@mcp.resource("dfirllama://sift/status")
def get_status() -> str:
    """Estado del servidor y herramientas disponibles."""
    import subprocess
    tools_status = {}
    for tool, cmd in [("volatility3", ["vol", "--help"]),
                      ("EvtxECmd",    ["EvtxECmd", "--help"]),
                      ("log2timeline", ["log2timeline.py", "--version"]),
                      ("yara",        ["python3", "-c", "import yara; print(yara.__version__)"])]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
            tools_status[tool] = "available"
        except Exception:
            tools_status[tool] = "not found"

    return (
        f"DFIRLlama-SIFT MCP Server\n"
        f"LLM Backend: {os.getenv('LLM_BACKEND', 'auto')} ({get_model_name()})\n"
        f"Evidence Root: {os.getenv('EVIDENCE_ROOT', '/cases')}\n"
        f"SIFT Tools: {tools_status}\n"
    )


@mcp.resource("dfirllama://sift/dfir-cheatsheet")
def get_cheatsheet() -> str:
    """Cheat sheet de Event IDs y artefactos DFIR más relevantes para el análisis."""
    return """
WINDOWS EVENT IDS — DFIR CHEAT SHEET
======================================
4624  Logon exitoso          | 4625 Logon fallido
4648  Logon credenciales exp | 4688 Proceso creado
4698  Scheduled task creada  | 4702 Scheduled task modificada
4697  Servicio instalado     | 7045 Nuevo servicio
1102  Audit log cleared      | 4104 PowerShell script block
4720  Cuenta creada          | 4732 User added to group
4776  NTLM auth intentada    | 4768 Kerberos TGT request

RDP (TSLSM — TerminalServices-LocalSessionManager):
21=logon | 22=shell_start | 23=logoff | 24=disconnect | 25=reconnect

ARTEFACTOS DE EJECUCIÓN:
Prefetch: C:\\Windows\\Prefetch\\*.pf
AmCache: C:\\Windows\\appcompat\\Programs\\Amcache.hve
ShimCache: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache
BAM/DAM: HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{SID}
UserAssist: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist (ROT13)

PERSISTENCIA:
Run keys: HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
Scheduled Tasks: C:\\Windows\\System32\\Tasks\\
Services: HKLM\\SYSTEM\\CurrentControlSet\\Services\\

TRUST RECORDS (macros habilitadas):
HKCU\\Software\\Microsoft\\Office\\<ver>\\Word\\Security\\Trusted Documents\\TrustRecords
Últimos 4 bytes = FF FF FF 7F → usuario hizo click en "Enable Content"
"""


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="DFIRLlama-SIFT MCP Server")
    p.add_argument("--http", metavar="HOST:PORT",
                   help="Correr en modo HTTP (ej: :8080). Default: stdio para Claude Desktop.")
    p.add_argument("--transport", choices=["stdio", "sse", "streamable-http"],
                   default="stdio")
    args = p.parse_args()

    print(f"[*] DFIRLlama-SIFT MCP Server", file=sys.stderr)
    print(f"[*] LLM Backend: {os.getenv('LLM_BACKEND', 'auto')}", file=sys.stderr)
    print(f"[*] Transport: {args.transport}", file=sys.stderr)

    if args.http:
        host, _, port = args.http.partition(":")
        mcp.run(transport="streamable-http",
                host=host or "127.0.0.1",
                port=int(port or 8080))
    else:
        mcp.run(transport=args.transport)
