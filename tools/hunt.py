"""
ATT&CK Hunt Engine — deterministic MITRE rule matching over forensic SQLite databases.

Two functions, both LLM-free and sub-second:
  threat_hunt(conn)         — run 19 MITRE rules, return structured hits
  ioc_correlate(ioc, conn)  — cross-table pivot search for any indicator

Used by:  triage_case_tool, investigate_case_tool, threat_hunt_tool,
          correlate_ioc_tool (server.py MCP tools)
"""

import sqlite3

import pandas as pd

from tools.confidence import enrich_hits


# ── MITRE ATT&CK detection rules ─────────────────────────────────────────────
# Each rule targets a specific technique using deterministic SQL.
# Rules are evaluated against the normalized evidence schema (tools/schema.py).

ATTACK_RULES = [
    # ── Process-based detection ───────────────────────────────────────────────
    {
        "id": "T1059.001", "severity": "HIGH",
        "name": "PowerShell Encoded Command",
        "table": "processes",
        "where": ("command_line LIKE '%-EncodedCommand%' "
                  "OR command_line LIKE '%-enc %' "
                  "OR command_line LIKE '%FromBase64String%'"),
        "cols": "pid, name, command_line, username",
    },
    {
        "id": "T1105", "severity": "HIGH",
        "name": "Ingress Tool Transfer (certutil / BITS / WebRequest)",
        "table": "processes",
        "where": ("command_line LIKE '%Invoke-WebRequest%' "
                  "OR command_line LIKE '%DownloadString%' "
                  "OR command_line LIKE '%certutil%url%' "
                  "OR command_line LIKE '%bitsadmin%transfer%'"),
        "cols": "pid, name, command_line",
    },
    {
        "id": "T1003", "severity": "CRITICAL",
        "name": "Credential Dumping Tools Detected",
        "table": "processes",
        "where": ("LOWER(name) IN ('mimikatz.exe','procdump.exe','wce.exe','fgdump.exe') "
                  "OR command_line LIKE '%sekurlsa%' "
                  "OR command_line LIKE '%lsadump%'"),
        "cols": "pid, name, command_line",
    },
    {
        "id": "T1078", "severity": "CRITICAL",
        "name": "Critical System Process Running as Non-System User",
        "table": "processes",
        "where": ("UPPER(username) NOT LIKE '%SYSTEM%' "
                  "AND UPPER(username) NOT LIKE '%SERVICE%' "
                  "AND UPPER(username) NOT LIKE '%LOCAL SERVICE%' "
                  "AND UPPER(username) NOT LIKE '%NETWORK SERVICE%' "
                  "AND name IN ('lsass.exe','services.exe','wininit.exe','csrss.exe','smss.exe')"),
        "cols": "pid, name, username, exe_path",
    },
    {
        "id": "T1036", "severity": "MEDIUM",
        "name": "Process Masquerading — Suspicious Execution Path",
        "table": "processes",
        "where": ("(exe_path LIKE '%\\Temp\\%' "
                  " OR exe_path LIKE '%\\AppData\\%' "
                  " OR exe_path LIKE '%\\Users\\Public\\%') "
                  "AND exe_path != ''"),
        "cols": "pid, name, exe_path, username",
    },
    # ── Scheduled task persistence ────────────────────────────────────────────
    {
        "id": "T1053.005", "severity": "HIGH",
        "name": "Scheduled Task with Suspicious Command",
        "table": "scheduled_tasks",
        "where": ("command LIKE '%Temp%' "
                  "OR command LIKE '%AppData%' "
                  "OR command LIKE '%-Enc%' "
                  "OR command LIKE '%DownloadString%'"),
        "cols": "task_name, command, author, run_as",
    },
    # ── Registry persistence ──────────────────────────────────────────────────
    {
        "id": "T1547.001", "severity": "MEDIUM",
        "name": "Registry Run Key Persistence",
        "table": "registry_keys",
        "where": "key_path LIKE '%\\Run%' OR key_path LIKE '%\\RunOnce%'",
        "cols": "key_path, value_name, value_data",
    },
    # ── Network-based detection ───────────────────────────────────────────────
    {
        "id": "T1071.001", "severity": "HIGH",
        "name": "C2 over HTTP/HTTPS — External Established Connection",
        "table": "network_connections",
        "where": ("state='ESTABLISHED' "
                  "AND remote_port IN (80,443,8080,8443) "
                  "AND remote_address NOT LIKE '10.%' "
                  "AND remote_address NOT LIKE '192.168.%' "
                  "AND remote_address NOT LIKE '127.%' "
                  "AND remote_address IS NOT NULL "
                  "AND remote_address != ''"),
        "cols": "remote_address, remote_port, pid, state",
    },
    {
        "id": "T1049", "severity": "MEDIUM",
        "name": "Non-Standard Outbound Port to External Host",
        "table": "network_connections",
        "where": ("state='ESTABLISHED' "
                  "AND remote_port NOT IN (80,443,22,21,25,53,3389,135,139,445) "
                  "AND remote_address NOT LIKE '10.%' "
                  "AND remote_address NOT LIKE '192.168.%' "
                  "AND remote_address NOT LIKE '127.%' "
                  "AND remote_address IS NOT NULL "
                  "AND remote_address != ''"),
        "cols": "remote_address, remote_port, pid, state",
    },
    # ── Event log-based detection ─────────────────────────────────────────────
    {
        "id": "T1110", "severity": "MEDIUM",
        "name": "Brute Force — Repeated Failed Logons",
        "table": "events",
        "where": "event_id = 4625",
        "cols": "COUNT(*) as failed_attempts, source_ip, username",
        "group_by": "source_ip, username",
        "having": "COUNT(*) > 5",
        "order_by": "failed_attempts DESC",
    },
    {
        "id": "T1078", "severity": "HIGH",
        "name": "Successful Logon from External IP",
        "table": "events",
        "where": ("event_id = 4624 "
                  "AND source_ip NOT LIKE '10.%' "
                  "AND source_ip NOT LIKE '192.168.%' "
                  "AND source_ip NOT LIKE '127.%' "
                  "AND source_ip IS NOT NULL "
                  "AND source_ip != ''"),
        "cols": "timestamp_utc, username, source_ip, computer",
    },
    # ── Sysmon-based detection ────────────────────────────────────────────────
    {
        "id": "T1059.001", "severity": "HIGH",
        "name": "Sysmon: Encoded PowerShell via Process Create",
        "table": "events",
        "where": ("event_id = 1 "
                  "AND (description LIKE '%-EncodedCommand%' "
                  "     OR description LIKE '%FromBase64String%' "
                  "     OR description LIKE '%-enc %' "
                  "     OR description LIKE '%IEX%')"),
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1055", "severity": "CRITICAL",
        "name": "Sysmon: Process Injection — LSASS Access",
        "table": "events",
        "where": "event_id = 10 AND description LIKE '%lsass%'",
        "cols": "timestamp_utc, computer, description",
    },
    {
        "id": "T1003.001", "severity": "CRITICAL",
        "name": "Sysmon: LSASS Memory Dump Attempt",
        "table": "events",
        "where": ("event_id = 1 "
                  "AND (description LIKE '%lsass%' "
                  "     OR description LIKE '%procdump%' "
                  "     OR description LIKE '%sekurlsa%')"),
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1071.001", "severity": "HIGH",
        "name": "Sysmon: Outbound Network Connection to External IP",
        "table": "events",
        "where": ("event_id = 3 "
                  "AND description NOT LIKE '%DestinationIp=10.%' "
                  "AND description NOT LIKE '%DestinationIp=192.168.%' "
                  "AND description NOT LIKE '%DestinationIp=127.%' "
                  "AND description LIKE '%Initiated=true%'"),
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1547.001", "severity": "HIGH",
        "name": "Sysmon: Registry Run Key Write",
        "table": "events",
        "where": ("event_id IN (12, 13, 14) "
                  "AND (description LIKE '%CurrentVersion\\Run%' "
                  "     OR description LIKE '%CurrentVersion\\RunOnce%')"),
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1105", "severity": "HIGH",
        "name": "Sysmon: Suspicious Download via certutil/bitsadmin/curl",
        "table": "events",
        "where": ("event_id = 1 "
                  "AND (description LIKE '%certutil%' "
                  "     OR description LIKE '%bitsadmin%' "
                  "     OR description LIKE '%DownloadString%' "
                  "     OR description LIKE '%Invoke-WebRequest%')"),
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1218", "severity": "HIGH",
        "name": "LOLBin Execution (certutil / regsvr32 / mshta / rundll32)",
        "table": "events",
        "where": ("event_id IN (1, 4688) "
                  "AND (description LIKE '%certutil%' "
                  "     OR description LIKE '%regsvr32%' "
                  "     OR description LIKE '%mshta%' "
                  "     OR description LIKE '%installutil%' "
                  "     OR description LIKE '%wscript%' "
                  "     OR description LIKE '%cscript%')"),
        "cols": "timestamp_utc, computer, username, description",
    },
    {
        "id": "T1070.001", "severity": "HIGH",
        "name": "Security Event Log Cleared (Defense Evasion)",
        "table": "events",
        "where": "event_id IN (1102, 4719)",
        "cols": "timestamp_utc, username, computer, description",
    },
]


def threat_hunt(conn: sqlite3.Connection) -> list[dict]:
    """
    Run all MITRE ATT&CK rules against the evidence database.
    Returns enriched hits with confidence scoring. LLM-free, ~0s.
    """
    hits = []
    for rule in ATTACK_RULES:
        cols    = rule["cols"]
        table   = rule["table"]
        where   = rule["where"]
        grp     = rule.get("group_by", "")
        having  = rule.get("having", "")
        order   = rule.get("order_by", "")

        sql = f"SELECT {cols} FROM {table} WHERE {where}"
        if grp:
            sql += f" GROUP BY {grp}"
        if having:
            sql += f" HAVING {having}"
        if order:
            sql += f" ORDER BY {order}"
        sql += " LIMIT 20"

        try:
            df = pd.read_sql(sql, conn)
            if not df.empty:
                hits.append({
                    "rule_id":  rule["id"],
                    "severity": rule["severity"],
                    "name":     rule["name"],
                    "table":    table,
                    "rows":     df,
                    "count":    len(df),
                })
        except Exception:
            pass  # table may not exist in all evidence sets

    return enrich_hits(hits)


def ioc_correlate(indicator: str, conn: sqlite3.Connection) -> dict:
    """
    Cross-table pivot search for an IOC (IP, hash, domain, username, process name).
    Returns all rows across all tables where the indicator appears. LLM-free, ~0s.
    """
    results: dict[str, pd.DataFrame] = {}
    ind_lower = indicator.lower()

    # Exact match on known IP/address columns
    exact_searches = [
        ("events",              "source_ip",      "timestamp_utc, event_id, username, computer"),
        ("network_connections", "remote_address", "protocol, remote_address, remote_port, local_address, state, pid"),
    ]
    for table, col, select_cols in exact_searches:
        try:
            df = pd.read_sql(
                f"SELECT {select_cols} FROM {table} WHERE {col} = ? LIMIT 50",
                conn, params=(indicator,)
            )
            if not df.empty:
                results[f"{table} ({col})"] = df
        except Exception:
            pass

    # Text search across string columns
    text_searches: dict[str, list[str]] = {
        "processes":       ["name", "command_line", "exe_path"],
        "scheduled_tasks": ["task_name", "command", "author"],
        "registry_keys":   ["key_path", "value_name", "value_data"],
        "events":          ["username", "description"],
    }
    for table, cols in text_searches.items():
        cond   = " OR ".join(f"LOWER({c}) LIKE ?" for c in cols)
        params = [f"%{ind_lower}%"] * len(cols)
        try:
            df  = pd.read_sql(f"SELECT * FROM {table} WHERE {cond} LIMIT 20", conn, params=params)
            key = f"{table} (text)"
            if not df.empty and key not in results:
                results[key] = df
        except Exception:
            pass

    return results
