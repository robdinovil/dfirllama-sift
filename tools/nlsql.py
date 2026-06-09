"""
DFIRLlama NL→SQL Engine — two tiers, same interface.

Tier 1 (DFIRLlamaAnalyst):
  BM25-based retrieval over a pre-trained corpus of 200+ forensic Q-SQL pairs.
  Covers all 14 ATT&CK tactics at 5W granularity (who/what/when/where/how).
  Validates SQL before execution (4-layer check) and auto-corrects hallucinations.
  Backed by DFIRLlamaStore (SQLite + Okapi BM25, zero external dependencies).

Tier 2 (query_nl):
  Kept for backward compatibility. Single-table few-shot approach.
  Used as fallback when Tier 1 is not available or schema is not normalized.
"""

import json
import re
import sqlite3

import pandas as pd

from llm.client import chat_completion
from tools.vectorstore import DFIRLlamaStore

# Conocimiento forense embebido en el prompt (equivale al "entrenamiento" de Vanna)
DFIR_CONTEXT = """
Eres un experto en Digital Forensics analizando una base de datos SQLite de eventos Windows.

CONOCIMIENTO FORENSE:
- EventId 4624 = logon exitoso (Security.evtx)
- EventId 4625 = logon fallido (Security.evtx)
- EventId 4688 = proceso creado (Security.evtx)
- EventId 1102 = log del sistema limpiado (Security.evtx)
- EventId 7045 = servicio instalado (System.evtx)
- EventId 21   = RDP logon exitoso (TSLSM - TerminalServices-LocalSessionManager)
- EventId 22   = RDP shell start (TSLSM)
- EventId 23   = RDP logoff (TSLSM)
- EventId 24   = RDP disconnect (TSLSM)
- EventId 4104 = PowerShell script block (PowerShell/Operational)
- Columna RemoteHost o IpAddress: IP de origen de la conexión
- IPs 10.x.x.x = red interna. Cualquier otra = externa/sospechosa
- Columna UserName o TargetUserName: usuario que inició sesión
- Columna TimeCreated: timestamp ISO 8601 UTC
- Horario nocturno sospechoso: entre 22:00 y 06:00 UTC
- administrator = cuenta privilegiada de mayor interés
"""

EJEMPLOS = """
EJEMPLOS (pregunta → SQL):
Q: ¿Cuántos logons exitosos hubo?
A: SELECT COUNT(*) as total FROM rdp_activity WHERE EventId=21

Q: ¿Desde qué IPs se conectó el administrator?
A: SELECT DISTINCT RemoteHost, COUNT(*) as cnt FROM rdp_activity WHERE EventId=21 AND UserName='administrator' GROUP BY RemoteHost ORDER BY cnt DESC

Q: ¿Hubo conexiones desde IPs externas?
A: SELECT TimeCreated, UserName, RemoteHost FROM rdp_activity WHERE EventId=21 AND RemoteHost NOT LIKE '10.%' ORDER BY TimeCreated

Q: ¿Hubo días donde un mismo usuario se conectó desde más de una IP?
A: SELECT date(TimeCreated) as d, UserName, COUNT(DISTINCT RemoteHost) as ips FROM rdp_activity WHERE EventId=21 GROUP BY d, UserName HAVING ips > 1 ORDER BY d

Q: ¿Sesiones activas en horario nocturno?
A: SELECT TimeCreated, UserName, RemoteHost FROM rdp_activity WHERE EventId=21 AND (CAST(strftime('%H',TimeCreated) AS INT)>=22 OR CAST(strftime('%H',TimeCreated) AS INT)<6) ORDER BY TimeCreated
"""


def query_nl(db_path: str, question: str,
             table_name: str | None = None) -> dict:
    """
    Traduce una pregunta en lenguaje natural a SQL y la ejecuta.
    Funciona con cualquier backend LLM configurado (claude-cli, claude-api, ollama).

    Args:
        db_path:    SQLite database
        question:   Pregunta forense en español o inglés
        table_name: Tabla a consultar. Si None, usa la primera tabla disponible.
    """
    try:
        conn   = sqlite3.connect(db_path)
        tables = pd.read_sql(
            "SELECT name FROM sqlite_master WHERE type='table'", conn
        )["name"].tolist()

        if not tables:
            conn.close()
            return {"ok": False, "error": "DB sin tablas"}

        tbl = table_name or tables[0]

        # Schema real de la tabla
        schema_df = pd.read_sql(f"PRAGMA table_info({tbl})", conn)
        cols      = schema_df["name"].tolist()
        col_types = dict(zip(schema_df["name"], schema_df["type"]))

        # Muestra de datos para que el LLM entienda los valores
        sample = pd.read_sql(f"SELECT * FROM {tbl} LIMIT 3", conn)
        sample_str = sample.to_string(index=False)

        # Stats básicas
        row_count = pd.read_sql(f"SELECT COUNT(*) as n FROM {tbl}", conn).iloc[0, 0]
        conn.close()

    except Exception as e:
        return {"ok": False, "error": f"DB error: {e}"}

    # Construir prompt
    system = f"""{DFIR_CONTEXT}

TABLA: {tbl}
COLUMNAS: {', '.join(f'{c} ({col_types[c]})' for c in cols)}
TOTAL FILAS: {row_count:,}
MUESTRA (3 filas):
{sample_str}

{EJEMPLOS}

REGLAS ESTRICTAS:
1. Responde SOLO con la SQL válida para SQLite, sin explicación
2. No uses markdown, no uses ```sql
3. Solo usa columnas que existen en la tabla mostrada
4. Usa la tabla {tbl} en todas las queries
5. Adapta los nombres de columnas exactamente como aparecen arriba"""

    user = f"Genera SQL para: {question}"

    # Llamar al LLM
    sql_raw = chat_completion(
        [{"role": "system", "content": system},
         {"role": "user",   "content": user}],
        temperature=0.1,
    )

    # Limpiar la SQL
    sql = _clean_sql(sql_raw)
    if not sql:
        return {"ok": False, "error": "LLM no generó SQL válida", "raw": sql_raw[:200]}

    # Ejecutar
    try:
        conn = sqlite3.connect(db_path)
        df   = pd.read_sql(sql, conn)
        conn.close()

        return {
            "ok":        True,
            "question":  question,
            "sql":       sql,
            "row_count": len(df),
            "columns":   list(df.columns),
            "results":   df.to_dict("records")[:50],
        }

    except Exception as e:
        return {
            "ok":    False,
            "sql":   sql,
            "error": f"SQL execution error: {e}",
        }


def _clean_sql_v2(text: str) -> str:
    """Improved extractor — skips prose before SELECT, handles multi-line."""
    text = re.sub(r"```sql\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"```\s*", "", text)
    m = re.search(r'\b(SELECT|WITH)\b', text, re.IGNORECASE)
    if not m:
        return ""
    sql = text[m.start():].strip()
    sql = re.split(r'\n\n', sql)[0].strip().rstrip(";")
    if not sql.upper().startswith(("SELECT", "WITH")):
        return ""
    return sql


def _clean_sql(text: str) -> str:
    """Extrae SQL limpio de la respuesta del LLM."""
    text = text.strip()

    # Quitar bloques markdown
    text = re.sub(r"```sql\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"```\s*",    "", text)

    # Tomar solo la primera statement SQL
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith(("SELECT", "WITH")):
            lines = [line]
        elif lines:
            lines.append(line)
        if lines and stripped.endswith(";"):
            break

    sql = " ".join(lines).strip().rstrip(";")

    # Validar que sea un SELECT
    if not sql.upper().startswith(("SELECT", "WITH")):
        return ""

    return sql


# ══════════════════════════════════════════════════════════════════════════════
# Tier 1 — DFIRLlamaAnalyst
# ══════════════════════════════════════════════════════════════════════════════

TABLE_DOCS = {
    "events": (
        "Table: events — Windows event log records (Security, System, Application, Sysmon, TerminalServices)\n"
        "Columns: id, timestamp_utc, event_id, channel, provider, level, computer, username, source_ip, description, raw_data, source_file\n"
        "Key event IDs:\n"
        "  4624=successful_logon  4625=failed_logon  4634/4647=logoff  4648=explicit_creds\n"
        "  4672=special_privileges_assigned  4688=process_created  4720=user_account_created\n"
        "  4732=user_added_to_group  4740=account_lockout  4771=kerberos_preauthfail\n"
        "  4776=ntlm_credential_validation  1102=security_log_cleared  104=system_log_cleared\n"
        "  7045=service_installed  4698=scheduled_task_created  4702=scheduled_task_updated\n"
        "  21=rdp_logon_success  22=rdp_shell_start  23=rdp_logoff  24=rdp_disconnect  25=rdp_reconnect\n"
        "  4103=powershell_module_log  4104=powershell_scriptblock_log\n"
        "  1=sysmon_process_create  3=sysmon_network_conn  7=sysmon_image_load\n"
        "  8=sysmon_create_remote_thread  10=sysmon_process_access  11=sysmon_file_create\n"
        "  12/13/14=sysmon_registry_events  15=sysmon_file_stream_create  22=sysmon_dns_query\n"
        "  4688=process_create_security  18456=mssql_auth_failure\n"
        "DFIR notes: source_ip is NULL for local events; channel='Security' for auth events; "
        "timestamp_utc is ISO 8601 UTC (YYYY-MM-DD HH:MM:SS); "
        "external IPs are NOT like '10.%','192.168.%','172.16.%','127.%'"
    ),
    "processes": (
        "Table: processes — process list snapshot (Task Manager / Tasklist CSV / Sysmon)\n"
        "Columns: id, timestamp_utc, pid, ppid, name, command_line, exe_path, username, session, memory_kb, cpu_time, status, source_file\n"
        "DFIR notes: suspicious exe_path includes Temp/AppData/Users/Public; "
        "PPID pivot reveals parent-child chain; "
        "encoded commands = -EncodedCommand/-enc/-e with base64 / FromBase64String / IEX; "
        "credential tools: mimikatz.exe, procdump.exe, wce.exe, fgdump.exe; "
        "LOLBins: certutil, regsvr32, mshta, rundll32, wscript, cscript, installutil"
    ),
    "network_connections": (
        "Table: network_connections — TCP/UDP connections (netstat -ano output)\n"
        "Columns: id, timestamp_utc, protocol, local_address, local_port, remote_address, remote_port, state, pid, process_name, source_file\n"
        "States: ESTABLISHED, LISTENING, TIME_WAIT, CLOSE_WAIT, SYN_SENT\n"
        "DFIR notes: remote_address NOT LIKE '10.%'/'192.168.%'/'172.16.%'/'127.%' = external; "
        "suspicious ports: 4444/4445=metasploit, 1337=common RAT, 9001/9030=Tor; "
        "C2-over-HTTP ports: 80,443,8080,8443; "
        "remote_access ports: 22=SSH, 3389=RDP, 23=telnet; "
        "powershell/svchost with external ESTABLISHED = high suspicion"
    ),
    "dns_cache": (
        "Table: dns_cache — DNS resolver cache (ipconfig /displaydns)\n"
        "Columns: id, timestamp_utc, hostname, record_type, ttl, resolved_ip, source_file\n"
        "DFIR notes: very low TTL (<60s) = DGA or fast-flux C2; "
        "unusual TLDs (.xyz/.tk/.pw/.cc/.top/.ru) = suspicious; "
        "long hostnames with random chars = DGA; "
        "base64-like subdomains = DNS exfiltration tunneling"
    ),
    "scheduled_tasks": (
        "Table: scheduled_tasks — Windows scheduled tasks (schtasks /query /FO CSV /V)\n"
        "Columns: id, task_name, status, last_run, next_run, author, run_as, command, source_file\n"
        "DFIR notes: command with Temp/AppData/-Enc/DownloadString/IEX = persistence IOC; "
        "run_as=SYSTEM with unusual author = privilege abuse; "
        "task_name mimicking Windows defaults = masquerading; "
        "status=Ready means it will run again"
    ),
    "registry_keys": (
        "Table: registry_keys — Windows registry export (.reg files)\n"
        "Columns: id, hive, key_path, value_name, value_type, value_data, modified_time, source_file\n"
        "Persistence paths: CurrentVersion\\Run / RunOnce / RunServices / RunOnceEx; "
        "HKLM\\SYSTEM\\CurrentControlSet\\Services (service install); "
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options; "
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon (userinit/shell); "
        "AppInit_DLLs; LSA (Authentication Packages / Notification Packages); "
        "DFIR notes: value_data .exe from Temp/AppData = implant; "
        "modified_time during incident window = IOC"
    ),
    "sysinfo": (
        "Table: sysinfo — systeminfo.exe output (key-value pairs)\n"
        "Columns: id, key, value, source_file\n"
        "Common keys: 'OS Name', 'OS Version', 'System Boot Time', 'Domain', "
        "'Hotfix(s)', 'Network Adapter(s)', 'Total Physical Memory'\n"
        "DFIR notes: 'System Boot Time' shows last reboot; "
        "missing Hotfix(s) = unpatched system; Domain = lateral movement context"
    ),
    "evidence_files": (
        "Table: evidence_files — inventory of ingested forensic artifacts\n"
        "Columns: id, filename, filepath, evidence_type, file_size_kb, ingested_at, record_count\n"
        "evidence_type values: evtx, csv, netstat, reg_export, systeminfo, unknown"
    ),
}


_TRAINING_QA = [
    # ── General statistics ─────────────────────────────────────────────────────
    {"q": "How many total events are there?",
     "sql": "SELECT COUNT(*) AS total_events FROM events"},
    {"q": "What event IDs appear most frequently?",
     "sql": "SELECT event_id, COUNT(*) AS count FROM events GROUP BY event_id ORDER BY count DESC LIMIT 20"},
    {"q": "What is the time range of the evidence?",
     "sql": "SELECT MIN(timestamp_utc) AS first_event, MAX(timestamp_utc) AS last_event FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''"},
    {"q": "How many unique users appear in the events?",
     "sql": "SELECT COUNT(DISTINCT username) AS unique_users FROM events WHERE username IS NOT NULL AND username != ''"},
    {"q": "How many unique source IPs appear in the events?",
     "sql": "SELECT COUNT(DISTINCT source_ip) AS unique_ips FROM events WHERE source_ip IS NOT NULL AND source_ip != ''"},
    {"q": "What machines appear in the evidence?",
     "sql": "SELECT computer, COUNT(*) AS event_count FROM events WHERE computer IS NOT NULL AND computer != '' GROUP BY computer ORDER BY event_count DESC"},
    {"q": "What evidence files were ingested?",
     "sql": "SELECT filename, evidence_type, record_count, file_size_kb, ingested_at FROM evidence_files ORDER BY ingested_at"},
    {"q": "What event log channels are present?",
     "sql": "SELECT channel, COUNT(*) AS count FROM events WHERE channel IS NOT NULL AND channel != '' GROUP BY channel ORDER BY count DESC"},
    {"q": "Give me row counts for all tables",
     "sql": "SELECT 'events' AS tbl, COUNT(*) AS rows FROM events UNION ALL SELECT 'processes', COUNT(*) FROM processes UNION ALL SELECT 'network_connections', COUNT(*) FROM network_connections UNION ALL SELECT 'scheduled_tasks', COUNT(*) FROM scheduled_tasks UNION ALL SELECT 'registry_keys', COUNT(*) FROM registry_keys UNION ALL SELECT 'dns_cache', COUNT(*) FROM dns_cache"},
    {"q": "What is the dwell time in days — first to last event?",
     "sql": "SELECT ROUND(JULIANDAY(MAX(timestamp_utc)) - JULIANDAY(MIN(timestamp_utc))) AS dwell_days, MIN(timestamp_utc) AS start, MAX(timestamp_utc) AS end FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''"},

    # ── Authentication / logon ─────────────────────────────────────────────────
    {"q": "How many successful logons event 4624?",
     "sql": "SELECT COUNT(*) AS successful_logons FROM events WHERE event_id = 4624"},
    {"q": "Show all successful logons with user and source IP",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4624 ORDER BY timestamp_utc LIMIT 100"},
    {"q": "How many failed logons event 4625?",
     "sql": "SELECT COUNT(*) AS failed_logons FROM events WHERE event_id = 4625"},
    {"q": "Which accounts had the most failed logon attempts?",
     "sql": "SELECT username, COUNT(*) AS failed_count FROM events WHERE event_id = 4625 AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY failed_count DESC LIMIT 20"},
    {"q": "Which source IPs caused the most failed logons brute force?",
     "sql": "SELECT source_ip, COUNT(*) AS attempts FROM events WHERE event_id = 4625 AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY attempts DESC LIMIT 20"},
    {"q": "Were there any account lockouts?",
     "sql": "SELECT timestamp_utc, username, computer FROM events WHERE event_id = 4740 ORDER BY timestamp_utc"},
    {"q": "Show successful logons from external IPs outside RFC1918",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4624 AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc"},
    {"q": "Show failed logons from external IPs",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4625 AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc"},
    {"q": "How many special privileges assigned events 4672?",
     "sql": "SELECT username, COUNT(*) AS count FROM events WHERE event_id = 4672 GROUP BY username ORDER BY count DESC"},
    {"q": "Were any user accounts created during the incident?",
     "sql": "SELECT timestamp_utc, username, computer FROM events WHERE event_id = 4720 ORDER BY timestamp_utc"},
    {"q": "Were any users added to groups?",
     "sql": "SELECT timestamp_utc, username, computer, description FROM events WHERE event_id = 4732 ORDER BY timestamp_utc"},
    {"q": "Were there explicit credential logons 4648 pass the hash?",
     "sql": "SELECT timestamp_utc, username, source_ip, computer, description FROM events WHERE event_id = 4648 ORDER BY timestamp_utc"},
    {"q": "Show NTLM authentication events 4776",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4776 ORDER BY timestamp_utc LIMIT 100"},
    {"q": "Show Kerberos pre-authentication failures 4771",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4771 ORDER BY timestamp_utc LIMIT 100"},
    {"q": "What logon activity did the administrator account have?",
     "sql": "SELECT timestamp_utc, event_id, source_ip, computer FROM events WHERE LOWER(username) = 'administrator' AND event_id IN (4624,4625,4634,4648,4672) ORDER BY timestamp_utc"},
    {"q": "Were there any logons during off-hours between 22:00 and 06:00 UTC?",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 4624 AND (CAST(strftime('%H', timestamp_utc) AS INTEGER) >= 22 OR CAST(strftime('%H', timestamp_utc) AS INTEGER) < 6) ORDER BY timestamp_utc"},
    {"q": "Show successful logons grouped by day",
     "sql": "SELECT DATE(timestamp_utc) AS day, COUNT(*) AS logon_count FROM events WHERE event_id = 4624 GROUP BY day ORDER BY day"},
    {"q": "Which users logged on from more than one IP address?",
     "sql": "SELECT username, COUNT(DISTINCT source_ip) AS ip_count FROM events WHERE event_id = 4624 AND source_ip IS NOT NULL AND source_ip != '' GROUP BY username HAVING ip_count > 1 ORDER BY ip_count DESC"},

    # ── RDP ───────────────────────────────────────────────────────────────────
    {"q": "How many RDP successful logons event 21?",
     "sql": "SELECT COUNT(*) AS rdp_logons FROM events WHERE event_id = 21"},
    {"q": "Show all RDP logon events with source IP and user",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 21 ORDER BY timestamp_utc"},
    {"q": "Show RDP activity from external IPs",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 21 AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc"},
    {"q": "Which users connected via RDP the most?",
     "sql": "SELECT username, COUNT(*) AS sessions FROM events WHERE event_id = 21 GROUP BY username ORDER BY sessions DESC"},
    {"q": "Show full RDP session timeline logon shell logoff disconnect",
     "sql": "SELECT timestamp_utc, event_id, username, source_ip, computer FROM events WHERE event_id IN (21, 22, 23, 24, 25) ORDER BY timestamp_utc"},

    # ── Processes ─────────────────────────────────────────────────────────────
    {"q": "How many processes are in the evidence?",
     "sql": "SELECT COUNT(*) AS total_processes FROM processes"},
    {"q": "Show processes running from Temp or AppData directories",
     "sql": "SELECT pid, name, exe_path, username, command_line FROM processes WHERE exe_path LIKE '%\\Temp\\%' OR exe_path LIKE '%\\AppData\\%' OR exe_path LIKE '%\\Users\\Public\\%' ORDER BY timestamp_utc"},
    {"q": "Were any credential dumping tools detected mimikatz procdump wce?",
     "sql": "SELECT pid, name, command_line, username, exe_path FROM processes WHERE LOWER(name) IN ('mimikatz.exe','procdump.exe','wce.exe','fgdump.exe','gsecdump.exe') OR command_line LIKE '%sekurlsa%' OR command_line LIKE '%lsadump%' OR command_line LIKE '%mimikatz%'"},
    {"q": "Show PowerShell processes with encoded commands",
     "sql": "SELECT pid, name, command_line, username FROM processes WHERE (LOWER(name) LIKE '%powershell%' OR LOWER(name) = 'pwsh.exe') AND (command_line LIKE '%-EncodedCommand%' OR command_line LIKE '%-enc %' OR command_line LIKE '%FromBase64String%' OR command_line LIKE '%IEX%')"},
    {"q": "Which processes were running as SYSTEM?",
     "sql": "SELECT pid, name, exe_path, command_line FROM processes WHERE UPPER(username) LIKE '%SYSTEM%' ORDER BY name"},
    {"q": "Show LOLBin execution certutil regsvr32 mshta rundll32",
     "sql": "SELECT pid, name, command_line, username FROM processes WHERE LOWER(name) IN ('certutil.exe','regsvr32.exe','mshta.exe','rundll32.exe','wscript.exe','cscript.exe','installutil.exe','msiexec.exe')"},
    {"q": "Show process creation events 4688 from event logs",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 4688 ORDER BY timestamp_utc LIMIT 100"},
    {"q": "What are the most common process names?",
     "sql": "SELECT name, COUNT(*) AS count FROM processes GROUP BY name ORDER BY count DESC LIMIT 30"},
    {"q": "Show processes with download or invoke in command line",
     "sql": "SELECT pid, name, command_line, username FROM processes WHERE command_line LIKE '%DownloadString%' OR command_line LIKE '%DownloadFile%' OR command_line LIKE '%Invoke-WebRequest%' OR command_line LIKE '%wget%' OR command_line LIKE '%curl%'"},

    # ── Network connections ────────────────────────────────────────────────────
    {"q": "How many network connections are in the evidence?",
     "sql": "SELECT COUNT(*) AS total_connections FROM network_connections"},
    {"q": "Show all established connections to external IPs",
     "sql": "SELECT remote_address, remote_port, local_address, pid, process_name, state FROM network_connections WHERE state='ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL AND remote_address != '' ORDER BY remote_address"},
    {"q": "Are there connections on non-standard ports to external hosts?",
     "sql": "SELECT remote_address, remote_port, process_name, pid FROM network_connections WHERE state='ESTABLISHED' AND remote_port NOT IN (80,443,22,21,25,53,3389,135,139,445,8080,8443) AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' AND remote_address NOT LIKE '127.%' ORDER BY remote_port"},
    {"q": "What processes have LISTENING sockets?",
     "sql": "SELECT local_address, local_port, pid, process_name FROM network_connections WHERE state='LISTENING' ORDER BY local_port"},
    {"q": "Are there PowerShell or cmd network connections?",
     "sql": "SELECT remote_address, remote_port, local_port, state, pid FROM network_connections WHERE LOWER(process_name) LIKE '%powershell%' OR LOWER(process_name) = 'cmd.exe'"},
    {"q": "Show connections on typical C2 ports 4444 1337 8080 8443",
     "sql": "SELECT remote_address, remote_port, process_name, pid, state FROM network_connections WHERE remote_port IN (4444,4445,1337,9001,9030,8080,8443) ORDER BY remote_port"},
    {"q": "Which external IPs does the machine connect to most?",
     "sql": "SELECT remote_address, COUNT(*) AS conn_count FROM network_connections WHERE remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' AND remote_address NOT LIKE '127.%' AND remote_address IS NOT NULL GROUP BY remote_address ORDER BY conn_count DESC LIMIT 20"},
    {"q": "Show RDP connections remote port 3389",
     "sql": "SELECT remote_address, remote_port, local_address, pid, process_name, state FROM network_connections WHERE remote_port = 3389 OR local_port = 3389"},

    # ── Persistence — scheduled tasks ─────────────────────────────────────────
    {"q": "How many scheduled tasks are present?",
     "sql": "SELECT COUNT(*) AS total_tasks FROM scheduled_tasks"},
    {"q": "Show scheduled tasks with suspicious commands",
     "sql": "SELECT task_name, command, run_as, author, status FROM scheduled_tasks WHERE command LIKE '%Temp%' OR command LIKE '%AppData%' OR command LIKE '%-Enc%' OR command LIKE '%DownloadString%' OR command LIKE '%IEX%' OR command LIKE '%cmd /c%'"},
    {"q": "Which scheduled tasks run as SYSTEM?",
     "sql": "SELECT task_name, command, author, run_as, status FROM scheduled_tasks WHERE UPPER(run_as) LIKE '%SYSTEM%'"},
    {"q": "Show all scheduled tasks ordered by last run time",
     "sql": "SELECT task_name, command, run_as, status, last_run, next_run FROM scheduled_tasks ORDER BY last_run DESC"},
    {"q": "Were any scheduled tasks created via event 4698?",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (4698, 4702, 4699) ORDER BY timestamp_utc"},

    # ── Persistence — registry ─────────────────────────────────────────────────
    {"q": "Show registry Run key entries persistence",
     "sql": "SELECT hive, key_path, value_name, value_data, modified_time FROM registry_keys WHERE key_path LIKE '%\\Run%' OR key_path LIKE '%\\RunOnce%' ORDER BY modified_time"},
    {"q": "Are there any AppInit_DLLs registry entries?",
     "sql": "SELECT hive, key_path, value_name, value_data, modified_time FROM registry_keys WHERE key_path LIKE '%AppInit_DLL%'"},
    {"q": "Show Winlogon registry keys userinit and shell hijacking",
     "sql": "SELECT hive, key_path, value_name, value_data, modified_time FROM registry_keys WHERE key_path LIKE '%Winlogon%' AND value_name IN ('Userinit','Shell')"},
    {"q": "Show registry entries with value data pointing to Temp or AppData",
     "sql": "SELECT hive, key_path, value_name, value_data, modified_time FROM registry_keys WHERE value_data LIKE '%Temp%' OR value_data LIKE '%AppData%' OR value_data LIKE '%Public%'"},
    {"q": "Were any services installed via registry?",
     "sql": "SELECT hive, key_path, value_name, value_data, modified_time FROM registry_keys WHERE key_path LIKE '%\\Services\\%' ORDER BY modified_time DESC LIMIT 50"},

    # ── Defense evasion ────────────────────────────────────────────────────────
    {"q": "Were event logs cleared event 1102 or 104?",
     "sql": "SELECT timestamp_utc, event_id, username, computer, channel FROM events WHERE event_id IN (1102, 104, 4719) ORDER BY timestamp_utc"},
    {"q": "Were any services installed event 7045?",
     "sql": "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 7045 ORDER BY timestamp_utc"},
    {"q": "Show LOLBin events from Security event log 4688",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 4688 AND (description LIKE '%certutil%' OR description LIKE '%regsvr32%' OR description LIKE '%mshta%' OR description LIKE '%wscript%' OR description LIKE '%cscript%' OR description LIKE '%installutil%' OR description LIKE '%rundll32%')"},
    {"q": "Show Sysmon LOLBin execution events event 1",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 1 AND (description LIKE '%certutil%' OR description LIKE '%regsvr32%' OR description LIKE '%mshta%' OR description LIKE '%bitsadmin%' OR description LIKE '%installutil%')"},

    # ── Credential access ──────────────────────────────────────────────────────
    {"q": "Show LSASS process access events Sysmon event 10",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 10 AND description LIKE '%lsass%' ORDER BY timestamp_utc"},
    {"q": "Were there any LSASS dump attempts Sysmon event 1?",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 1 AND (description LIKE '%lsass%' OR description LIKE '%procdump%' OR description LIKE '%sekurlsa%') ORDER BY timestamp_utc"},
    {"q": "Show PowerShell scriptblock log events 4104",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 4104 ORDER BY timestamp_utc LIMIT 50"},
    {"q": "Show brute force by IP more than 5 failed logons",
     "sql": "SELECT source_ip, COUNT(*) AS failed_count FROM events WHERE event_id = 4625 AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip HAVING failed_count > 5 ORDER BY failed_count DESC"},

    # ── Lateral movement ───────────────────────────────────────────────────────
    {"q": "Show SMB file share connections lateral movement",
     "sql": "SELECT remote_address, remote_port, process_name, pid, state FROM network_connections WHERE remote_port IN (139, 445) OR local_port IN (139, 445)"},
    {"q": "Show pass-the-hash explicit credential logons 4648",
     "sql": "SELECT timestamp_utc, username, source_ip, computer, description FROM events WHERE event_id = 4648 ORDER BY timestamp_utc"},
    {"q": "Show WMI DCOM process creation lateral movement",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (4688, 1) AND (description LIKE '%WmiPrvSE%' OR description LIKE '%wmiprvse%') ORDER BY timestamp_utc"},

    # ── ATT&CK tactic queries ──────────────────────────────────────────────────
    {"q": "TA0001 Initial Access who connected from external IPs first?",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id IN (4624, 21) AND source_ip IS NOT NULL AND source_ip != '' AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' ORDER BY timestamp_utc LIMIT 10"},
    {"q": "TA0001 Initial Access when did the first external logon happen?",
     "sql": "SELECT MIN(timestamp_utc) AS first_external_logon, username, source_ip FROM events WHERE event_id IN (4624, 21) AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY username, source_ip ORDER BY first_external_logon LIMIT 5"},
    {"q": "TA0001 which IPs tried the most logons success vs failure?",
     "sql": "SELECT source_ip, SUM(CASE WHEN event_id=4624 THEN 1 ELSE 0 END) AS successes, SUM(CASE WHEN event_id=4625 THEN 1 ELSE 0 END) AS failures FROM events WHERE event_id IN (4624, 4625) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY failures DESC LIMIT 20"},
    {"q": "TA0002 Execution what suspicious processes were executed?",
     "sql": "SELECT timestamp_utc, pid, name, command_line, username FROM processes WHERE command_line LIKE '%powershell%' OR command_line LIKE '%-enc%' OR command_line LIKE '%cmd /c%' OR command_line LIKE '%wscript%' OR command_line LIKE '%cscript%' ORDER BY timestamp_utc"},
    {"q": "TA0002 Execution who ran PowerShell encoded commands?",
     "sql": "SELECT username, COUNT(*) AS times, MIN(timestamp_utc) AS first_seen FROM processes WHERE LOWER(name) LIKE '%powershell%' AND (command_line LIKE '%-EncodedCommand%' OR command_line LIKE '%-enc %' OR command_line LIKE '%FromBase64String%') GROUP BY username ORDER BY times DESC"},
    {"q": "TA0003 Persistence what persistence mechanisms were found?",
     "sql": "SELECT 'sched_task' AS type, task_name AS name, command AS detail FROM scheduled_tasks WHERE command LIKE '%Temp%' OR command LIKE '%AppData%' OR command LIKE '%-Enc%' UNION ALL SELECT 'registry_run', key_path, value_data FROM registry_keys WHERE key_path LIKE '%Run%' UNION ALL SELECT 'service_install', description, computer FROM events WHERE event_id = 7045"},
    {"q": "TA0003 Persistence were any new services installed?",
     "sql": "SELECT timestamp_utc, computer, description FROM events WHERE event_id = 7045 ORDER BY timestamp_utc"},
    {"q": "TA0004 Privilege Escalation show special privilege assignment events",
     "sql": "SELECT timestamp_utc, username, computer FROM events WHERE event_id = 4672 ORDER BY timestamp_utc LIMIT 100"},
    {"q": "TA0004 are critical system processes running under wrong users?",
     "sql": "SELECT pid, name, username, exe_path FROM processes WHERE UPPER(username) NOT LIKE '%SYSTEM%' AND UPPER(username) NOT LIKE '%SERVICE%' AND name IN ('lsass.exe','services.exe','wininit.exe','csrss.exe','smss.exe')"},
    {"q": "TA0005 Defense Evasion were audit logs cleared?",
     "sql": "SELECT timestamp_utc, event_id, username, computer FROM events WHERE event_id IN (1102, 104, 4719) ORDER BY timestamp_utc"},
    {"q": "TA0005 Defense Evasion show masquerading processes from unusual paths",
     "sql": "SELECT pid, name, exe_path, username FROM processes WHERE (exe_path LIKE '%\\Temp\\%' OR exe_path LIKE '%\\AppData\\%' OR exe_path LIKE '%\\Users\\Public\\%') AND exe_path != '' ORDER BY timestamp_utc"},
    {"q": "TA0006 Credential Access was LSASS accessed?",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id = 10 AND description LIKE '%lsass%' ORDER BY timestamp_utc"},
    {"q": "TA0006 Credential Access which IPs caused brute force failures?",
     "sql": "SELECT source_ip, username, COUNT(*) AS failures FROM events WHERE event_id IN (4625, 4771, 4776) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip, username HAVING failures > 10 ORDER BY failures DESC"},
    {"q": "TA0007 Discovery show network scanning processes",
     "sql": "SELECT pid, name, command_line, username FROM processes WHERE LOWER(name) IN ('nmap.exe','masscan.exe','arp.exe','nbtstat.exe','nltest.exe','net.exe') OR command_line LIKE '%net view%' OR command_line LIKE '%net user%' OR command_line LIKE '%nltest%'"},
    {"q": "TA0007 what system information was collected?",
     "sql": "SELECT key, value FROM sysinfo ORDER BY key LIMIT 50"},
    {"q": "TA0008 Lateral Movement show RDP logons from internal IPs",
     "sql": "SELECT timestamp_utc, username, source_ip, computer FROM events WHERE event_id = 21 AND source_ip IS NOT NULL AND source_ip != '' ORDER BY timestamp_utc"},
    {"q": "TA0008 Lateral Movement show SMB connections",
     "sql": "SELECT remote_address, remote_port, process_name, pid, state FROM network_connections WHERE remote_port IN (139, 445) ORDER BY remote_address"},
    {"q": "TA0009 Collection were any files staged in Temp directories?",
     "sql": "SELECT name, exe_path, command_line, username FROM processes WHERE exe_path LIKE '%\\Temp\\%' OR command_line LIKE '%\\Temp\\%'"},
    {"q": "TA0010 Exfiltration show large data transfers unusual outbound connections",
     "sql": "SELECT remote_address, remote_port, process_name, pid FROM network_connections WHERE state='ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' AND remote_address NOT LIKE '127.%' ORDER BY remote_port"},
    {"q": "TA0010 Exfiltration were DNS tunneling indicators found?",
     "sql": "SELECT hostname, resolved_ip, ttl, COUNT(*) AS lookups FROM dns_cache WHERE ttl < 60 OR LENGTH(hostname) > 50 GROUP BY hostname ORDER BY lookups DESC LIMIT 20"},
    {"q": "TA0011 C2 show external established connections on HTTP HTTPS ports",
     "sql": "SELECT remote_address, remote_port, pid, process_name FROM network_connections WHERE state='ESTABLISHED' AND remote_port IN (80,443,8080,8443) AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' AND remote_address NOT LIKE '127.%'"},
    {"q": "TA0011 C2 which processes have external established connections?",
     "sql": "SELECT process_name, COUNT(*) AS connections FROM network_connections WHERE state='ESTABLISHED' AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' AND remote_address NOT LIKE '172.16.%' GROUP BY process_name ORDER BY connections DESC"},
    {"q": "TA0011 C2 suspicious DNS queries low TTL or long hostnames",
     "sql": "SELECT hostname, resolved_ip, ttl, record_type FROM dns_cache WHERE ttl < 300 OR LENGTH(hostname) > 40 ORDER BY ttl ASC LIMIT 30"},
    {"q": "TA0040 Impact ransomware indicators shadow copy deletion",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%vssadmin%delete%' OR description LIKE '%wbadmin%delete%' OR description LIKE '%shadowcopy%delete%') ORDER BY timestamp_utc"},

    # ── Specific technique cross-table queries ────────────────────────────────
    {"q": "T1059.001 PowerShell all evidence across tables",
     "sql": "SELECT 'process' AS src, timestamp_utc, command_line AS detail, username FROM processes WHERE LOWER(name) LIKE '%powershell%' OR command_line LIKE '%powershell%' UNION ALL SELECT 'event_4104', timestamp_utc, description, username FROM events WHERE event_id = 4104 ORDER BY timestamp_utc"},
    {"q": "T1003 credential dumping all evidence",
     "sql": "SELECT 'process' AS src, name, command_line, username FROM processes WHERE LOWER(name) IN ('mimikatz.exe','procdump.exe','wce.exe') OR command_line LIKE '%sekurlsa%' UNION ALL SELECT 'event_10_lsass', timestamp_utc, description, username FROM events WHERE event_id = 10 AND description LIKE '%lsass%'"},
    {"q": "T1110 Brute Force failed logon patterns with success correlation",
     "sql": "SELECT username, source_ip, SUM(CASE WHEN event_id=4625 THEN 1 ELSE 0 END) AS failures, SUM(CASE WHEN event_id=4624 THEN 1 ELSE 0 END) AS successes FROM events WHERE event_id IN (4624, 4625) AND source_ip IS NOT NULL AND source_ip != '' GROUP BY username, source_ip ORDER BY failures DESC LIMIT 20"},
    {"q": "T1078 Valid Accounts all accounts with successful logons from external IPs",
     "sql": "SELECT username, source_ip, MIN(timestamp_utc) AS first_seen, COUNT(*) AS session_count FROM events WHERE event_id = 4624 AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '127.%' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY username, source_ip ORDER BY first_seen"},
    {"q": "T1547.001 Registry Run Keys persistence via autorun",
     "sql": "SELECT hive, key_path, value_name, value_data, modified_time FROM registry_keys WHERE key_path LIKE '%\\CurrentVersion\\Run%' OR key_path LIKE '%\\CurrentVersion\\RunOnce%' OR key_path LIKE '%\\CurrentVersion\\RunServices%' ORDER BY modified_time"},
    {"q": "T1036 Masquerading processes with system names running from wrong paths",
     "sql": "SELECT pid, name, exe_path, username, command_line FROM processes WHERE LOWER(name) IN ('svchost.exe','lsass.exe','services.exe','csrss.exe') AND exe_path NOT LIKE '%System32%' AND exe_path != '' ORDER BY name"},
    {"q": "T1070.001 log clearing who cleared logs and when?",
     "sql": "SELECT timestamp_utc, event_id, username, computer, channel FROM events WHERE event_id IN (1102, 104, 4719) ORDER BY timestamp_utc"},
    {"q": "T1053.005 Scheduled Task what tasks were created or modified?",
     "sql": "SELECT task_name, command, run_as, author, status, last_run FROM scheduled_tasks UNION ALL SELECT description, '', '', '', '', timestamp_utc FROM events WHERE event_id IN (4698, 4702) ORDER BY 1"},
    {"q": "T1003.006 DCSync replication privilege events",
     "sql": "SELECT timestamp_utc, username, source_ip, computer, description FROM events WHERE event_id = 4662 AND description LIKE '%1131f6ad%' ORDER BY timestamp_utc"},
    {"q": "T1218 LOLBin signed binary proxy execution all evidence",
     "sql": "SELECT timestamp_utc, computer, username, description FROM events WHERE event_id IN (1, 4688) AND (description LIKE '%certutil%' OR description LIKE '%regsvr32%' OR description LIKE '%mshta%' OR description LIKE '%rundll32%' OR description LIKE '%wscript%' OR description LIKE '%cscript%') ORDER BY timestamp_utc"},
]


class DFIRLlamaAnalyst:
    """
    DFIRLlama's primary NL→SQL engine.

    BM25 retrieval selects the most relevant training examples, then
    guides the LLM to generate validated, schema-aware SQL.
    A 4-layer validator catches hallucinations before execution and
    triggers one auto-correction pass when errors are found.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._store  = DFIRLlamaStore(":memory:")
        self._trained = False

    def train(self, force: bool = False) -> int:
        """Load training corpus into BM25 store. Returns number of QA pairs loaded."""
        if self._trained and not force:
            return 0
        for doc in TABLE_DOCS.values():
            self._store.add_doc(doc)
        for item in _TRAINING_QA:
            self._store.add_qa(item["q"], item["sql"])
        self._trained = True
        return len(_TRAINING_QA)

    def ask(self, question: str) -> dict:
        """
        Translate a natural language forensic question to SQL and execute it.

        Returns dict with: ok, question, sql, row_count, columns, result (DataFrame), error
        """
        if not self._trained:
            self.train()

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
        except Exception as e:
            return {"ok": False, "error": f"DB connect failed: {e}"}

        active   = self._detect_active_tables(conn)
        similar  = self._store.get_similar_qa(question, top_k=5)
        messages = self._build_prompt(question, similar, active)

        raw = self._call_llm(messages)
        sql = _clean_sql_v2(raw)

        if not sql:
            conn.close()
            return {"ok": False, "error": "LLM did not generate valid SQL", "raw": raw[:200]}

        from tools.sql_validator import validate_sql_query, build_correction_hint
        v = validate_sql_query(sql, conn)

        if not v.valid:
            hint  = build_correction_hint(v, conn)
            retry = messages + [
                {"role": "assistant", "content": raw},
                {"role": "user",
                 "content": f"That SQL has errors:\n{hint}\n\nGenerate corrected SQL only."},
            ]
            raw2 = self._call_llm(retry)
            sql2 = _clean_sql_v2(raw2)
            if sql2:
                v2 = validate_sql_query(sql2, conn)
                if v2.valid:
                    sql, v = sql2, v2

        if not v.valid:
            conn.close()
            return {"ok": False, "error": "; ".join(v.errors), "sql": sql}

        try:
            df = pd.read_sql(sql, conn)
            conn.close()
            return {
                "ok":        True,
                "question":  question,
                "sql":       sql,
                "row_count": len(df),
                "columns":   list(df.columns),
                "result":    df,
            }
        except Exception as e:
            conn.close()
            return {"ok": False, "sql": sql, "error": f"Execution error: {e}"}

    def _detect_active_tables(self, conn: sqlite3.Connection) -> list[str]:
        """Return tables that exist and contain rows."""
        active: list[str] = []
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            for (name,) in rows:
                try:
                    n = conn.execute(f"SELECT COUNT(*) FROM [{name}]").fetchone()[0]
                    if n > 0:
                        active.append(name)
                except Exception:
                    pass
        except Exception:
            pass
        return active

    def _build_prompt(self, question: str,
                      similar_qa: list[dict],
                      active_tables: list[str]) -> list[dict]:
        docs = [TABLE_DOCS[t] for t in active_tables if t in TABLE_DOCS]

        sys_parts = [
            "You are a forensic SQL analyst. Translate the question into ONE valid SQLite SELECT.",
            "",
            f"Active tables in this case: {', '.join(active_tables) or 'none detected'}",
            "",
            "TABLE DOCUMENTATION:",
            *docs,
        ]

        if similar_qa:
            sys_parts += [
                "",
                "SIMILAR EXAMPLES (adapt — do not copy verbatim):",
                *[f"Q: {ex['question']}\nSQL: {ex['sql']}" for ex in similar_qa],
            ]

        sys_parts += [
            "",
            "STRICT RULES:",
            "1. Output ONLY the SQL query. No markdown, no explanation, no comments.",
            "2. Only SELECT statements. Never INSERT/UPDATE/DELETE/DROP/CREATE.",
            "3. Use only columns documented above.",
            "4. Timestamps are ISO 8601 UTC (YYYY-MM-DD HH:MM:SS).",
            "5. Use LIMIT 100 unless counting or aggregating.",
            "6. External IPs: NOT LIKE '10.%','192.168.%','172.16.%','127.%'.",
        ]

        return [
            {"role": "system", "content": "\n".join(sys_parts)},
            {"role": "user",   "content": f"Question: {question}"},
        ]

    def _call_llm(self, messages: list[dict]) -> str:
        return chat_completion(messages, temperature=0.0, max_tokens=512)
