"""
IRReportGenerator — automated DOCX Incident Response report.

Pipeline:
  1. SQL data collection (deterministic, zero LLM)
  2. Executive summary via LLM (~1 LLM call)
  3. Recommendations via LLM (~1 LLM call)
  4. DOCX assembly with python-docx

Output follows NIST SP 800-61 Rev. 3 structure (8 sections).
Requires: pip install python-docx
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from llm.client import chat_completion

try:
    from docx import Document
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    _DOCX_AVAILABLE = True
except ImportError:
    _DOCX_AVAILABLE = False

# Windows Event ID → description for the timeline section
_EID_NAMES = {
    4624: "Successful Logon",      4625: "Failed Logon",
    4634: "Logoff",                4648: "Logon with Explicit Credentials",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",      4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",4702: "Scheduled Task Updated",
    4720: "User Account Created",  4726: "User Account Deleted",
    4728: "Member Added to Group", 4732: "Member Added to Local Group",
    4742: "Computer Account Changed",
    4776: "NTLM Authentication",   4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket", 4771: "Kerberos Pre-auth Failed",
    4798: "User Local Group Enumerated", 4799: "Group Membership Enumerated",
    5140: "Network Share Accessed", 5145: "Network Share Object Checked",
    5136: "Directory Service Object Modified",
    7045: "New Service Installed",
    1102: "Security Log Cleared",  4719: "Audit Policy Changed",
    1116: "Malware Detected",      1117: "Malware Action Taken",
    21: "RDP Session Logon",       22: "RDP Shell Start",
    23: "RDP Session Logoff",      24: "RDP Session Disconnect",
    1: "Sysmon: Process Create",   3: "Sysmon: Network Connection",
    10: "Sysmon: Process Access",  11: "Sysmon: File Created",
    4104: "PowerShell Script Block",
}


def generate_report(case_name: str, db_path: str,
                    eil_conclusion: str = "",
                    triage_json_path: str = "",
                    output_dir: str = "/tmp") -> dict:
    """
    Generate an IR report (DOCX) from a normalized forensic database.

    Args:
        case_name:        Case identifier (e.g. "IR-2024-0622")
        db_path:          SQLite from ingest_evidence_dir
        eil_conclusion:   Output from investigate_case (optional, enriches Section 6)
        triage_json_path: Path to triage JSON from triage_case (optional)
        output_dir:       Where to write the .docx file

    Returns dict with report_path and section summaries.
    """
    if not _DOCX_AVAILABLE:
        return {
            "ok": False,
            "error": "python-docx not installed. Run: pip install python-docx",
        }

    conn = sqlite3.connect(db_path, check_same_thread=False)
    data = _collect_data(conn, case_name)
    conn.close()

    # Load triage JSON if provided
    triage = {}
    if triage_json_path:
        try:
            triage = json.loads(Path(triage_json_path).read_text())
        except Exception:
            pass

    # LLM calls (2 total)
    exec_summary    = _llm_exec_summary(data, triage, eil_conclusion)
    recommendations = _llm_recommendations(data, triage)

    # DOCX assembly
    ts_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out    = Path(output_dir) / f"IR_{case_name}_{ts_str}.docx"
    _build_docx(out, case_name, data, exec_summary, recommendations,
                eil_conclusion, triage)

    return {
        "ok":             True,
        "report_path":    str(out),
        "case_name":      case_name,
        "sections":       8,
        "total_events":   data["scope"].get("total_events", 0),
        "mitre_hits":     len(data.get("mitre_hits", [])),
        "exec_summary":   exec_summary[:400],
    }


# ── Section 1: data collection ────────────────────────────────────────────────

def _collect_data(conn: sqlite3.Connection, case_name: str) -> dict:
    data: dict = {"case_name": case_name}

    def q(sql, params=()):
        try:
            return conn.execute(sql, params).fetchall()
        except Exception:
            return []

    def q1(sql, params=()):
        rows = q(sql, params)
        return rows[0][0] if rows else 0

    # Scope
    data["scope"] = {
        "total_events":   q1("SELECT COUNT(*) FROM events"),
        "unique_computers": q1("SELECT COUNT(DISTINCT computer) FROM events WHERE computer IS NOT NULL AND computer != ''"),
        "unique_users":   q1("SELECT COUNT(DISTINCT username) FROM events WHERE username IS NOT NULL AND username != ''"),
        "unique_ips":     q1("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''"),
        "first_event":    q1("SELECT MIN(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''") or "",
        "last_event":     q1("SELECT MAX(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''") or "",
    }

    # Timeline (first 20 events)
    timeline = q(
        "SELECT timestamp_utc, event_id, username, source_ip, computer "
        "FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != '' "
        "ORDER BY timestamp_utc ASC LIMIT 20"
    )
    data["timeline"] = [
        {
            "timestamp": r[0], "event_id": r[1],
            "event_name": _EID_NAMES.get(r[1], f"Event {r[1]}"),
            "username": r[2], "source_ip": r[3], "computer": r[4],
        }
        for r in timeline
    ]

    # External logons
    ext_logons = q(
        "SELECT timestamp_utc, username, source_ip, computer FROM events "
        "WHERE event_id IN (4624, 21) "
        "AND source_ip IS NOT NULL AND source_ip != '' "
        "AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' "
        "AND source_ip NOT LIKE '127.%' "
        "ORDER BY timestamp_utc LIMIT 20"
    )
    data["external_logons"] = [
        {"timestamp": r[0], "username": r[1], "source_ip": r[2], "computer": r[3]}
        for r in ext_logons
    ]

    # IOCs: external IPs
    ext_ips = q(
        "SELECT source_ip, COUNT(*) as count FROM events "
        "WHERE source_ip IS NOT NULL AND source_ip != '' "
        "AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' "
        "AND source_ip NOT LIKE '127.%' "
        "GROUP BY source_ip ORDER BY count DESC LIMIT 15"
    )
    data["ioc_ips"] = [{"ip": r[0], "count": r[1]} for r in ext_ips]

    # IOCs: suspicious processes
    susp_procs = q(
        "SELECT pid, name, exe_path, username FROM processes "
        "WHERE exe_path LIKE '%Temp%' OR exe_path LIKE '%AppData%' "
        "OR name IN ('mimikatz.exe','procdump.exe','wce.exe','fgdump.exe') "
        "LIMIT 10"
    )
    data["ioc_processes"] = [{"pid": r[0], "name": r[1], "path": r[2], "user": r[3]} for r in susp_procs]

    # External network connections
    ext_net = q(
        "SELECT remote_address, remote_port, protocol, process_name FROM network_connections "
        "WHERE state='ESTABLISHED' "
        "AND remote_address IS NOT NULL AND remote_address != '' "
        "AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' "
        "AND remote_address NOT LIKE '127.%' LIMIT 10"
    )
    data["ioc_network"] = [{"ip": r[0], "port": r[1], "proto": r[2], "process": r[3]} for r in ext_net]

    # MITRE ATT&CK hits (reuse threat_hunt)
    try:
        from tools.hunt import threat_hunt, ATTACK_RULES
        import pandas as pd
        hits_raw = threat_hunt(conn)
        data["mitre_hits"] = [
            {"rule_id": h["rule_id"], "severity": h["severity"],
             "name": h["name"], "count": h["count"]}
            for h in hits_raw
        ]
    except Exception:
        data["mitre_hits"] = []

    # Run keys (persistence)
    run_keys = q(
        "SELECT key_path, value_name, value_data FROM registry_keys "
        "WHERE key_path LIKE '%\\Run%' OR key_path LIKE '%\\RunOnce%' LIMIT 10"
    )
    data["run_keys"] = [{"key": r[0], "name": r[1], "data": r[2]} for r in run_keys]

    # Forensic gaps
    data["gaps"] = _detect_gaps(conn)

    # Evidence manifest
    manifest = q("SELECT filename, evidence_type, record_count FROM evidence_files ORDER BY evidence_type")
    data["evidence_files"] = [{"file": r[0], "type": r[1], "records": r[2]} for r in manifest]

    return data


def _detect_gaps(conn: sqlite3.Connection) -> list[str]:
    gaps = []
    checks = [
        ("SELECT COUNT(*) FROM processes",          "No process snapshots (tasklist/WMIC) available"),
        ("SELECT COUNT(*) FROM network_connections","No network connection data (netstat) available"),
        ("SELECT COUNT(*) FROM scheduled_tasks",    "No scheduled tasks data available"),
        ("SELECT COUNT(*) FROM registry_keys",      "No registry export available"),
        ("SELECT COUNT(*) FROM sysinfo",            "No system information (systeminfo) available"),
        ("SELECT COUNT(*) FROM events WHERE event_id = 4104", "No PowerShell script block logging (EID 4104) found"),
    ]
    for sql, msg in checks:
        try:
            n = conn.execute(sql).fetchone()[0]
            if n == 0:
                gaps.append(msg)
        except Exception:
            gaps.append(msg)
    return gaps


# ── LLM calls ─────────────────────────────────────────────────────────────────

def _llm_exec_summary(data: dict, triage: dict, eil_conclusion: str) -> str:
    scope    = data["scope"]
    mitre    = data.get("mitre_hits", [])
    critical = [h for h in mitre if h["severity"] in ("CRITICAL", "HIGH")]
    sev      = triage.get("severity", "UNKNOWN")
    phase    = triage.get("attack_phase", "unknown")

    context = (
        f"Case: {data['case_name']}\n"
        f"Severity: {sev} | Attack phase: {phase}\n"
        f"Scope: {scope['total_events']:,} events, "
        f"{scope['unique_computers']} systems, "
        f"{scope['unique_users']} accounts\n"
        f"Time range: {scope['first_event'][:19]} → {scope['last_event'][:19]}\n"
        f"MITRE rules triggered: {len(mitre)} ({len(critical)} CRITICAL/HIGH)\n"
        f"External IPs: {len(data.get('ioc_ips', []))}\n"
    )
    if eil_conclusion:
        context += f"\nInvestigation conclusion:\n{eil_conclusion}\n"

    prompt = (
        "You are a DFIR analyst writing a formal IR report.\n"
        "Write an executive summary in Spanish (3-4 paragraphs) describing:\n"
        "1. What happened (nature of the incident)\n"
        "2. Scope of impact (systems, accounts, timeframe)\n"
        "3. Key attacker actions detected\n"
        "4. Immediate risk level\n\n"
        "Be factual and reference specific numbers from the data.\n"
        "Do not use markdown. Write continuous prose.\n\n"
        f"{context}"
    )
    return chat_completion(
        [{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=600,
    )


def _llm_recommendations(data: dict, triage: dict) -> list[str]:
    mitre = data.get("mitre_hits", [])
    gaps  = data.get("gaps", [])
    sev   = triage.get("severity", "UNKNOWN")

    context = (
        f"Severity: {sev}\n"
        f"MITRE techniques: {', '.join(h['rule_id'] for h in mitre[:8])}\n"
        f"Forensic gaps: {'; '.join(gaps[:4]) if gaps else 'none'}\n"
        f"Suspicious processes: {len(data.get('ioc_processes', []))}\n"
        f"External connections: {len(data.get('ioc_network', []))}\n"
    )

    prompt = (
        "You are a DFIR analyst. Based on the incident data below, "
        "provide 6 specific recommendations in Spanish:\n"
        "- 2 immediate containment actions (within hours)\n"
        "- 2 short-term remediation steps (within days)\n"
        "- 2 strategic improvements (within weeks)\n\n"
        "Return ONLY a JSON array of 6 strings. No explanation.\n\n"
        f"{context}"
    )
    raw = chat_completion(
        [{"role": "user", "content": prompt}],
        temperature=0.1,
        response_json=True,
        max_tokens=400,
    )
    try:
        result = json.loads(raw)
        if isinstance(result, list):
            return result[:6]
    except Exception:
        pass
    return [
        "Aislar los sistemas comprometidos de la red inmediatamente.",
        "Restablecer credenciales de todas las cuentas afectadas.",
        "Implementar autenticación multi-factor en todos los accesos remotos.",
        "Revisar y auditar todas las tareas programadas y claves Run del registro.",
        "Implementar SIEM con detección de anomalías de comportamiento (UEBA).",
        "Realizar ejercicio de threat hunting post-incidente en todos los sistemas.",
    ]


# ── DOCX builder ─────────────────────────────────────────────────────────────

def _build_docx(out: Path, case_name: str, data: dict,
                exec_summary: str, recommendations: list[str],
                eil_conclusion: str, triage: dict) -> None:
    doc = Document()

    # Title
    title = doc.add_heading(f"Incident Response Report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph(
        f"Case: {case_name}  |  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    ).alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph("")

    scope = data["scope"]

    # Section 1: Executive Summary
    doc.add_heading("1. Executive Summary", 1)
    doc.add_paragraph(exec_summary or "Not available.")

    # Section 2: Incident Scope
    doc.add_heading("2. Incident Scope", 1)
    t = doc.add_table(rows=1, cols=2)
    t.style = "Table Grid"
    for label, val in [
        ("Total Events", f"{scope['total_events']:,}"),
        ("Systems Involved", scope['unique_computers']),
        ("Accounts Involved", scope['unique_users']),
        ("Unique Source IPs", scope['unique_ips']),
        ("First Event (UTC)", scope['first_event'][:19] if scope['first_event'] else "N/A"),
        ("Last Event (UTC)", scope['last_event'][:19] if scope['last_event'] else "N/A"),
    ]:
        row = t.add_row().cells
        row[0].text = label
        row[1].text = str(val)

    # Section 3: Incident Timeline
    doc.add_heading("3. Incident Timeline", 1)
    if data.get("timeline"):
        t = doc.add_table(rows=1, cols=5)
        t.style = "Table Grid"
        hdr = t.rows[0].cells
        for i, h in enumerate(["Timestamp (UTC)", "Event ID", "Event", "User", "Source IP"]):
            hdr[i].text = h
        for ev in data["timeline"][:20]:
            row = t.add_row().cells
            row[0].text = str(ev["timestamp"])[:19]
            row[1].text = str(ev["event_id"])
            row[2].text = ev["event_name"]
            row[3].text = str(ev["username"] or "")
            row[4].text = str(ev["source_ip"] or "")
    else:
        doc.add_paragraph("No timestamped events found.")

    # Section 4: MITRE ATT&CK Analysis
    doc.add_heading("4. MITRE ATT&CK Analysis", 1)
    if data.get("mitre_hits"):
        t = doc.add_table(rows=1, cols=4)
        t.style = "Table Grid"
        hdr = t.rows[0].cells
        for i, h in enumerate(["Technique", "Severity", "Rule Name", "Hits"]):
            hdr[i].text = h
        for hit in data["mitre_hits"]:
            row = t.add_row().cells
            row[0].text = hit["rule_id"]
            row[1].text = hit["severity"]
            row[2].text = hit["name"]
            row[3].text = str(hit["count"])
    else:
        doc.add_paragraph("No MITRE ATT&CK rules triggered.")

    # Section 5: Indicators of Compromise
    doc.add_heading("5. Indicators of Compromise", 1)
    if data.get("ioc_ips"):
        doc.add_paragraph("External IP Addresses:", style="Heading 3" if False else "Normal").bold = True
        for ioc in data["ioc_ips"][:10]:
            doc.add_paragraph(f"  {ioc['ip']} ({ioc['count']} events)", style="List Bullet")
    if data.get("ioc_processes"):
        doc.add_paragraph("Suspicious Processes:").runs[0].bold = True
        for p in data["ioc_processes"]:
            doc.add_paragraph(f"  {p['name']} (PID {p['pid']}) — {p['path']}", style="List Bullet")
    if data.get("ioc_network"):
        doc.add_paragraph("External Network Connections:").runs[0].bold = True
        for n in data["ioc_network"]:
            doc.add_paragraph(f"  {n['ip']}:{n['port']} ({n['proto']}) via {n['process'] or 'unknown'}", style="List Bullet")

    # Section 6: Key Findings (EIL conclusion)
    doc.add_heading("6. Key Findings", 1)
    if eil_conclusion:
        doc.add_paragraph(eil_conclusion)
    elif triage.get("top_indicators"):
        for ind in triage["top_indicators"]:
            doc.add_paragraph(f"• {ind}", style="List Bullet")
    else:
        doc.add_paragraph("No deep investigation was performed. Run investigate_case_tool for detailed findings.")

    # Section 7: Recommendations
    doc.add_heading("7. Recommendations", 1)
    for rec in recommendations:
        doc.add_paragraph(rec, style="List Bullet")

    # Section 8: Forensic Gaps and Evidence Analyzed
    doc.add_heading("8. Forensic Gaps & Evidence", 1)
    if data.get("gaps"):
        doc.add_paragraph("Forensic Gaps Detected:").runs[0].bold = True
        for gap in data["gaps"]:
            doc.add_paragraph(f"  {gap}", style="List Bullet")
    if data.get("evidence_files"):
        doc.add_paragraph("Evidence Files Analyzed:").runs[0].bold = True
        t = doc.add_table(rows=1, cols=3)
        t.style = "Table Grid"
        hdr = t.rows[0].cells
        hdr[0].text = "File"
        hdr[1].text = "Type"
        hdr[2].text = "Records"
        for ef in data["evidence_files"]:
            row = t.add_row().cells
            row[0].text = ef["file"]
            row[1].text = ef["type"]
            row[2].text = str(ef["records"])

    doc.save(str(out))
