"""
TriageAgent — rapid first-look classification of a forensic case.

Three-phase pipeline (matches the DFIRLlama DFIR-Chain pattern):
  Phase 1: SQL statistics    — zero LLM, deterministic truth
  Phase 2: ATT&CK rules      — zero LLM, 19 MITRE rules (~0s)
  Phase 3: LLM classification — severity / attack_phase / top_indicators

The LLM only classifies. All factual inputs come from SQL.
Total time: ~90s on CPU-only hardware with a 3B parameter model.
"""

import json
import re
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from llm.client import chat_completion
from tools.hunt import threat_hunt


# ── Phase 1: deterministic statistics ────────────────────────────────────────

def _collect_stats(conn: sqlite3.Connection) -> dict:
    """Pure SQL — zero LLM. Everything the classifier sees as facts."""
    s = {}

    def q(sql, params=()):
        try:
            return conn.execute(sql, params).fetchall()
        except Exception:
            return []

    def q1(sql, params=()):
        rows = q(sql, params)
        return rows[0][0] if rows else 0

    s["total_events"]    = q1("SELECT COUNT(*) FROM events")
    s["unique_event_ids"]= q1("SELECT COUNT(DISTINCT event_id) FROM events")
    s["unique_users"]    = q1("SELECT COUNT(DISTINCT username) FROM events WHERE username IS NOT NULL AND username != ''")
    s["unique_ips"]      = q1("SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL AND source_ip != ''")
    s["unique_machines"] = q1("SELECT COUNT(DISTINCT computer) FROM events WHERE computer IS NOT NULL AND computer != ''")
    s["processes"]       = q1("SELECT COUNT(*) FROM processes")
    s["net_connections"] = q1("SELECT COUNT(*) FROM network_connections")
    s["sched_tasks"]     = q1("SELECT COUNT(*) FROM scheduled_tasks")
    s["registry_keys"]   = q1("SELECT COUNT(*) FROM registry_keys")

    s["first_event"] = q1("SELECT MIN(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''") or ""
    s["last_event"]  = q1("SELECT MAX(timestamp_utc) FROM events WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''") or ""
    dwell = 0
    if s["first_event"] and s["last_event"]:
        try:
            fmt = "%Y-%m-%d %H:%M:%S"
            t0  = datetime.strptime(s["first_event"][:19], fmt)
            t1  = datetime.strptime(s["last_event"][:19], fmt)
            dwell = (t1 - t0).days
        except Exception:
            pass
    s["dwell_days"] = dwell

    rows = q("SELECT event_id, COUNT(*) n FROM events GROUP BY event_id ORDER BY n DESC LIMIT 8")
    s["top_event_ids"] = [{"event_id": r[0], "count": r[1]} for r in rows]

    bf = q(
        "SELECT source_ip, COUNT(*) n FROM events "
        "WHERE event_id IN (4625,4771,4776,18456) AND source_ip IS NOT NULL AND source_ip != '' "
        "GROUP BY source_ip ORDER BY n DESC LIMIT 5"
    )
    s["brute_force_ips"]   = [{"ip": r[0], "count": r[1]} for r in bf]
    s["brute_force_total"] = q1("SELECT COUNT(*) FROM events WHERE event_id IN (4625,4771,4776,18456)")

    ext = q(
        "SELECT username, source_ip, COUNT(*) n FROM events "
        "WHERE event_id IN (4624, 21) "
        "AND source_ip IS NOT NULL AND source_ip != '' "
        "AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' "
        "AND source_ip NOT LIKE '127.%' "
        "GROUP BY username, source_ip ORDER BY n DESC LIMIT 5"
    )
    s["external_logons"]    = [{"user": r[0], "ip": r[1], "count": r[2]} for r in ext]
    s["log_clearing"]       = q1("SELECT COUNT(*) FROM events WHERE event_id IN (1102, 104)")
    s["priv_assigned"]      = q1("SELECT COUNT(*) FROM events WHERE event_id = 4672")
    s["suspicious_procs"]   = q1(
        "SELECT COUNT(*) FROM processes "
        "WHERE exe_path LIKE '%\\Temp\\%' OR exe_path LIKE '%\\AppData\\%' OR exe_path LIKE '%\\Users\\Public\\%'"
    )
    ext_conn = q(
        "SELECT remote_address, remote_port, process_name FROM network_connections "
        "WHERE state='ESTABLISHED' "
        "AND remote_address IS NOT NULL AND remote_address != '' "
        "AND remote_address NOT LIKE '10.%' AND remote_address NOT LIKE '192.168.%' "
        "AND remote_address NOT LIKE '127.%' LIMIT 5"
    )
    s["external_connections"] = [{"ip": r[0], "port": r[1], "process": r[2]} for r in ext_conn]
    s["credential_signals"]   = q1(
        "SELECT COUNT(*) FROM processes "
        "WHERE LOWER(name) IN ('mimikatz.exe','procdump.exe','wce.exe') "
        "OR command_line LIKE '%sekurlsa%' OR command_line LIKE '%lsadump%'"
    )
    s["lsass_access"]       = q1("SELECT COUNT(*) FROM events WHERE event_id = 10 AND description LIKE '%lsass%'")
    s["suspicious_tasks"]   = q1(
        "SELECT COUNT(*) FROM scheduled_tasks "
        "WHERE command LIKE '%Temp%' OR command LIKE '%AppData%' "
        "OR command LIKE '%-Enc%' OR command LIKE '%DownloadString%'"
    )
    s["run_keys"]           = q1(
        "SELECT COUNT(*) FROM registry_keys "
        "WHERE key_path LIKE '%\\Run%' OR key_path LIKE '%\\RunOnce%'"
    )
    user_rows = q(
        "SELECT DISTINCT username FROM events "
        "WHERE username IS NOT NULL AND username != '' "
        "AND username NOT IN ('SYSTEM','LOCAL SERVICE','NETWORK SERVICE','ANONYMOUS LOGON') "
        "AND username NOT LIKE '%$' AND username NOT LIKE 'NT AUTHORITY%' "
        "LIMIT 10"
    )
    s["human_users"] = [r[0] for r in user_rows]
    return s


# ── Phase 2: build classifier prompt ─────────────────────────────────────────

def _build_prompt(stats: dict, mitre_hits: list[dict]) -> str:
    lines = ["FORENSIC CASE STATISTICS:"]
    lines.append(
        f"  Events: {stats['total_events']:,} | Unique EIDs: {stats['unique_event_ids']} "
        f"| Users: {stats['unique_users']} | IPs: {stats['unique_ips']} "
        f"| Machines: {stats['unique_machines']}"
    )
    lines.append(
        f"  Processes: {stats['processes']} | Net connections: {stats['net_connections']} "
        f"| Sched tasks: {stats['sched_tasks']} | Registry keys: {stats['registry_keys']}"
    )
    if stats["first_event"]:
        lines.append(
            f"  Time range: {stats['first_event'][:19]} → {stats['last_event'][:19]} "
            f"({stats['dwell_days']} days)"
        )
    if stats["brute_force_total"] > 0:
        lines.append(f"  Brute force signals: {stats['brute_force_total']} failed auth events")
        for bf in stats["brute_force_ips"][:3]:
            lines.append(f"    • {bf['ip']}: {bf['count']} attempts")
    if stats["external_logons"]:
        lines.append("  External successful logons:")
        for el in stats["external_logons"][:3]:
            lines.append(f"    • {el['user']} from {el['ip']} ({el['count']}x)")
    if stats["log_clearing"] > 0:
        lines.append(f"  Log clearing events: {stats['log_clearing']} (Defense Evasion)")
    if stats["priv_assigned"] > 0:
        lines.append(f"  Special privileges assigned: {stats['priv_assigned']} events")
    if stats["suspicious_procs"] > 0:
        lines.append(f"  Processes from Temp/AppData: {stats['suspicious_procs']}")
    if stats["credential_signals"] > 0:
        lines.append(f"  Credential dumping tools: {stats['credential_signals']}")
    if stats["lsass_access"] > 0:
        lines.append(f"  LSASS access events: {stats['lsass_access']}")
    if stats["external_connections"]:
        lines.append("  Established external connections:")
        for ec in stats["external_connections"][:3]:
            lines.append(f"    • {ec['ip']}:{ec['port']} ({ec['process'] or 'unknown'})")
    if stats["suspicious_tasks"] > 0:
        lines.append(f"  Suspicious scheduled tasks: {stats['suspicious_tasks']}")
    if stats["run_keys"] > 0:
        lines.append(f"  Registry Run keys: {stats['run_keys']}")

    if mitre_hits:
        lines.append(f"\nMITRE ATT&CK RULES TRIGGERED ({len(mitre_hits)}):")
        for h in mitre_hits:
            sc = h.get("score")
            conf = f" confidence:{sc.confidence:.0%}" if sc else ""
            lines.append(f"  [{h['severity']}] {h['rule_id']} — {h['name']}: {h['count']} hits{conf}")
    else:
        lines.append("\nMITRE ATT&CK: No rules triggered.")

    return "\n".join(lines)


_TRIAGE_SYSTEM = """\
You are a DFIR triage analyst. Given forensic case statistics, output ONLY valid JSON.

Required JSON fields:
{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0.0-1.0,
  "attack_phase": "initial_access" | "execution" | "persistence" | "privilege_escalation" | "defense_evasion" | "credential_access" | "lateral_movement" | "collection" | "exfiltration" | "impact" | "unknown",
  "top_indicators": ["string", "string", "string"],
  "recommendation": "one actionable sentence in Spanish",
  "needs_eil": true | false
}

Rules:
- severity CRITICAL if: ransomware/encryption signals, active C2, credential dumping tools found
- severity HIGH if: external logons successful, log clearing, brute force success, LSASS access
- severity MEDIUM if: brute force attempts only (no success), suspicious processes, run keys
- severity LOW if: only administrative activity, no attack signals
- needs_eil: true if severity is HIGH or CRITICAL
- top_indicators: the 3 most alarming findings (include counts and IPs when available)
- Output ONLY the JSON object, no explanation, no markdown
"""


def _classify(prompt: str) -> dict:
    raw = chat_completion(
        [{"role": "system", "content": _TRIAGE_SYSTEM},
         {"role": "user",   "content": prompt}],
        temperature=0.0,
        response_json=True,
        max_tokens=300,
    )
    raw = re.sub(r"```json\s*|\s*```", "", raw).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        return {
            "severity": "UNKNOWN", "confidence": 0.0, "attack_phase": "unknown",
            "top_indicators": [raw[:200]],
            "recommendation": "Revisar manualmente — clasificación automática falló.",
            "needs_eil": True,
        }


# ── Entry point ───────────────────────────────────────────────────────────────

def run_triage(case_name: str, db_path: str, output_dir: str = "/tmp") -> dict:
    """
    Run full triage pipeline on an evidence database.
    Returns the triage result dict and saves a JSON to output_dir.

    Args:
        case_name:  Case identifier (e.g. "IR-2024-0622")
        db_path:    Path to normalized SQLite from ingest_evidence_dir
        output_dir: Where to save triage_<case>_<ts>.json
    """
    t0   = time.time()
    conn = sqlite3.connect(db_path, check_same_thread=False)

    stats      = _collect_stats(conn)
    mitre_hits = threat_hunt(conn)
    conn.close()

    prompt = _build_prompt(stats, mitre_hits)
    result = _classify(prompt)

    result["case_name"]   = case_name
    result["elapsed_s"]   = round(time.time() - t0, 1)
    result["timestamp"]   = datetime.utcnow().isoformat() + "Z"
    result["stats"]       = stats
    result["mitre_rules"] = [
        {"rule_id": h["rule_id"], "severity": h["severity"],
         "name": h["name"], "count": h["count"]}
        for h in mitre_hits
    ]

    ts_str   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir) / f"triage_{case_name}_{ts_str}.json"
    out_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, default=str)
    )
    result["saved_to"] = str(out_path)
    return result
