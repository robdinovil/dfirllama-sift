"""
EIL — Evidence Interrogation Loop

ReAct agent that autonomously investigates a forensic case.
Cycle: THINK → ACT (tool) → OBSERVE → repeat → done()

Available tools (the agent decides which to call):
  threat_hunt()              MITRE ATT&CK detection — always the first step
  pivot_user("username")     All events + processes for a specific user
  pivot_ip("ip")             All events + network connections for a specific IP
  pivot_process("name")      All processes + connections for a process name
  sql_query("question")      Natural language query via the NL→SQL engine
  done("narrative")          Finalize with 4-5 sentence incident summary

No human input is required. The agent runs start to finish.
Uses the same LLM backend configured for DFIRLlama (claude-cli / claude-api / ollama).
"""

import re
import sqlite3
import time

from llm.client import chat_completion
from tools.hunt import threat_hunt as _run_threat_hunt

MAX_STEPS    = 8
MAX_ROWS_OBS = 10
CTX_WINDOW   = 6   # how many assistant+user turns to keep in context

_SYSTEM_PROMPT = """\
You are a DFIR analyst. Investigate a Windows forensic case using these tools:

  threat_hunt()              — MITRE ATT&CK detection (always start here)
  pivot_user("username")     — All events for a user (use real usernames from CASE DATA)
  pivot_ip("ip")             — All events for an IP (use real IPs from CASE DATA)
  pivot_process("name")      — All events for a process
  sql_query("NL question")   — Query the forensic database in natural language
  done("narrative")          — Finish: 4-5 sentence incident summary in Spanish

Rules:
- ONLY use usernames and IPs listed in CASE DATA. Never invent values.
- One THOUGHT + one ACTION per turn. No explanations outside this format.
- Call done() as soon as you can describe: initial access + what attacker did.
- If a sql_query returns ERROR, do NOT repeat it — try a different tool.
- If you called the same tool twice with no new findings, call done().

Output format (strict):
THOUGHT: <one sentence reasoning>
ACTION: tool_name("argument")
"""


def investigate(case_name: str, db_path: str,
                goal: str = "Determine what happened in this incident.",
                max_steps: int = MAX_STEPS) -> dict:
    """
    Run an autonomous EIL investigation on a forensic case database.

    Args:
        case_name:  Case identifier (e.g. "IR-2024-0622")
        db_path:    Path to normalized SQLite from ingest_evidence_dir
        goal:       Investigation objective (default: "Determine what happened")
        max_steps:  Maximum ReAct iterations before forcing done()

    Returns dict with:
        conclusion    Final incident narrative (4-5 sentences)
        steps_taken   Number of ReAct iterations
        tools_called  List of (tool, arg) pairs in execution order
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # NL→SQL engine for sql_query tool
    from tools.nlsql import DFIRLlamaAnalyst
    analyst = DFIRLlamaAnalyst(db_path)
    analyst.train()

    case_ctx = _get_case_context(conn)
    system   = _SYSTEM_PROMPT + f"\n{case_ctx}"

    messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user",   "content": f"Case: {case_name}\nGoal: {goal}\n\nBegin."},
    ]

    conclusion:  str | None = None
    tools_called: list[tuple] = []
    loop_guard:   list[str]  = []

    for step in range(1, max_steps + 1):
        if step == max_steps:
            messages.append({
                "role": "user",
                "content": (
                    "This is your LAST step. You MUST call done() now with a complete "
                    "summary of everything you found. Do not call any other tool."
                )
            })

        # Sliding context window
        ctx = [messages[0], messages[1]] + messages[2:][-CTX_WINDOW * 2:]

        try:
            raw = _llm(ctx)
        except Exception:
            try:
                raw = _llm([messages[0], messages[-1]])
            except Exception:
                break

        messages.append({"role": "assistant", "content": raw})

        parsed = _parse_action(raw)
        if not parsed:
            messages.append({"role": "user", "content": "Please respond with THOUGHT and ACTION."})
            continue

        tool, arg = parsed
        tools_called.append((tool, arg))

        # Loop detection: same tool+arg twice in a row → redirect
        sig = f"{tool}:{arg}"
        if loop_guard[-2:].count(sig) >= 2:
            tool, arg = "sql_query", "What are the most important findings in this case?"
        loop_guard.append(sig)

        observation = _dispatch(tool, arg, analyst, conn)

        if tool == "done":
            conclusion = observation
            break

        messages.append({
            "role": "user",
            "content": f"OBSERVATION:\n{observation}\n\nContinue."
        })

    conn.close()

    if not conclusion:
        conclusion = "Investigation incomplete — maximum steps reached without a definitive conclusion."

    return {
        "conclusion":   conclusion,
        "steps_taken":  len(tools_called),
        "tools_called": tools_called,
    }


# ── Tool implementations ──────────────────────────────────────────────────────

def _dispatch(tool: str, arg: str, analyst, conn: sqlite3.Connection) -> str:
    if tool == "sql_query":
        return _tool_sql_query(analyst, arg)
    elif tool == "pivot_user":
        return _tool_pivot_user(conn, arg)
    elif tool == "pivot_ip":
        return _tool_pivot_ip(conn, arg)
    elif tool == "pivot_process":
        return _tool_pivot_process(conn, arg)
    elif tool == "threat_hunt":
        return _tool_threat_hunt(conn)
    elif tool == "done":
        return arg
    else:
        return f"Unknown tool: {tool}"


def _tool_threat_hunt(conn: sqlite3.Connection) -> str:
    hits = _run_threat_hunt(conn)
    if not hits:
        return "No MITRE ATT&CK rules triggered."
    return "\n".join(
        f"[{h['severity']}] {h['rule_id']} — {h['name']}: {h['count']} hits"
        for h in hits
    )


def _tool_sql_query(analyst, question: str) -> str:
    result = analyst.ask(question)
    if result.get("error"):
        return f"ERROR: {result['error']}"
    df = result.get("result")
    if df is None or len(df) == 0:
        return "No rows returned."
    rows = min(len(df), MAX_ROWS_OBS)
    return f"{len(df)} rows (showing {rows}):\n" + df.head(rows).to_string(index=False)


def _tool_pivot_user(conn: sqlite3.Connection, username: str) -> str:
    parts = []
    for sql, label in [
        (f"SELECT event_id, timestamp_utc, username, source_ip, computer, channel "
         f"FROM events WHERE LOWER(username) = LOWER(?) LIMIT {MAX_ROWS_OBS}", "events"),
        (f"SELECT pid, name, exe_path, username, command_line "
         f"FROM processes WHERE LOWER(username) = LOWER(?) LIMIT {MAX_ROWS_OBS}", "processes"),
    ]:
        try:
            cur  = conn.execute(sql, (username,))
            rows = cur.fetchall()
            if rows:
                cols = [d[0] for d in cur.description]
                parts.append(f"[{label}] {len(rows)} rows:\n" + _fmt(rows, cols))
        except Exception:
            pass
    return "\n\n".join(parts) if parts else f"No activity for user '{username}'."


def _tool_pivot_ip(conn: sqlite3.Connection, ip: str) -> str:
    parts = []
    for sql, label in [
        (f"SELECT event_id, timestamp_utc, username, source_ip, computer "
         f"FROM events WHERE source_ip = ? LIMIT {MAX_ROWS_OBS}", "events"),
        (f"SELECT protocol, remote_address, remote_port, state, process_name "
         f"FROM network_connections WHERE remote_address = ? LIMIT {MAX_ROWS_OBS}", "network_connections"),
    ]:
        try:
            cur  = conn.execute(sql, (ip,))
            rows = cur.fetchall()
            if rows:
                cols = [d[0] for d in cur.description]
                parts.append(f"[{label}] {len(rows)} rows:\n" + _fmt(rows, cols))
        except Exception:
            pass
    return "\n\n".join(parts) if parts else f"No activity for IP '{ip}'."


def _tool_pivot_process(conn: sqlite3.Connection, name: str) -> str:
    parts = []
    for sql, label in [
        (f"SELECT pid, name, exe_path, username, command_line "
         f"FROM processes WHERE LOWER(name) LIKE LOWER(?) LIMIT {MAX_ROWS_OBS}", "processes"),
        (f"SELECT protocol, remote_address, remote_port, state, process_name "
         f"FROM network_connections WHERE LOWER(process_name) LIKE LOWER(?) LIMIT {MAX_ROWS_OBS}",
         "network_connections"),
    ]:
        try:
            cur  = conn.execute(sql, (f"%{name}%",))
            rows = cur.fetchall()
            if rows:
                cols = [d[0] for d in cur.description]
                parts.append(f"[{label}] {len(rows)} rows:\n" + _fmt(rows, cols))
        except Exception:
            pass
    return "\n\n".join(parts) if parts else f"No activity for process '{name}'."


# ── Case context ──────────────────────────────────────────────────────────────

def _get_case_context(conn: sqlite3.Connection) -> str:
    lines = ["CASE DATA (use ONLY these real values in pivot tools):"]
    try:
        rows = conn.execute(
            "SELECT username, COUNT(*) n FROM events "
            "WHERE username IS NOT NULL AND username != '' "
            "GROUP BY username ORDER BY n DESC LIMIT 8"
        ).fetchall()
        if rows:
            lines.append("Users: " + ", ".join(r[0] for r in rows))
    except Exception:
        pass
    try:
        rows = conn.execute(
            "SELECT source_ip, COUNT(*) n FROM events "
            "WHERE source_ip IS NOT NULL AND source_ip != '' "
            "GROUP BY source_ip ORDER BY n DESC LIMIT 6"
        ).fetchall()
        if rows:
            lines.append("Source IPs: " + ", ".join(r[0] for r in rows))
    except Exception:
        pass
    try:
        rows = conn.execute(
            "SELECT event_id, COUNT(*) n FROM events "
            "GROUP BY event_id ORDER BY n DESC LIMIT 10"
        ).fetchall()
        if rows:
            lines.append("Event IDs: " + ", ".join(str(r[0]) for r in rows))
    except Exception:
        pass
    return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _llm(messages: list[dict]) -> str:
    return chat_completion(messages, temperature=0.0, max_tokens=256)


def _parse_action(text: str) -> tuple[str, str] | None:
    m = re.search(r'ACTION:\s*(\w+)\((["\']?)(.*?)\2\s*\)', text, re.DOTALL)
    if not m:
        m2 = re.search(r'ACTION:\s*(\w+)\(\)', text)
        if m2:
            return m2.group(1), ""
        return None
    return m.group(1), m.group(3).strip()


def _fmt(rows: list, cols: list[str], limit: int = MAX_ROWS_OBS) -> str:
    header = " | ".join(cols)
    sep    = "-" * min(len(header), 72)
    lines  = [header, sep]
    for row in rows[:limit]:
        lines.append(" | ".join(str(row[c] if isinstance(row, dict) else row[i] or "")[:35]
                                for i, c in enumerate(cols)))
    if len(rows) > limit:
        lines.append(f"... ({len(rows) - limit} more rows)")
    return "\n".join(lines)
