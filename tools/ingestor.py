"""
ForensicIngestor — normalize Windows IR artifacts into a unified SQLite database.

Supported input formats (auto-detected by content, not file extension):
  .evtx          Windows Event Log (EVTX binary, magic: ElfFile)
  .csv           tasklist/WMIC process snapshots, EvtxECmd CSV exports, schtasks /fo CSV
  netstat*.txt   netstat -ano output (TCP/UDP connection state)
  *.reg          Windows Registry export (REGEDIT4 / Windows Registry Editor)
  systeminfo.txt systeminfo command output (en/es)

All artifacts are written to a normalized schema (tools/schema.py) and tracked
in the evidence_files table for chain-of-custody reporting.
"""

import re
import sqlite3
import time
from pathlib import Path

import pandas as pd

from tools.schema import SCHEMA_SQL


# ── Evidence type detection ───────────────────────────────────────────────────

_MAGIC_EVTX    = b"\x45\x6c\x66\x46\x69\x6c\x65\x00"  # ElfFile\x00
_BOM_UTF16_LE  = b"\xff\xfe"
_BOM_UTF16_BE  = b"\xfe\xff"
_BOM_UTF8      = b"\xef\xbb\xbf"


def _detect_type(path: Path) -> str:
    """Identify evidence type from file content (not extension)."""
    try:
        header = path.read_bytes()[:512]
    except Exception:
        return "unknown"

    if header.startswith(_MAGIC_EVTX):
        return "evtx"

    # Try text sample
    for enc in ("utf-8", "utf-16", "utf-16-le", "utf-8-sig", "latin-1"):
        try:
            sample = path.read_text(encoding=enc, errors="replace")[:2000].lower()
            break
        except Exception:
            sample = ""

    if "windows registry editor" in sample or "regedit4" in sample:
        return "reg_export"
    if "host name" in sample or "nombre de host" in sample:
        return "systeminfo"
    if sample.strip().startswith("proto") or "established" in sample or "listening" in sample:
        if re.search(r"(tcp|udp)\s+[\d\.\[\]:]+:\d+", sample, re.IGNORECASE):
            return "netstat"

    # CSV detection
    if path.suffix.lower() == ".csv":
        return "csv"
    if "," in sample and "\n" in sample:
        return "csv"

    return "unknown"


# ── ForensicIngestor ──────────────────────────────────────────────────────────

class ForensicIngestor:
    """
    Ingests a file or directory of forensic evidence into a normalized SQLite DB.
    Idempotent — re-ingesting the same filepath is a no-op.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def ingest_file(self, filepath: str | Path) -> dict:
        """Detect and ingest a single evidence file. Returns a result summary."""
        path = Path(filepath)
        t0   = time.time()
        result = {
            "file":      path.name,
            "type":      "unknown",
            "records":   0,
            "elapsed_s": 0.0,
            "error":     None,
        }

        # Skip if already ingested
        already = self.conn.execute(
            "SELECT id FROM evidence_files WHERE filepath = ?", (str(path),)
        ).fetchone()
        if already:
            result["error"] = "already ingested"
            return result

        evidence_type = _detect_type(path)
        result["type"] = evidence_type

        try:
            if evidence_type == "evtx":
                count = _parse_evtx(path, self.conn)
            elif evidence_type == "csv":
                count = _parse_csv(path, self.conn)
            elif evidence_type == "netstat":
                count = _parse_netstat(path, self.conn)
            elif evidence_type == "reg_export":
                count = _parse_registry(path, self.conn)
            elif evidence_type == "systeminfo":
                count = _parse_systeminfo(path, self.conn)
            else:
                result["error"] = f"unsupported evidence type: {evidence_type}"
                return result

            result["records"]   = count
            result["elapsed_s"] = round(time.time() - t0, 2)
            _register_file(self.conn, path, evidence_type, count)

        except Exception as exc:
            result["error"] = str(exc)[:200]

        return result

    def ingest_directory(self, dirpath: str | Path) -> list[dict]:
        """Ingest all recognized evidence files in a directory."""
        path    = Path(dirpath)
        results = []
        for f in sorted(path.rglob("*")):
            if f.is_file() and f.suffix.lower() not in (".db", ".sqlite", ".json", ".py"):
                r = self.ingest_file(f)
                if r["type"] != "unknown":
                    results.append(r)
        return results

    def summary(self) -> dict:
        """Return record counts per table."""
        tables = [
            "events", "processes", "network_connections",
            "scheduled_tasks", "registry_keys", "sysinfo", "evidence_files",
        ]
        counts = {}
        for t in tables:
            try:
                counts[t] = self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except Exception:
                counts[t] = 0
        return counts

    def close(self):
        self.conn.close()


# ── EVTX parser ───────────────────────────────────────────────────────────────

def _parse_evtx(path: Path, conn: sqlite3.Connection) -> int:
    """Parse an EVTX binary using the evtx (Rust) or python-evtx library."""
    try:
        from evtx import PyEvtxParser as _RustParser
        return _parse_evtx_rust(path, conn, _RustParser)
    except ImportError:
        pass
    try:
        import Evtx.Evtx as _PythonLib
        return _parse_evtx_python(path, conn, _PythonLib)
    except ImportError:
        pass
    raise RuntimeError(
        "No EVTX library found. Install one: pip install evtx  (recommended, Rust-based)"
    )


def _parse_evtx_rust(path: Path, conn: sqlite3.Connection, parser_cls) -> int:
    import json
    records = []
    parser  = parser_cls(str(path))
    for rec in parser.records_json():
        try:
            data = json.loads(rec["data"])
            sys  = data.get("Event", {}).get("System", {})
            ed   = data.get("Event", {}).get("EventData", {}) or {}

            records.append((
                sys.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime", ""),
                _safe_int(sys.get("EventID")),
                sys.get("Channel", ""),
                sys.get("Provider", {}).get("#attributes", {}).get("Name", ""),
                sys.get("Level", ""),
                sys.get("Computer", ""),
                _extract_username(ed, sys),
                _extract_source_ip(ed),
                _build_description(ed),
                path.name,
            ))
        except Exception:
            continue

    conn.executemany(
        "INSERT INTO events "
        "(timestamp_utc,event_id,channel,provider,level,computer,username,source_ip,description,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


def _parse_evtx_python(path: Path, conn: sqlite3.Connection, evtx_lib) -> int:
    from lxml import etree as ET
    NS  = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    records = []
    with evtx_lib.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                root   = ET.fromstring(rec.xml().encode())
                sys_el = root.find("e:System", NS)
                ed_el  = root.find("e:EventData", NS)
                ed     = {}
                if ed_el is not None:
                    for d in ed_el.findall("e:Data", NS):
                        name = d.get("Name", "")
                        if name:
                            ed[name] = d.text or ""
                ts       = _xpath(sys_el, ".//e:TimeCreated/@SystemTime", NS)
                event_id = _safe_int(_xpath(sys_el, "e:EventID", NS))
                records.append((
                    ts, event_id,
                    _xpath(sys_el, "e:Channel", NS),
                    (sys_el.find("e:Provider", NS).get("Name", "") if sys_el is not None else ""),
                    _xpath(sys_el, "e:Level", NS),
                    _xpath(sys_el, "e:Computer", NS),
                    _extract_username(ed, {}),
                    _extract_source_ip(ed),
                    _build_description(ed),
                    path.name,
                ))
            except Exception:
                continue
    conn.executemany(
        "INSERT INTO events "
        "(timestamp_utc,event_id,channel,provider,level,computer,username,source_ip,description,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


# ── CSV parser ────────────────────────────────────────────────────────────────

_COL_PROCESS = {
    "nombre de imagen": "name", "image name": "name",
    "pid": "pid",
    "nombre de sesión": "session", "session name": "session",
    "uso de memoria": "memory_raw", "mem usage": "memory_raw",
    "estado": "status", "status": "status",
    "nombre de usuario": "username", "user name": "username",
    "tiempo de cpu": "cpu_time", "cpu time": "cpu_time",
}

_COL_WMIC = {
    "commandline": "command_line", "command line": "command_line",
    "executablepath": "exe_path",  "executable path": "exe_path",
    "caption": "name", "name": "name",
    "parentprocessid": "ppid",  "processid": "pid",
}

_COL_EVTX = {
    "eventid": "event_id", "event_id": "event_id",
    "timecreated": "timestamp_utc", "time_created": "timestamp_utc",
    "mapdescription": "description",
    "username": "username", "remotehost": "source_ip",
    "computer": "computer", "channel": "channel", "level": "level",
}

_COL_TASKS = {
    "taskname": "task_name", "task name": "task_name",
    "nombre de tarea": "task_name",
    "status": "status", "estado": "status",
    "lastruntime": "last_run", "last run time": "last_run",
    "nextruntime": "next_run", "next run time": "next_run",
    "author": "author", "autor": "author",
    "run as user": "run_as", "ejecutar como usuario": "run_as",
    "task to run": "command", "tarea para ejecutar": "command",
}


def _parse_csv(path: Path, conn: sqlite3.Connection) -> int:
    df = None
    for enc in ("utf-8", "utf-16", "utf-8-sig", "latin-1", "cp1252"):
        try:
            df = pd.read_csv(path, encoding=enc, encoding_errors="replace",
                             low_memory=False, on_bad_lines="skip")
            break
        except Exception:
            continue
    if df is None:
        raise RuntimeError(f"Cannot read CSV: {path.name}")

    df.columns = [str(c).strip().strip('"').lower() for c in df.columns]
    cols       = set(df.columns)

    # Detect subtype
    has_event_signal = any(c in cols for c in ("mapdescription", "channel", "eventrecordid"))
    has_eventid      = any(c in cols for c in ("eventid", "event_id", "timecreated"))
    if has_event_signal or (has_eventid and "commandline" not in cols):
        return _csv_to_events(df, path, conn)

    if any(c in cols for c in ("pid", "processid", "commandline", "nombre de imagen", "image name")):
        return _csv_to_processes(df, path, conn)

    if any(c in cols for c in ("taskname", "task name", "lastruntime", "nombre de tarea")):
        return _csv_to_tasks(df, path, conn)

    return 0  # unrecognized CSV — skip silently


def _csv_to_events(df: pd.DataFrame, path: Path, conn: sqlite3.Connection) -> int:
    df = _rename(df, _COL_EVTX)
    records = []
    for _, row in df.iterrows():
        records.append((
            str(row.get("timestamp_utc", ""))[:30],
            _safe_int(row.get("event_id")),
            str(row.get("channel", ""))[:100],
            "",
            str(row.get("level", ""))[:20],
            str(row.get("computer", ""))[:100],
            str(row.get("username", ""))[:100],
            str(row.get("source_ip", ""))[:50],
            str(row.get("description", ""))[:500],
            path.name,
        ))
    conn.executemany(
        "INSERT INTO events "
        "(timestamp_utc,event_id,channel,provider,level,computer,username,source_ip,description,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


def _csv_to_processes(df: pd.DataFrame, path: Path, conn: sqlite3.Connection) -> int:
    df = _rename(df, {**_COL_PROCESS, **_COL_WMIC})
    records = []
    for _, row in df.iterrows():
        mem = _parse_memory(str(row.get("memory_raw", "")))
        records.append((
            None,
            _safe_int(row.get("pid")),
            _safe_int(row.get("ppid")),
            str(row.get("name", ""))[:200],
            str(row.get("command_line", ""))[:500],
            str(row.get("exe_path", ""))[:500],
            str(row.get("username", ""))[:100],
            str(row.get("session", ""))[:50],
            mem,
            str(row.get("cpu_time", ""))[:20],
            str(row.get("status", ""))[:50],
            path.name,
        ))
    conn.executemany(
        "INSERT INTO processes "
        "(timestamp_utc,pid,ppid,name,command_line,exe_path,username,session,memory_kb,cpu_time,status,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


def _csv_to_tasks(df: pd.DataFrame, path: Path, conn: sqlite3.Connection) -> int:
    df = _rename(df, _COL_TASKS)
    records = []
    for _, row in df.iterrows():
        enabled = 1 if str(row.get("status", "")).lower() in ("ready", "running", "listo") else 0
        records.append((
            str(row.get("task_name", ""))[:300],
            str(row.get("task_name", ""))[:300],
            str(row.get("status", ""))[:50],
            str(row.get("last_run", ""))[:30],
            str(row.get("next_run", ""))[:30],
            str(row.get("author", ""))[:100],
            str(row.get("run_as", ""))[:100],
            str(row.get("command", ""))[:500],
            "",
            enabled,
            path.name,
        ))
    conn.executemany(
        "INSERT INTO scheduled_tasks "
        "(task_name,task_path,status,last_run,next_run,author,run_as,command,arguments,enabled,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


# ── Netstat parser ────────────────────────────────────────────────────────────

_NETSTAT_RE = re.compile(
    r"(TCP|UDP)\s+([\d\.\[\]:]+):(\d+)\s+([\d\.\[\]:*]+):(\d+|\*)\s+(\w+)?\s*(\d+)?",
    re.IGNORECASE,
)


def _parse_netstat(path: Path, conn: sqlite3.Connection) -> int:
    text = _read_text(path)
    records = []
    for line in text.splitlines():
        m = _NETSTAT_RE.search(line)
        if not m:
            continue
        proto, local_a, local_p, remote_a, remote_p, state, pid = m.groups()
        records.append((
            None,
            proto.upper(),
            local_a,
            _safe_int(local_p),
            remote_a if remote_a != "*" else None,
            _safe_int(remote_p) if remote_p != "*" else None,
            (state or "").upper(),
            _safe_int(pid),
            None,
            path.name,
        ))
    conn.executemany(
        "INSERT INTO network_connections "
        "(timestamp_utc,protocol,local_address,local_port,remote_address,remote_port,state,pid,process_name,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


# ── Registry export parser ────────────────────────────────────────────────────

_RE_KEY     = re.compile(r"^\[(.+)\]$")
_RE_VALUE   = re.compile(r'^"(.+)"\s*=\s*(.+)$')
_RE_DEFAULT = re.compile(r'^@\s*=\s*(.+)$')


def _parse_registry(path: Path, conn: sqlite3.Connection) -> int:
    text    = _read_text(path)
    records = []
    current_key = ""
    hive        = ""

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        m = _RE_KEY.match(line)
        if m:
            current_key = m.group(1)
            hive        = current_key.split("\\")[0]
            continue

        m = _RE_VALUE.match(line)
        if m and current_key:
            vtype, vdata = _parse_reg_value(m.group(2).strip())
            records.append((hive, current_key, m.group(1), vtype, vdata[:500], None, path.name))
            continue

        m = _RE_DEFAULT.match(line)
        if m and current_key:
            vtype, vdata = _parse_reg_value(m.group(1).strip())
            records.append((hive, current_key, "(Default)", vtype, vdata[:500], None, path.name))

    conn.executemany(
        "INSERT INTO registry_keys "
        "(hive,key_path,value_name,value_type,value_data,modified_time,source_file) "
        "VALUES (?,?,?,?,?,?,?)",
        records,
    )
    conn.commit()
    return len(records)


# ── Systeminfo parser ─────────────────────────────────────────────────────────

_SYSINFO_FIELDS = {
    "host name": "hostname",            "nombre de host": "hostname",
    "os name": "os_name",               "nombre del sistema operativo": "os_name",
    "os version": "os_version",         "versión del sistema operativo": "os_version",
    "system type": "architecture",      "tipo del sistema": "architecture",
    "original install date": "install_date", "fecha de instalación original": "install_date",
    "system boot time": "last_boot",    "hora de inicio del sistema": "last_boot",
    "domain": "domain",                 "dominio": "domain",
    "hotfix(s)": "hotfixes",            "revisión(es)": "hotfixes",
    "ip address(es)": "ip_addresses",   "dirección(es) ip": "ip_addresses",
}


def _parse_systeminfo(path: Path, conn: sqlite3.Connection) -> int:
    text    = _read_text(path)
    fields: dict[str, str] = {}
    current = None
    vals:   list[str] = []

    for line in text.splitlines():
        m = re.match(r"^([^:]{3,45}):\s*(.*)", line)
        if m:
            if current:
                fields[current] = " ".join(vals).strip()
            current = m.group(1).strip().lower()
            vals    = [m.group(2).strip()]
        elif current and line.startswith(" " * 4):
            vals.append(line.strip())

    if current:
        fields[current] = " ".join(vals).strip()

    row = {v: "" for v in _SYSINFO_FIELDS.values()}
    for raw, norm in _SYSINFO_FIELDS.items():
        if raw in fields:
            row[norm] = fields[raw][:500]

    conn.execute(
        "INSERT INTO sysinfo "
        "(hostname,os_name,os_version,architecture,install_date,last_boot,domain,ip_addresses,hotfixes,source_file) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (row["hostname"], row["os_name"], row["os_version"], row["architecture"],
         row["install_date"], row["last_boot"], row["domain"], row["ip_addresses"],
         row["hotfixes"], path.name),
    )
    conn.commit()
    return 1


# ── Evidence file tracking ────────────────────────────────────────────────────

def _register_file(conn: sqlite3.Connection, path: Path,
                   evidence_type: str, count: int) -> None:
    try:
        size_kb = path.stat().st_size / 1024
    except Exception:
        size_kb = 0.0
    conn.execute(
        "INSERT OR IGNORE INTO evidence_files "
        "(filename, filepath, evidence_type, file_size_kb, record_count) "
        "VALUES (?, ?, ?, ?, ?)",
        (path.name, str(path), evidence_type, round(size_kb, 1), count),
    )
    conn.commit()


# ── Shared helpers ────────────────────────────────────────────────────────────

def _safe_int(val) -> int | None:
    try:
        return int(str(val).strip().replace(",", ""))
    except (TypeError, ValueError):
        return None


def _extract_username(ed: dict, sys: dict) -> str:
    for key in ("SubjectUserName", "TargetUserName", "UserName", "User"):
        v = ed.get(key, "")
        if v and v not in ("-", ""):
            return str(v)
    return ""


def _extract_source_ip(ed: dict) -> str:
    for key in ("IpAddress", "SourceAddress", "CallerIpAddress", "RemoteAddress", "WorkstationName"):
        v = ed.get(key, "")
        if v and v not in ("-", "::1", "127.0.0.1", ""):
            return str(v)
    return ""


def _build_description(ed: dict) -> str:
    parts = [f"{k}={v}" for k, v in ed.items() if v and str(v).strip() not in ("-", "")]
    return "; ".join(parts[:10])


def _read_text(path: Path) -> str:
    for enc in ("utf-8", "utf-16", "utf-16-le", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=enc, errors="replace")
        except Exception:
            continue
    return ""


def _xpath(el, path: str, ns: dict) -> str:
    if el is None:
        return ""
    try:
        tag = path.lstrip(".//").split("/")[0].split("@")[0].strip()
        r   = el.find(tag, ns)
        return r.text or "" if r is not None else ""
    except Exception:
        return ""


def _rename(df: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    rename = {}
    for col in df.columns:
        c = col.strip().strip('"').lower()
        if c in mapping:
            rename[col] = mapping[c]
    return df.rename(columns=rename)


def _parse_memory(raw: str) -> float | None:
    raw = raw.replace(",", "").replace(".", "").replace("\xa0", "").strip()
    m   = re.search(r"(\d+)", raw)
    if m:
        val = int(m.group(1))
        return val * 1024.0 if "mb" in raw.lower() else float(val)
    return None


def _parse_reg_value(raw: str) -> tuple[str, str]:
    if raw.startswith('"') and raw.endswith('"'):
        return "REG_SZ", raw.strip('"')
    if raw.startswith("dword:"):
        return "REG_DWORD", raw[6:]
    if raw.startswith("hex(2):"):
        return "REG_EXPAND_SZ", raw[7:]
    if raw.startswith("hex:"):
        return "REG_BINARY", raw[4:]
    if raw.startswith("hex(7):"):
        return "REG_MULTI_SZ", raw[7:]
    return "REG_UNKNOWN", raw[:200]
