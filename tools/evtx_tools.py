"""
EVTX tools — el diferenciador de DFIRLlama-SIFT.

evtx_to_sqlite: parsea un .evtx a SQLite usando EvtxECmd (Zimmerman)
query_evtx_nl:  pregunta en lenguaje natural sobre los eventos → Vanna NL-to-SQL
"""
import os
import json
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import pandas as pd
from guardrails import audit, check_path, safe_run

# ── Configuración de Vanna ────────────────────────────────────────────────────

CHROMA_PATH = os.getenv("CHROMA_PATH", "/tmp/dfirllama_chroma")
LLM_BACKEND = os.getenv("LLM_BACKEND", "claude")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_URL    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "mistral:7b")


def _get_vanna(db_path: str):
    """
    Inicializa Vanna con el mejor backend LLM disponible.
    Prioridad: claude-cli → claude-api → ollama
    """
    from vanna.chromadb import ChromaDB_VectorStore
    from vanna.base import VannaBase
    from llm.client import chat_completion, _get_backend

    backend = _get_backend()

    if backend in ("claude-cli", "claude-api"):
        # Backend custom que usa nuestro chat_completion (claude-cli o API)
        class VannaCustom(ChromaDB_VectorStore, VannaBase):
            def __init__(self, config=None):
                ChromaDB_VectorStore.__init__(self, config=config)
                VannaBase.__init__(self, config=config)

            def system_message(self, msg: str) -> dict:
                return {"role": "system", "content": msg}

            def user_message(self, msg: str) -> dict:
                return {"role": "user", "content": msg}

            def assistant_message(self, msg: str) -> dict:
                return {"role": "assistant", "content": msg}

            def submit_prompt(self, prompt, **kwargs) -> str:
                # prompt es una lista de mensajes
                messages = prompt if isinstance(prompt, list) else [
                    {"role": "user", "content": str(prompt)}
                ]
                return chat_completion(messages, temperature=0.1)

        vn = VannaCustom(config={"path": CHROMA_PATH})

    elif backend == "ollama":
        from vanna.ollama import Ollama

        class VannaOllama(ChromaDB_VectorStore, Ollama):
            def __init__(self, config=None):
                ChromaDB_VectorStore.__init__(self, config=config)
                Ollama.__init__(self, config=config)

        vn = VannaOllama(config={"model": OLLAMA_MODEL, "path": CHROMA_PATH})

    else:
        raise RuntimeError("No hay backend LLM disponible (instala Ollama o configura API key)")

    vn.connect_to_sqlite(db_path)
    return vn


def _train_vanna_dfir(vn, conn: sqlite3.Connection):
    """Entrena Vanna con conocimiento forense básico de EVTX/TSLSM."""
    # Schema
    for row in pd.read_sql("SELECT type, sql FROM sqlite_master WHERE sql IS NOT NULL", conn).itertuples():
        if row.sql:
            vn.train(ddl=row.sql)

    # Semántica DFIR
    docs = [
        "EventId 4624 = Windows logon exitoso (Security.evtx).",
        "EventId 4625 = Windows logon fallido (Security.evtx).",
        "EventId 4648 = Logon con credenciales explícitas (pass-the-hash / runas).",
        "EventId 4688 = Proceso creado (Security.evtx). Contiene path del ejecutable y usuario.",
        "EventId 4698 = Scheduled task creada. Persistencia.",
        "EventId 1102 = Audit log cleared. Alta severidad — posible anti-forense.",
        "EventId 7045 = Nuevo servicio instalado. Persistencia / lateral movement.",
        "EventId 21 = RDP logon exitoso (Microsoft-Windows-TerminalServices-LocalSessionManager/Operational).",
        "EventId 22 = RDP shell start — confirma sesión RDP completa.",
        "EventId 23 = RDP logoff.",
        "EventId 24 = RDP session disconnected.",
        "EventId 4104 = PowerShell script block logging. Contiene el código ejecutado.",
        "RemoteHost o IpAddress con valor 10.x.x.x = red interna.",
        "RemoteHost o IpAddress fuera de 10.0.0.0/8 = conexión externa — revisar.",
        "TimeCreated está en formato ISO 8601 UTC.",
        "UserName puede incluir el dominio: DOMINIO\\usuario.",
    ]
    for doc in docs:
        vn.train(documentation=doc)

    # Pares Q-SQL de ejemplo
    pairs = [
        ("¿Cuántos logons exitosos hubo?",
         "SELECT COUNT(*) as total FROM events WHERE EventId = 4624"),
        ("Lista las IPs externas que se conectaron por RDP",
         "SELECT DISTINCT RemoteHost, COUNT(*) as cnt FROM events WHERE EventId=21 AND RemoteHost NOT LIKE '10.%' GROUP BY RemoteHost ORDER BY cnt DESC"),
        ("¿Hubo limpieza de logs?",
         "SELECT TimeCreated, UserName, Computer FROM events WHERE EventId=1102 ORDER BY TimeCreated"),
        ("¿Qué procesos creó el usuario administrator?",
         "SELECT TimeCreated, NewProcessName, CommandLine FROM events WHERE EventId=4688 AND SubjectUserName='administrator' ORDER BY TimeCreated"),
        ("¿Se instalaron servicios nuevos?",
         "SELECT TimeCreated, ServiceName, ImagePath FROM events WHERE EventId=7045 ORDER BY TimeCreated"),
    ]
    for q, sql in pairs:
        vn.train(question=q, sql=sql)


# ── Tool 1: evtx_to_sqlite ────────────────────────────────────────────────────

def evtx_to_sqlite(evtx_path: str, output_db: str | None = None) -> dict:
    """
    Parsea un archivo .evtx y lo carga en una base de datos SQLite.
    Usa EvtxECmd (Zimmerman) si está disponible, con fallback a python-evtx.
    Retorna la ruta del SQLite creado y estadísticas básicas.

    Args:
        evtx_path: Ruta al archivo .evtx a parsear.
        output_db: Ruta de la SQLite de salida. Si None, usa /tmp/<nombre>.db
    """
    evtx_path = str(check_path(evtx_path))
    evtx_name = Path(evtx_path).stem

    if output_db is None:
        output_db = f"/tmp/dfirllama_{evtx_name}.db"

    audit("evtx_to_sqlite", {"evtx_path": evtx_path, "output_db": output_db})

    # Intentar EvtxECmd primero (mejor parser, más columnas)
    evtxecmd = _find_evtxecmd()
    if evtxecmd:
        csv_dir  = tempfile.mkdtemp(prefix="dfirllama_evtx_")
        csv_file = Path(csv_dir) / f"{evtx_name}.csv"
        try:
            result = subprocess.run(
                [evtxecmd, "-f", evtx_path,
                 "--csv", csv_dir, "--csvf", csv_file.name],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and csv_file.exists():
                df = pd.read_csv(csv_file)
                df.to_sql("events", sqlite3.connect(output_db), if_exists="replace", index=False)
                stats = _db_stats(output_db)
                return {"ok": True, "db_path": output_db, "parser": "EvtxECmd", **stats}
        except Exception as e:
            pass  # caer al fallback

    # Fallback: python-evtx
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
        import xml.etree.ElementTree as ET

        rows = []
        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root    = ET.fromstring(xml_str)
                    ns      = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    sys_el  = root.find("e:System", ns)

                    def _txt(tag):
                        el = sys_el.find(f"e:{tag}", ns) if sys_el is not None else None
                        return el.text if el is not None else None

                    row = {
                        "RecordNumber": record.record_num(),
                        "TimeCreated":  sys_el.find("e:TimeCreated", ns).get("SystemTime") if sys_el is not None else None,
                        "EventId":      int(_txt("EventID") or 0),
                        "Channel":      _txt("Channel"),
                        "Computer":     _txt("Computer"),
                        "RawXml":       xml_str[:2000],
                    }
                    rows.append(row)
                except Exception:
                    continue

        if not rows:
            return {"ok": False, "error": "No se pudieron parsear eventos"}

        df = pd.DataFrame(rows)
        df.to_sql("events", sqlite3.connect(output_db), if_exists="replace", index=False)
        stats = _db_stats(output_db)
        return {"ok": True, "db_path": output_db, "parser": "python-evtx", **stats}

    except ImportError:
        return {"ok": False, "error": "Ni EvtxECmd ni python-evtx disponibles"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _find_evtxecmd() -> str | None:
    for name in ["EvtxECmd", "evtxecmd", "EvtxECmd.exe"]:
        path = subprocess.run(["which", name], capture_output=True, text=True).stdout.strip()
        if path:
            return path
    return None


def _db_stats(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    try:
        tables = pd.read_sql(
            "SELECT name FROM sqlite_master WHERE type='table'", conn
        )["name"].tolist()
        if not tables:
            return {"total_events": 0, "tables": [], "error": "No tables found"}

        # Usar la primera tabla disponible para las stats
        tbl = tables[0]
        cols = pd.read_sql(f"PRAGMA table_info({tbl})", conn)["name"].tolist()

        total = pd.read_sql(f"SELECT COUNT(*) as n FROM {tbl}", conn).iloc[0, 0]

        stats: dict = {"total_events": int(total), "tables": tables, "primary_table": tbl}

        # EventId stats si la columna existe
        eid_col = next((c for c in cols if c.lower() in ("eventid", "event_id")), None)
        if eid_col:
            eids = pd.read_sql(
                f"SELECT {eid_col} as EventId, COUNT(*) as cnt FROM {tbl} "
                f"GROUP BY {eid_col} ORDER BY cnt DESC LIMIT 10", conn
            ).to_dict("records")
            stats["top_event_ids"] = eids

        # Rango temporal
        time_col = next((c for c in cols if c.lower() in ("timecreated", "time_created", "timestamp")), None)
        if time_col:
            t_min = pd.read_sql(f"SELECT MIN({time_col}) as t FROM {tbl}", conn).iloc[0, 0]
            t_max = pd.read_sql(f"SELECT MAX({time_col}) as t FROM {tbl}", conn).iloc[0, 0]
            stats["time_range"] = f"{t_min} → {t_max}"

        return stats
    finally:
        conn.close()


# ── Tool 2: query_evtx_nl ─────────────────────────────────────────────────────

_vanna_cache: dict = {}

def query_evtx_nl(db_path: str, question: str, train_first: bool = False) -> dict:
    """
    Hace una pregunta en lenguaje natural sobre una base SQLite de eventos EVTX.
    Usa Vanna.ai (NL→SQL) con el LLM configurado (Claude o Ollama).
    Retorna el SQL generado, los resultados y una interpretación forense.

    Args:
        db_path:     Ruta a la SQLite creada por evtx_to_sqlite.
        question:    Pregunta en español o inglés (ej: "¿Hubo conexiones RDP externas?")
        train_first: Si True, re-entrena Vanna con el schema de esta DB antes de consultar.
    """
    db_path = str(check_path(db_path))
    audit("query_evtx_nl", {"db_path": db_path, "question": question})

    try:
        if db_path not in _vanna_cache or train_first:
            vn   = _get_vanna(db_path)
            conn = sqlite3.connect(db_path)
            _train_vanna_dfir(vn, conn)
            conn.close()
            _vanna_cache[db_path] = vn
        else:
            vn = _vanna_cache[db_path]

        sql = vn.generate_sql(question)
        if not sql:
            return {"ok": False, "error": "Vanna no pudo generar SQL", "question": question}

        conn = sqlite3.connect(db_path)
        df   = pd.read_sql(sql, conn)
        conn.close()

        results = df.to_dict("records")[:50]  # máximo 50 filas al agente

        return {
            "ok":          True,
            "question":    question,
            "sql":         sql,
            "row_count":   len(df),
            "results":     results,
            "columns":     list(df.columns),
        }

    except Exception as e:
        # Fallback: ejecutar SQL directamente si Vanna falla
        return {"ok": False, "error": str(e), "question": question, "sql": None}
