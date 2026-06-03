"""
NL→SQL directo — sin depender de Vanna.
Usa nuestro chat_completion (claude-cli, claude-api, o ollama).

Más robusto que Vanna para nuestro caso porque:
- No necesita entrenamiento previo (few-shot en el prompt)
- Funciona con cualquier backend LLM
- Control total sobre el prompt forense
"""

import json
import re
import sqlite3

import pandas as pd

from llm.client import chat_completion

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
