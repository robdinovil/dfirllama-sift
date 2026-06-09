"""
SQL Validator — 4-layer hallucination detection before executing LLM-generated SQL.

Layer 1: Statement type  — must be SELECT or CTE (no INSERT/UPDATE/DROP)
Layer 2: Syntax          — EXPLAIN QUERY PLAN catches malformed SQL
Layer 3: Structural      — tables and columns must exist in the real schema
Layer 4: Referential     — event_id values must exist in the actual database
"""

import re
import sqlite3
from dataclasses import dataclass, field


@dataclass
class SQLValidation:
    valid:            bool
    errors:           list[str] = field(default_factory=list)
    hallucination_type: str | None = None  # structural / referential / syntax / None

    @property
    def error_summary(self) -> str:
        return "; ".join(self.errors)


def validate_sql_query(sql: str, conn: sqlite3.Connection) -> SQLValidation:
    """Validate a SQL string against the real schema and data before executing."""
    errors = []
    htype  = None

    sql_clean = sql.strip().rstrip(";")
    sql_upper = sql_clean.upper().lstrip()
    if not (sql_upper.startswith("SELECT") or sql_upper.startswith("WITH")):
        return SQLValidation(False, ["SQL must be a SELECT statement"], "structural")

    # Layer 2: syntax check
    try:
        conn.execute(f"EXPLAIN QUERY PLAN {sql_clean}")
    except sqlite3.OperationalError as e:
        err_lower = str(e).lower()
        if "no such table" in err_lower or "no such column" in err_lower:
            pass  # handled by structural checks below with better messages
        else:
            return SQLValidation(False, [f"SQL syntax error: {e}"], "syntax")

    # Layer 3a: table existence
    tables_in_sql = _extract_tables(sql_clean)
    real_tables   = _get_real_tables(conn)
    cte_names     = {m.lower() for m in re.findall(
        r"\bWITH\s+(\w+)\s+AS\s*\(", sql_clean, re.IGNORECASE
    )}

    for t in tables_in_sql:
        if t not in real_tables and t not in cte_names:
            errors.append(
                f"Table '{t}' does not exist. Available: {', '.join(sorted(real_tables))}"
            )
            htype = "structural"

    if errors:
        return SQLValidation(False, errors, htype)

    # Layer 3b: column existence
    col_errors = _check_columns(sql_clean, conn, tables_in_sql)
    if col_errors:
        errors.extend(col_errors)
        htype = "structural"

    if errors:
        return SQLValidation(False, errors, htype)

    # Layer 4: referential check for event_id values
    eid_errors = _check_event_ids(sql_clean, conn)
    if eid_errors:
        errors.extend(eid_errors)
        htype = "referential"

    return SQLValidation(len(errors) == 0, errors, htype if errors else None)


def build_correction_hint(result: SQLValidation, conn: sqlite3.Connection) -> str:
    """Build a targeted correction hint for the LLM retry prompt."""
    hints = []
    for err in result.errors:
        if "does not exist" in err and "Column" in err:
            m = re.search(r"Column '(\w+)'", err)
            if m:
                col     = m.group(1)
                similar = _find_similar_columns(col, conn)
                hint    = f"Column '{col}' does not exist."
                if similar:
                    hint += f" Did you mean: {', '.join(similar)}?"
                hints.append(hint)
        else:
            hints.append(err)
    return " | ".join(hints)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_tables(sql: str) -> list[str]:
    return list(set(re.findall(r"(?:FROM|JOIN)\s+(\w+)", sql, re.IGNORECASE)))


def _get_real_tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {r[0].lower() for r in rows}


def _get_table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        cursor = conn.execute(f"SELECT * FROM {table} LIMIT 0")
        return {d[0].lower() for d in cursor.description}
    except Exception:
        return set()


def _check_columns(sql: str, conn: sqlite3.Connection, tables: list[str]) -> list[str]:
    errors: list[str] = []
    all_valid: set[str] = set()
    for t in tables:
        all_valid |= _get_table_columns(conn, t)

    aliases = {m.lower() for m in re.findall(r"\bAS\s+(\w+)", sql, re.IGNORECASE)}
    all_valid |= aliases

    if not all_valid:
        return errors

    SQL_KEYWORDS = {
        "select", "from", "where", "and", "or", "not", "in", "like", "is",
        "null", "having", "group", "by", "order", "limit", "join", "on",
        "count", "sum", "avg", "min", "max", "distinct", "as", "case",
        "when", "then", "else", "end", "date", "strftime", "datetime",
        "upper", "lower", "trim", "length", "substr", "coalesce",
        "inner", "left", "right", "outer", "asc", "desc", "between",
        "exists", "union", "all", "true", "false",
    }

    col_refs = re.findall(
        r"(?:WHERE|AND|OR|ON|,|\()\s+(?:\w+\.)?(\w+)\s*"
        r"(?:=|!=|<|>|\bLIKE\b|\bIS\b|\bNOT\b|\bIN\b)",
        sql, re.IGNORECASE
    )
    for col in col_refs:
        col_lower = col.lower()
        if (col_lower not in SQL_KEYWORDS and col_lower not in all_valid
                and not col_lower.isdigit() and len(col_lower) > 2):
            errors.append(
                f"Column '{col}' does not exist. "
                f"Valid columns: {', '.join(sorted(all_valid)[:15])}"
            )
    return list(set(errors))


def _check_event_ids(sql: str, conn: sqlite3.Connection) -> list[str]:
    errors: list[str] = []
    single = re.findall(r"event_id\s*=\s*(\d+)", sql, re.IGNORECASE)
    multi  = re.findall(r"event_id\s+IN\s*\(([^)]+)\)", sql, re.IGNORECASE)

    referenced: set[int] = {int(x) for x in single}
    for group in multi:
        for x in group.split(","):
            x = x.strip()
            if x.isdigit():
                referenced.add(int(x))

    if not referenced:
        return errors

    try:
        real_ids = {
            r[0] for r in conn.execute(
                "SELECT DISTINCT event_id FROM events WHERE event_id IS NOT NULL"
            ).fetchall()
        }
    except Exception:
        return errors

    if not real_ids:
        return errors

    for eid in referenced:
        if eid not in real_ids:
            errors.append(
                f"event_id={eid} not found in this database. "
                f"Available: {', '.join(str(i) for i in sorted(real_ids))}"
            )
    return errors


def _find_similar_columns(col: str, conn: sqlite3.Connection) -> list[str]:
    all_cols: set[str] = set()
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    for (t,) in tables:
        all_cols |= _get_table_columns(conn, t)
    col_lower = col.lower()
    return [c for c in sorted(all_cols)
            if col_lower[:4] in c or c[:4] in col_lower][:3]
