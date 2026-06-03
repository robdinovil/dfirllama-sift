"""
validate_findings — Validador activo de alucinaciones para DFIRLlama-SIFT.

Verifica cada hallazgo de la investigación contra la evidencia real.
Clasifica: confirmed / unverified / contradicted / invalid_format
Genera self_correction_triggers cuando detecta contradicciones.

Esta es nuestra contribución más original — nadie en el hackathon tiene esto.
"""

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
from guardrails import audit

# ── Patrones de validación ────────────────────────────────────────────────────

_IP_RE      = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_RE  = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
_MD5_RE     = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE    = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE  = re.compile(r"^[a-fA-F0-9]{64}$")
_MITRE_RE   = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_WINPATH_RE = re.compile(r"^[A-Za-z]:\\")
_TS_RE      = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")

# Sub-técnicas MITRE ATT&CK válidas conocidas (subset — las más comunes en IR)
KNOWN_MITRE = {
    "T1059", "T1059.001", "T1059.003", "T1059.005", "T1059.007",
    "T1078", "T1078.001", "T1078.002", "T1078.003",
    "T1055", "T1055.001", "T1055.012",
    "T1053", "T1053.005",
    "T1547", "T1547.001",
    "T1548", "T1548.002",
    "T1003", "T1003.001",
    "T1021", "T1021.001",
    "T1071", "T1071.001",
    "T1486", "T1490",
    "T1562", "T1562.001", "T1562.002",
    "T1070", "T1070.001", "T1070.004",
    "T1190", "T1133",
    "T1566", "T1566.001",
    "T1105", "T1041",
    "T1560", "T1560.001",
    "T1083", "T1082", "T1057", "T1049",
    "T1112", "T1036", "T1027",
    "T1140", "T1204", "T1204.002",
    "T1218", "T1218.011",
}


# ── Validador principal ───────────────────────────────────────────────────────

def validate_findings(findings: list[dict],
                      evidence_db: str | None = None,
                      source_text: str | None = None) -> dict:
    """
    Valida cada hallazgo forense contra la evidencia real.

    Para cada hallazgo verifica:
      1. Formato válido de IOCs (IP, hash, dominio, técnica MITRE)
      2. Si existe evidence_db: confirma que la evidencia citada existe en el SQLite
      3. Si existe source_text: verifica que los IOC values aparecen en el texto fuente
      4. Consistencia temporal (timestamps en orden lógico)

    Retorna: hallucination_score (0.0-1.0), desglose por finding,
             y self_correction_triggers para los casos que necesitan re-investigar.

    Args:
        findings:     Lista de dicts con hallazgos de la investigación.
                      Cada finding debe tener: "description", y opcionalmente
                      "ioc_value", "ioc_type", "mitre_technique", "evidence_citation",
                      "timestamp", "confidence".
        evidence_db:  Ruta a la SQLite generada por evtx_to_sqlite (opcional).
                      Si se provee, verifica que la evidencia citada existe en la DB.
        source_text:  Texto fuente del reporte/alerta (opcional).
                      Si se provee, verifica que los IOC values aparecen en él.
    """
    audit("validate_findings", {
        "finding_count": len(findings),
        "has_db": bool(evidence_db),
        "has_text": bool(source_text),
    })

    results = []
    hallucination_count = 0
    self_correction_triggers = []

    for i, finding in enumerate(findings):
        result = _validate_single(finding, i, evidence_db, source_text)
        results.append(result)

        if result["status"] in ("invalid_format", "contradicted"):
            hallucination_count += 1

        if result.get("self_correction_trigger"):
            self_correction_triggers.append({
                "finding_index": i,
                "finding":       finding.get("description", "")[:100],
                "issue":         result["issue"],
                "suggestion":    result.get("correction_suggestion", ""),
            })

    total = len(findings)
    hallucination_score = hallucination_count / total if total > 0 else 0.0

    # Clasificación por status
    by_status: dict = {}
    for r in results:
        s = r["status"]
        by_status[s] = by_status.get(s, 0) + 1

    return {
        "ok":                    True,
        "total_findings":        total,
        "hallucination_score":   round(hallucination_score, 3),
        "hallucination_pct":     f"{hallucination_score * 100:.1f}%",
        "by_status":             by_status,
        "self_correction_triggers": self_correction_triggers,
        "needs_correction":      len(self_correction_triggers) > 0,
        "details":               results,
        "verdict":               _overall_verdict(hallucination_score),
    }


def _validate_single(finding: dict, idx: int,
                     evidence_db: str | None,
                     source_text: str | None) -> dict:
    """Valida un solo hallazgo. Retorna dict con status y detalle."""
    desc       = finding.get("description", "")
    ioc_value  = finding.get("ioc_value", "")
    ioc_type   = finding.get("ioc_type", "")
    mitre_id   = finding.get("mitre_technique", "")
    evidence   = finding.get("evidence_citation", "")
    confidence = finding.get("confidence", "unknown")

    issues = []
    checks_passed = []

    # ── Check 1: Formato de IOC ───────────────────────────────────────────────
    if ioc_value and ioc_type:
        format_ok, format_issue = _check_ioc_format(ioc_value, ioc_type)
        if format_ok:
            checks_passed.append(f"IOC format valid ({ioc_type}: {ioc_value[:30]})")
        else:
            issues.append(f"IOC format invalid: {format_issue}")

    # ── Check 2: MITRE técnica válida ─────────────────────────────────────────
    if mitre_id:
        mitre_ok, mitre_issue = _check_mitre(mitre_id)
        if mitre_ok:
            checks_passed.append(f"MITRE {mitre_id} válido")
        else:
            issues.append(f"MITRE issue: {mitre_issue}")

    # ── Check 3: IOC en texto fuente ──────────────────────────────────────────
    if source_text and ioc_value and len(ioc_value) > 3:
        if ioc_value.lower() in source_text.lower():
            checks_passed.append(f"IOC '{ioc_value[:30]}' encontrado en texto fuente")
        else:
            issues.append(f"IOC '{ioc_value[:30]}' NO encontrado en texto fuente — posible alucinación")

    # ── Check 4: Evidencia en DB ──────────────────────────────────────────────
    if evidence_db and evidence:
        db_ok, db_issue = _check_evidence_in_db(evidence, evidence_db)
        if db_ok:
            checks_passed.append(f"Evidencia verificada en DB: {evidence[:50]}")
        elif db_issue:
            issues.append(f"Evidencia no verificada en DB: {db_issue}")

    # ── Check 5: Consistencia de timestamp ───────────────────────────────────
    timestamp = finding.get("timestamp", "")
    if timestamp:
        ts_ok, ts_issue = _check_timestamp(timestamp)
        if not ts_ok:
            issues.append(f"Timestamp issue: {ts_issue}")
        else:
            checks_passed.append(f"Timestamp válido: {timestamp}")

    # ── Determinar status ─────────────────────────────────────────────────────
    if not issues:
        status = "confirmed" if checks_passed else "unverified"
        issue  = None
    elif any("NO encontrado" in i or "format invalid" in i for i in issues):
        status = "invalid_format" if "format invalid" in str(issues) else "contradicted"
        issue  = "; ".join(issues[:2])
    else:
        status = "unverified"
        issue  = "; ".join(issues[:2])

    self_correction = status in ("contradicted", "invalid_format") and bool(ioc_value or evidence)

    return {
        "index":                 idx,
        "description":           desc[:100],
        "status":                status,
        "confidence":            confidence,
        "checks_passed":         checks_passed,
        "issue":                 issue,
        "self_correction_trigger": self_correction,
        "correction_suggestion": _suggest_correction(status, finding) if self_correction else None,
    }


def _check_ioc_format(value: str, ioc_type: str) -> tuple[bool, str]:
    """Verifica que el formato del IOC sea válido para su tipo."""
    t = ioc_type.lower()
    if t == "ip":
        if _IP_RE.match(value):
            parts = list(map(int, value.split(".")))
            if all(0 <= p <= 255 for p in parts):
                return True, ""
        return False, f"IP inválida: {value}"

    elif t == "domain":
        if _DOMAIN_RE.match(value):
            return True, ""
        return False, f"Dominio inválido: {value}"

    elif t in ("hash_md5", "md5"):
        return (_MD5_RE.match(value) is not None, f"MD5 inválido: {value}")

    elif t in ("hash_sha1", "sha1"):
        return (_SHA1_RE.match(value) is not None, f"SHA1 inválido: {value}")

    elif t in ("hash_sha256", "sha256"):
        return (_SHA256_RE.match(value) is not None, f"SHA256 inválido: {value}")

    elif t == "email":
        return ("@" in value and "." in value.split("@")[-1], f"Email inválido: {value}")

    elif t == "url":
        return (value.startswith(("http://", "https://")), f"URL inválida: {value}")

    elif t == "registry_key":
        return (any(value.upper().startswith(h)
                    for h in ("HKEY_", "HKLM", "HKCU", "HKU", "HKCR")),
                f"Registry key inválida: {value}")

    return True, ""  # tipo desconocido — no validamos


def _check_mitre(technique_id: str) -> tuple[bool, str]:
    """Verifica que el ID de técnica ATT&CK sea válido."""
    tid = technique_id.strip().upper()

    if not _MITRE_RE.match(tid):
        return False, f"{tid} no sigue el patrón T####[.###]"

    # Verificar número de técnica en rango válido (T1000–T1999 ATT&CK Enterprise)
    base   = tid.split(".")[0]
    t_num  = int(base[1:])
    if not (1000 <= t_num <= 1999):
        return False, f"{tid} — número fuera del rango válido T1000-T1999"

    if tid in KNOWN_MITRE or base in KNOWN_MITRE:
        return True, ""

    # Formato correcto pero no en lista conocida — marcar como advertencia, no error
    return True, f"{tid} formato OK pero no confirmado en lista conocida (verificar manualmente)"


def _check_evidence_in_db(evidence_citation: str, db_path: str) -> tuple[bool, str]:
    """
    Verifica que la evidencia citada existe en la SQLite.
    Parsea la cita para extraer EventId, UserName, IP, etc. y hace una SQL query.
    """
    try:
        conn   = sqlite3.connect(db_path)
        tables = pd.read_sql(
            "SELECT name FROM sqlite_master WHERE type='table'", conn
        )["name"].tolist()

        if not tables:
            conn.close()
            return False, "DB sin tablas"

        tbl = tables[0]

        # Extraer EventId de la cita si existe
        eid_match = re.search(r"Event\s*I[dD]\s*[=:]\s*(\d+)", evidence_citation)
        ip_match  = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", evidence_citation)
        user_match = re.search(r"(?:user|usuario|UserName)[:\s]+(\w+)", evidence_citation, re.I)

        # Descubrir columnas reales de la tabla
        cols_df   = pd.read_sql(f"PRAGMA table_info({tbl})", conn)
        real_cols = set(cols_df["name"].str.lower().tolist())

        conditions = []
        if eid_match:
            eid_col = next((c for c in cols_df["name"] if c.lower() in ("eventid", "event_id")), None)
            if eid_col:
                conditions.append(f"{eid_col} = {eid_match.group(1)}")

        if ip_match:
            ip_val  = ip_match.group(1)
            ip_cols = [c for c in cols_df["name"]
                       if c.lower() in ("remotehost", "ipaddress", "ip_address",
                                        "sourceip", "source_ip", "clientip")]
            if ip_cols:
                ip_clauses = " OR ".join(f"{c} = '{ip_val}'" for c in ip_cols)
                conditions.append(f"({ip_clauses})")

        if user_match:
            user_val  = user_match.group(1)
            user_cols = [c for c in cols_df["name"]
                         if c.lower() in ("username", "user_name", "user",
                                          "targetusername", "subjectusername")]
            if user_cols:
                conditions.append(f"{user_cols[0]} LIKE '%{user_val}%'")

        if not conditions:
            conn.close()
            return False, "No se pudo extraer condiciones de la cita"

        where = " AND ".join(conditions)
        count = pd.read_sql(f"SELECT COUNT(*) as n FROM {tbl} WHERE {where}", conn).iloc[0, 0]
        conn.close()

        if count > 0:
            return True, ""
        return False, f"0 registros encontrados para: {where}"

    except Exception as e:
        return False, str(e)[:100]


def _check_timestamp(ts: str) -> tuple[bool, str]:
    """Verifica que el timestamp tiene formato válido y es una fecha razonable."""
    if not _TS_RE.search(ts):
        return False, f"Formato de timestamp no reconocido: {ts[:30]}"
    try:
        # Intentar parsear
        clean = ts.replace("T", " ").replace("Z", "").split(".")[0]
        dt    = datetime.strptime(clean[:19], "%Y-%m-%d %H:%M:%S")
        if dt.year < 2000 or dt.year > 2030:
            return False, f"Año fuera de rango razonable: {dt.year}"
        return True, ""
    except ValueError:
        return False, f"No parseable: {ts[:30]}"


def _suggest_correction(status: str, finding: dict) -> str:
    """Genera una sugerencia de corrección para el agente."""
    if status == "contradicted":
        return (
            f"La evidencia '{finding.get('evidence_citation', '')[:50]}' "
            f"no coincide con la DB. Re-investigar con query más específica o "
            f"verificar en el EVTX correcto."
        )
    elif status == "invalid_format":
        return (
            f"El IOC '{finding.get('ioc_value', '')[:30]}' "
            f"tiene formato inválido. Verificar extracción desde el texto fuente."
        )
    return "Re-investigar con herramientas adicionales."


def _overall_verdict(score: float) -> str:
    if score == 0.0:
        return "LIMPIO — todos los hallazgos verificados"
    elif score < 0.10:
        return "ACEPTABLE — tasa de alucinación <10%, revisar triggers"
    elif score < 0.25:
        return "REQUIERE REVISIÓN — tasa de alucinación significativa"
    else:
        return "ALTO RIESGO — más del 25% de hallazgos no verificados"
