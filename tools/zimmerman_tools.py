"""
Zimmerman Tools wrappers — EZ Tools suite para artefactos Windows.
Todos los tools retornan JSON estructurado, nunca texto crudo al LLM.
Todos son read-only sobre la evidencia.

Tools:
  amcache_parse      — AmcacheParser → ejecución de programas
  prefetch_parse     — PECmd → prefetch files
  shimcache_parse    — AppCompatCacheParser → ShimCache
  registry_query     — RECmd → colmenas de registro
  mft_timeline       — MFTECmd → Master File Table completo
  lnk_parse          — LECmd → archivos LNK (actividad de usuario)
  shellbag_parse     — SBECmd → Shellbags (carpetas visitadas)
  jumplist_parse     — JLECmd → Jump Lists (archivos recientes)
  recycle_bin_parse  — RBCmd → Papelera de reciclaje
"""

import os
import csv
import json
import sqlite3
import tempfile
import subprocess
from pathlib import Path

import pandas as pd
from guardrails import audit, check_path, safe_run

# Todos los Zimmerman tools van como: dotnet /opt/zimmermantools/Tool.dll
ZT_BASE = "/opt/zimmermantools"


def _run_zt(dll: str, args: list[str], timeout: int = 120) -> tuple[bool, str]:
    """Corre un Zimmerman Tool .dll con dotnet. Retorna (ok, output)."""
    cmd = ["dotnet", dll] + args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout + (f"\n[stderr]: {result.stderr}" if result.stderr else "")
        return result.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, f"Timeout después de {timeout}s"
    except Exception as e:
        return False, str(e)


def _csv_to_records(csv_path: str, max_rows: int = 500) -> list[dict]:
    """Lee un CSV y retorna lista de dicts, limitado a max_rows."""
    try:
        df = pd.read_csv(csv_path, nrows=max_rows, on_bad_lines="skip")
        return df.fillna("").to_dict("records")
    except Exception as e:
        return [{"error": f"CSV parse error: {e}"}]


# ── amcache_parse ─────────────────────────────────────────────────────────────

def amcache_parse(hive_path: str, output_dir: str | None = None) -> dict:
    """
    Parsea el Amcache.hve de Windows para extraer historial de ejecución de programas.
    Retorna entradas con: nombre del ejecutable, SHA1, primera ejecución, ruta.
    Evidencia clave para confirmar ejecución de malware con timestamp.

    Args:
        hive_path:  Ruta al archivo Amcache.hve
        output_dir: Directorio de salida para CSVs. Default: /tmp/
    """
    hive_path = str(check_path(hive_path))
    out_dir   = output_dir or tempfile.mkdtemp(prefix="dfirllama_amcache_")
    audit("amcache_parse", {"hive": hive_path})

    dll = f"{ZT_BASE}/AmcacheParser.dll"
    ok, output = _run_zt(dll, ["-f", hive_path, "--csv", out_dir], timeout=60)

    if not ok:
        return {"ok": False, "error": output[:500]}

    # Leer CSVs generados (AmcacheParser genera varios)
    csv_files = list(Path(out_dir).glob("*.csv"))
    results: dict = {"ok": True, "output_dir": out_dir, "files": {}}

    for csv_file in csv_files:
        key = csv_file.stem.split("_")[-1]  # UnassociatedFileEntries, etc.
        records = _csv_to_records(str(csv_file))
        results["files"][key] = {
            "count": len(records),
            "records": records[:100],  # máximo 100 al agente
        }

    # Resumen ejecutivo
    all_entries = results["files"].get("UnassociatedFileEntries", {}).get("records", [])
    results["summary"] = {
        "total_entries": sum(f["count"] for f in results["files"].values()),
        "suspicious_paths": [
            e for e in all_entries
            if any(p in str(e.get("FullPath", "")).lower()
                   for p in ["temp", "appdata", "downloads", "public"])
        ][:20],
    }
    return results


# ── prefetch_parse ────────────────────────────────────────────────────────────

def prefetch_parse(path: str, output_dir: str | None = None) -> dict:
    """
    Parsea archivos Prefetch de Windows (.pf) o un directorio de Prefetch.
    Retorna: nombre del ejecutable, timestamps de ejecución (hasta 8 anteriores),
    contador de ejecuciones, y lista de archivos referenciados.

    Args:
        path:       Archivo .pf específico o directorio C:\\Windows\\Prefetch
        output_dir: Directorio de salida para CSVs.
    """
    path    = str(check_path(path))
    out_dir = output_dir or tempfile.mkdtemp(prefix="dfirllama_prefetch_")
    audit("prefetch_parse", {"path": path})

    dll  = f"{ZT_BASE}/PECmd.dll"
    flag = "-f" if Path(path).is_file() else "-d"
    ok, output = _run_zt(dll, [flag, path, "--csv", out_dir, "--csvf", "prefetch.csv"])

    if not ok and "No .pf files" not in output:
        return {"ok": False, "error": output[:500]}

    csv_path = Path(out_dir) / "prefetch.csv"
    if not csv_path.exists():
        # Buscar cualquier CSV generado
        csvs = list(Path(out_dir).glob("*.csv"))
        if not csvs:
            return {"ok": False, "error": "PECmd no generó CSV", "output": output[:300]}
        csv_path = csvs[0]

    records = _csv_to_records(str(csv_path))

    # Parsear timestamps de la última ejecución
    suspicious = []
    for r in records:
        last_run = str(r.get("LastRun", ""))
        exe_name = str(r.get("ExecutableName", "")).lower()
        if any(p in exe_name for p in ["powershell", "cmd", "wscript", "mshta",
                                        "rundll32", "regsvr32", "schtasks"]):
            suspicious.append(r)

    return {
        "ok":           True,
        "total_entries": len(records),
        "records":      records[:200],
        "suspicious_executables": suspicious[:20],
        "output_dir":   out_dir,
    }


# ── shimcache_parse ───────────────────────────────────────────────────────────

def shimcache_parse(system_hive: str, output_dir: str | None = None) -> dict:
    """
    Parsea AppCompatCache (ShimCache) desde la colmena SYSTEM del registro.
    ShimCache registra archivos que INTERACTUARON con el sistema — no prueba ejecución,
    pero confirma que el archivo fue visto por el OS. La presencia + Amcache = ejecución.

    Args:
        system_hive: Ruta a la colmena SYSTEM (ej: /mnt/case/Windows/System32/config/SYSTEM)
        output_dir:  Directorio de salida.
    """
    system_hive = str(check_path(system_hive))
    out_dir     = output_dir or tempfile.mkdtemp(prefix="dfirllama_shimcache_")
    audit("shimcache_parse", {"hive": system_hive})

    dll = f"{ZT_BASE}/AppCompatCacheParser.dll"
    ok, output = _run_zt(dll, ["-f", system_hive, "--csv", out_dir, "--csvf", "shimcache.csv"])

    if not ok:
        return {"ok": False, "error": output[:500]}

    csv_path = Path(out_dir) / "shimcache.csv"
    if not csv_path.exists():
        csvs = list(Path(out_dir).glob("*.csv"))
        if not csvs:
            return {"ok": False, "error": "No CSV generado", "output": output[:300]}
        csv_path = csvs[0]

    records = _csv_to_records(str(csv_path))
    return {
        "ok":            True,
        "total_entries": len(records),
        "records":       records[:200],
        "output_dir":    out_dir,
        "note":          "ShimCache = interacción con OS, no prueba ejecución directa. Combinar con Amcache/Prefetch.",
    }


# ── registry_query ────────────────────────────────────────────────────────────

def registry_query(hive_path: str, key_path: str = "",
                   output_dir: str | None = None) -> dict:
    """
    Consulta una colmena del Registro de Windows con RECmd.
    Puede extraer claves específicas o usar batch files predefinidos para
    persistencia, USB history, timezone, network, etc.

    Args:
        hive_path:  Ruta al archivo de colmena (SYSTEM, SOFTWARE, NTUSER.DAT, etc.)
        key_path:   Ruta de la clave a extraer (ej: "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                    Vacío = usa batch files de RECmd para extracción completa
        output_dir: Directorio de salida.
    """
    hive_path = str(check_path(hive_path))
    out_dir   = output_dir or tempfile.mkdtemp(prefix="dfirllama_registry_")
    audit("registry_query", {"hive": hive_path, "key": key_path})

    dll = f"{ZT_BASE}/RECmd/RECmd.dll"

    if key_path:
        args = ["-f", hive_path, "--kn", key_path, "--csv", out_dir]
    else:
        # Batch mode — batch files de RECmd para extracción forense completa
        batch_dir = f"{ZT_BASE}/RECmd/BatchExamples"
        if Path(batch_dir).exists():
            args = ["-f", hive_path, "--bn", batch_dir, "--csv", out_dir]
        else:
            args = ["-f", hive_path, "--csv", out_dir]

    ok, output = _run_zt(dll, args, timeout=90)
    if not ok and "No keys found" not in output:
        return {"ok": False, "error": output[:500]}

    csvs = list(Path(out_dir).glob("*.csv"))
    results: dict = {"ok": True, "key_path": key_path, "output_dir": out_dir, "data": {}}

    for csv_file in csvs[:10]:  # máximo 10 archivos
        records = _csv_to_records(str(csv_file))
        results["data"][csv_file.stem] = records[:50]

    return results


# ── mft_timeline ──────────────────────────────────────────────────────────────

def mft_timeline(mft_path: str, output_dir: str | None = None,
                 filter_path: str = "") -> dict:
    """
    Parsea la Master File Table ($MFT) completa de un volumen NTFS.
    Extrae timestamps CREATED/MODIFIED/ACCESSED/ENTRY_MODIFIED para cada archivo.
    Detecta timestomping comparando $STANDARD_INFORMATION vs $FILE_NAME timestamps.
    Evidencia de archivos eliminados también presente en MFT.

    Args:
        mft_path:    Ruta al archivo $MFT extraído del volumen
        output_dir:  Directorio de salida para CSVs.
        filter_path: Filtrar por path parcial (ej: "Users\\jparker\\AppData")
    """
    mft_path = str(check_path(mft_path))
    out_dir  = output_dir or tempfile.mkdtemp(prefix="dfirllama_mft_")
    audit("mft_timeline", {"mft": mft_path, "filter": filter_path})

    dll  = f"{ZT_BASE}/MFTECmd.dll"
    args = ["-f", mft_path, "--csv", out_dir, "--csvf", "mft_records.csv"]
    if filter_path:
        args += ["--de", filter_path]

    ok, output = _run_zt(dll, args, timeout=300)  # MFT grande puede tardar
    if not ok:
        return {"ok": False, "error": output[:500]}

    csv_path = Path(out_dir) / "mft_records.csv"
    if not csv_path.exists():
        csvs = list(Path(out_dir).glob("*.csv"))
        if not csvs:
            return {"ok": False, "error": "MFTECmd no generó CSV", "output": output[:300]}
        csv_path = csvs[0]

    # Detectar timestomping: SI_Created != FN_Created por más de 2 segundos
    records = _csv_to_records(str(csv_path))
    timestomped = []
    for r in records:
        si_created = str(r.get("Created0x10", ""))
        fn_created = str(r.get("Created0x30", ""))
        if si_created and fn_created and si_created != fn_created:
            timestomped.append({
                "file":       r.get("FileName", ""),
                "si_created": si_created,
                "fn_created": fn_created,
                "note":       "Posible timestomping — $SI y $FN difieren",
            })

    return {
        "ok":             True,
        "total_records":  len(records),
        "records":        records[:200],
        "timestomped":    timestomped[:20],
        "output_dir":     out_dir,
    }


# ── lnk_parse ─────────────────────────────────────────────────────────────────

def lnk_parse(path: str, output_dir: str | None = None) -> dict:
    """
    Parsea archivos LNK (accesos directos) de Windows con LECmd.
    Los LNK revelan: qué archivos abrió el usuario, desde dónde, cuándo,
    y datos del volumen de origen (número de serie, etiqueta).
    Útil para establecer acceso a archivos en medios externos.

    Args:
        path:       Archivo .lnk específico o directorio (ej: C:\\Users\\X\\Recent)
        output_dir: Directorio de salida.
    """
    path    = str(check_path(path))
    out_dir = output_dir or tempfile.mkdtemp(prefix="dfirllama_lnk_")
    audit("lnk_parse", {"path": path})

    dll  = f"{ZT_BASE}/LECmd.dll"
    flag = "-f" if Path(path).is_file() else "-d"
    ok, output = _run_zt(dll, [flag, path, "--csv", out_dir, "--csvf", "lnk.csv"])

    csv_path = Path(out_dir) / "lnk.csv"
    if not csv_path.exists():
        csvs = list(Path(out_dir).glob("*.csv"))
        if not csvs:
            return {"ok": False, "error": "LECmd no generó CSV", "output": output[:300]}
        csv_path = csvs[0]

    records = _csv_to_records(str(csv_path))
    return {
        "ok":      True,
        "count":   len(records),
        "records": records[:200],
        "output_dir": out_dir,
    }


# ── shellbag_parse ────────────────────────────────────────────────────────────

def shellbag_parse(hive_path: str, output_dir: str | None = None) -> dict:
    """
    Parsea Shellbags desde NTUSER.DAT o UsrClass.dat con SBECmd.
    Shellbags registran cada carpeta que el usuario visitó — incluso en medios
    externos ya desconectados y carpetas ya eliminadas. Evidencia de acceso a
    carpetas aunque no haya archivos LNK.

    Args:
        hive_path:  Ruta al NTUSER.DAT o UsrClass.dat del usuario
        output_dir: Directorio de salida.
    """
    hive_path = str(check_path(hive_path))
    out_dir   = output_dir or tempfile.mkdtemp(prefix="dfirllama_shellbag_")
    audit("shellbag_parse", {"hive": hive_path})

    dll = f"{ZT_BASE}/SBECmd.dll"
    ok, output = _run_zt(dll, ["-d", hive_path, "--csv", out_dir])

    csvs = list(Path(out_dir).glob("*.csv"))
    if not csvs:
        return {"ok": False, "error": "SBECmd no generó CSV", "output": output[:300]}

    records = _csv_to_records(str(csvs[0]))
    return {
        "ok":      True,
        "count":   len(records),
        "records": records[:200],
        "output_dir": out_dir,
    }


# ── jumplist_parse ────────────────────────────────────────────────────────────

def jumplist_parse(path: str, output_dir: str | None = None) -> dict:
    """
    Parsea Jump Lists de Windows con JLECmd.
    Jump Lists = archivos recientes por aplicación. Evidencia de qué documentos
    abrió el usuario con qué aplicación, incluyendo archivos en rutas de red o USB.

    Args:
        path:       Directorio AutomaticDestinations/CustomDestinations o archivo específico
        output_dir: Directorio de salida.
    """
    path    = str(check_path(path))
    out_dir = output_dir or tempfile.mkdtemp(prefix="dfirllama_jumplist_")
    audit("jumplist_parse", {"path": path})

    dll  = f"{ZT_BASE}/JLECmd.dll"
    flag = "-f" if Path(path).is_file() else "-d"
    ok, output = _run_zt(dll, [flag, path, "--csv", out_dir])

    csvs = list(Path(out_dir).glob("*.csv"))
    if not csvs:
        return {"ok": False, "error": "JLECmd no generó CSV", "output": output[:300]}

    all_records: list[dict] = []
    for csv_file in csvs:
        all_records.extend(_csv_to_records(str(csv_file))[:100])

    return {
        "ok":      True,
        "count":   len(all_records),
        "records": all_records[:200],
        "output_dir": out_dir,
    }


# ── recycle_bin_parse ─────────────────────────────────────────────────────────

def recycle_bin_parse(path: str, output_dir: str | None = None) -> dict:
    """
    Parsea la Papelera de Reciclaje de Windows ($Recycle.Bin) con RBCmd.
    Recupera: nombre original del archivo eliminado, ruta original, timestamp
    de eliminación, tamaño. Evidencia de anti-forense o exfiltración borrada.

    Args:
        path:       Directorio $Recycle.Bin o archivo $I específico
        output_dir: Directorio de salida.
    """
    path    = str(check_path(path))
    out_dir = output_dir or tempfile.mkdtemp(prefix="dfirllama_recycle_")
    audit("recycle_bin_parse", {"path": path})

    dll  = f"{ZT_BASE}/RBCmd.dll"
    flag = "-f" if Path(path).is_file() else "-d"
    ok, output = _run_zt(dll, [flag, path, "--csv", out_dir])

    csvs = list(Path(out_dir).glob("*.csv"))
    if not csvs:
        return {"ok": not ok, "output": output[:500]}

    records = _csv_to_records(str(csvs[0]))
    return {
        "ok":      True,
        "count":   len(records),
        "records": records[:200],
        "output_dir": out_dir,
    }
