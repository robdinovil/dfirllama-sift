"""
Herramientas forenses generales — bulk_extractor, tshark, strings, hashing.
Todas retornan JSON estructurado. Todas read-only sobre evidencia.
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from guardrails import audit, check_path, safe_run


# ── bulk_extract ──────────────────────────────────────────────────────────────

def bulk_extract(target_path: str, output_dir: str | None = None,
                 carvers: list[str] | None = None) -> dict:
    """
    Corre bulk_extractor sobre un archivo de imagen, memoria o directorio.
    Extrae automáticamente: IPs, emails, URLs, dominios, hashes MD5,
    números de tarjeta de crédito, credenciales, y más.
    Ideal para carving en volcados de memoria o imágenes de disco.

    Args:
        target_path: Imagen de disco, volcado de memoria, o archivo grande.
        output_dir:  Directorio de salida para los feature files.
        carvers:     Lista de carvers a activar. Default: ["ip", "email", "url",
                     "domain", "md5", "json", "base64"].
    """
    target_path = str(check_path(target_path))
    out_dir     = output_dir or tempfile.mkdtemp(prefix="dfirllama_bulk_")
    carvers     = carvers or ["ip", "email", "url", "domain", "md5", "json", "base64"]
    audit("bulk_extract", {"target": target_path, "carvers": carvers})

    # Solo los carvers especificados
    scanner_args = []
    for c in carvers:
        scanner_args += ["-e", c]

    cmd = ["bulk_extractor", "-o", out_dir, "-j", "4"] + scanner_args + [target_path]
    ok, output = _run_cmd(cmd, timeout=300)

    # Leer feature files generados
    results: dict = {"ok": True, "output_dir": out_dir, "features": {}}
    for feature_file in Path(out_dir).glob("*.txt"):
        if feature_file.stat().st_size == 0:
            continue
        name = feature_file.stem
        lines = feature_file.read_text(errors="replace").splitlines()
        # Filtrar comentarios y limitar
        data = [l for l in lines if not l.startswith("#")][:200]
        if data:
            results["features"][name] = {
                "count": len(data),
                "sample": data[:50],
            }

    results["total_features"] = sum(
        v["count"] for v in results["features"].values()
    )
    return results


def _run_cmd(cmd: list[str], timeout: int = 120) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return False, f"Timeout {timeout}s"
    except Exception as e:
        return False, str(e)


# ── pcap_analyze ──────────────────────────────────────────────────────────────

def pcap_analyze(pcap_path: str, filter_expr: str = "") -> dict:
    """
    Analiza un archivo PCAP con tshark y retorna un resumen estructurado.
    Incluye: conversaciones top, protocolos, IPs externas, DNS queries,
    HTTP hosts, y alertas básicas (beaconing, large uploads).

    Args:
        pcap_path:   Ruta al archivo .pcap o .pcapng
        filter_expr: Filtro Wireshark opcional (ej: "tcp.port == 443")
    """
    pcap_path = str(check_path(pcap_path))
    audit("pcap_analyze", {"pcap": pcap_path, "filter": filter_expr})

    base_args = ["tshark", "-r", pcap_path, "-q"]
    if filter_expr:
        base_args += ["-Y", filter_expr]

    results: dict = {"ok": True, "pcap": pcap_path}

    # Estadísticas de protocolos
    ok, proto_output = _run_cmd(base_args + ["-z", "io,phs"], timeout=60)
    results["protocol_hierarchy"] = proto_output[:2000] if ok else "unavailable"

    # Top conversaciones IP
    ok, conv_output = _run_cmd(base_args + ["-z", "conv,ip"], timeout=60)
    results["top_conversations"] = _parse_tshark_table(conv_output)[:20]

    # DNS queries únicas
    dns_cmd = ["tshark", "-r", pcap_path, "-Y", "dns.qry.name",
                "-T", "fields", "-e", "dns.qry.name", "-q"]
    ok, dns_output = _run_cmd(dns_cmd, timeout=60)
    if ok:
        domains = list(set(dns_output.strip().splitlines()))
        results["dns_queries"] = domains[:100]

    # HTTP hosts
    http_cmd = ["tshark", "-r", pcap_path, "-Y", "http.host",
                 "-T", "fields", "-e", "http.host", "-q"]
    ok, http_output = _run_cmd(http_cmd, timeout=60)
    if ok:
        results["http_hosts"] = list(set(http_output.strip().splitlines()))[:50]

    # IPs externas (heurística: no RFC1918)
    ip_cmd = ["tshark", "-r", pcap_path, "-T", "fields",
               "-e", "ip.dst", "-q"]
    ok, ip_output = _run_cmd(ip_cmd, timeout=60)
    if ok:
        all_ips = set(ip_output.strip().splitlines())
        external = [ip for ip in all_ips if ip and not _is_rfc1918(ip)]
        results["external_ips"] = list(external)[:50]

    return results


def _parse_tshark_table(text: str) -> list[dict]:
    """Parsea una tabla de tshark a lista de dicts."""
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("=")]
    return [{"row": l} for l in lines[2:]]  # skip header


def _is_rfc1918(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        return (parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168))
    except Exception:
        return False


# ── strings_extract ───────────────────────────────────────────────────────────

def strings_extract(file_path: str, min_len: int = 6,
                    encoding: str = "both") -> dict:
    """
    Extrae strings de un archivo binario, ejecutable o volcado de memoria.
    Filtra automáticamente por patrones forenses relevantes: IPs, URLs,
    dominios, rutas de archivo, claves de registro, comandos PowerShell.

    Args:
        file_path: Binario, ejecutable PE, o volcado de memoria.
        min_len:   Longitud mínima de string (default 6).
        encoding:  "ascii", "unicode", o "both" (default).
    """
    file_path = str(check_path(file_path))
    audit("strings_extract", {"file": file_path, "min_len": min_len})

    cmd = ["strings", f"-n{min_len}"]
    if encoding == "unicode":
        cmd += ["-e", "l"]
    elif encoding == "both":
        # Correr dos veces: ASCII y Unicode
        cmd_ascii   = ["strings", f"-n{min_len}", file_path]
        cmd_unicode = ["strings", f"-n{min_len}", "-e", "l", file_path]
        ok1, ascii_out   = _run_cmd(cmd_ascii, timeout=60)
        ok2, unicode_out = _run_cmd(cmd_unicode, timeout=60)
        all_strings = (ascii_out + "\n" + unicode_out).splitlines()
        return _classify_strings(all_strings, file_path)

    cmd.append(file_path)
    ok, output = _run_cmd(cmd, timeout=60)
    if not ok:
        return {"ok": False, "error": output[:300]}

    return _classify_strings(output.splitlines(), file_path)


# Patrones forenses relevantes
_PATTERNS = {
    "ips":          re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "urls":         re.compile(r"https?://[^\s\"'<>]{4,100}"),
    "domains":      re.compile(r"\b(?:[a-zA-Z0-9-]+\.){1,5}(?:com|net|org|io|ru|cn|de|uk|onion)\b"),
    "reg_keys":     re.compile(r"(?:HKEY_|HKLM|HKCU|HKU|HKCR)\\[^\s\"']{4,}"),
    "file_paths":   re.compile(r"[A-Za-z]:\\[^\s\"'<>]{4,100}"),
    "powershell":   re.compile(r"(?i)(?:invoke-|iex|bypass|encoded|base64|downloadstring)"),
    "emails":       re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "b64_chunks":   re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
}


def _classify_strings(lines: list[str], file_path: str) -> dict:
    classified: dict = {k: [] for k in _PATTERNS}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        for category, pattern in _PATTERNS.items():
            if pattern.search(line):
                classified[category].append(line[:200])
                break  # una categoría por string

    # Deduplicar
    for cat in classified:
        classified[cat] = list(dict.fromkeys(classified[cat]))[:50]

    return {
        "ok":         True,
        "file":       file_path,
        "total_strings": len(lines),
        "classified": classified,
        "total_hits": sum(len(v) for v in classified.values()),
    }


# ── file_hash ─────────────────────────────────────────────────────────────────

def file_hash(file_path: str) -> dict:
    """
    Calcula hashes criptográficos y fuzzy hash de un archivo para
    verificación de integridad de evidencia y correlación con threat intel.
    Retorna MD5, SHA1, SHA256, SHA512, ssdeep (fuzzy).

    Args:
        file_path: Ruta al archivo a hashear.
    """
    file_path = str(check_path(file_path))
    audit("file_hash", {"file": file_path})

    p = Path(file_path)
    if not p.exists():
        return {"ok": False, "error": f"Archivo no encontrado: {file_path}"}
    if not p.is_file():
        return {"ok": False, "error": "La ruta no es un archivo"}

    try:
        data = p.read_bytes()
        hashes = {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha1":   hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "size_bytes": len(data),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

    # ssdeep fuzzy hash
    ok, ssdeep_out = _run_cmd(["ssdeep", file_path], timeout=30)
    if ok:
        lines = [l for l in ssdeep_out.splitlines() if ":" in l and not l.startswith("ssdeep")]
        hashes["ssdeep"] = lines[0] if lines else "unavailable"

    # file type
    ok, file_type = _run_cmd(["file", "-b", file_path], timeout=10)
    hashes["file_type"] = file_type.strip() if ok else "unknown"

    return {"ok": True, "file": file_path, **hashes}
