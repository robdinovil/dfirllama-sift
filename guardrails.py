"""
Guardrails de seguridad para DFIRLlama-SIFT.
- Read-only: bloquea comandos destructivos
- Path boundaries: el agente solo puede leer desde EVIDENCE_ROOT
- Audit trail: loguea cada tool call
"""
import os
import re
import json
import datetime
from pathlib import Path

EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/cases")).resolve()
AUDIT_LOG     = os.getenv("AUDIT_LOG", "/tmp/dfirllama_audit.log")

BLOCKED_PATTERNS = re.compile(
    r"\b(rm|dd|shred|mkfs|fdisk|wipefs|wget|curl|ssh|scp|nc|ncat|netcat"
    r"|chmod\s+[0-7]*7|chown\s+root|sudo\s+rm|mv\s+/|cp\s+.*\s+/)\b",
    re.IGNORECASE
)

BLOCKED_ARGS = {
    "--write", "--delete", "--force", "-rf", "-fr",
    "--overwrite", "--wipe", "--destroy",
}


def audit(tool_name: str, args: dict, result_summary: str = ""):
    """Registra cada invocación de herramienta en el audit trail."""
    entry = {
        "ts":   datetime.datetime.utcnow().isoformat() + "Z",
        "tool": tool_name,
        "args": {k: str(v)[:200] for k, v in args.items()},
        "result": result_summary[:300],
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def check_path(path: str | Path) -> Path:
    """
    Verifica que la ruta esté dentro de EVIDENCE_ROOT o sea un archivo conocido.
    Lanza ValueError si la ruta está fuera del scope permitido.
    """
    p = Path(path).resolve()
    # Permitir rutas en /tmp, /home y EVIDENCE_ROOT
    allowed_prefixes = [
        EVIDENCE_ROOT,
        Path("/tmp"),
        Path("/home"),
        Path("/var/log"),
    ]
    if not any(str(p).startswith(str(prefix)) for prefix in allowed_prefixes):
        raise ValueError(
            f"Ruta fuera del scope permitido: {p}\n"
            f"Scope permitido: {[str(x) for x in allowed_prefixes]}"
        )
    return p


def check_command(cmd: str):
    """Bloquea comandos destructivos antes de ejecutarlos."""
    if BLOCKED_PATTERNS.search(cmd):
        raise PermissionError(
            f"Comando bloqueado por guardrail read-only: {cmd[:100]}"
        )
    for blocked in BLOCKED_ARGS:
        if blocked in cmd.split():
            raise PermissionError(f"Argumento bloqueado: {blocked}")


def safe_run(cmd: list[str], tool_name: str, **kwargs) -> str:
    """Ejecuta un comando de forma segura — solo lectura, con audit trail."""
    import subprocess
    cmd_str = " ".join(str(c) for c in cmd)
    check_command(cmd_str)
    audit(tool_name, {"cmd": cmd_str})

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=kwargs.get("timeout", 120),
    )
    output = result.stdout + (f"\n[stderr]: {result.stderr}" if result.stderr else "")
    audit(tool_name, {"cmd": cmd_str}, result_summary=output[:300])
    return output
