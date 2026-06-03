"""
Wrappers read-only para herramientas nativas de SIFT.

volatility_run:    ejecuta un plugin de Volatility3 sobre una imagen de memoria
log2timeline_run:  corre plaso sobre un artefacto y retorna la supertimeline CSV
yara_scan:         aplica reglas YARA a un archivo o directorio
map_to_mitre:      mapea hallazgos de triage a técnicas MITRE ATT&CK
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

from guardrails import audit, check_path, safe_run
from llm.client import chat_completion

# ── Volatility3 ───────────────────────────────────────────────────────────────

VOLATILITY_BIN = os.getenv("VOLATILITY_BIN", "vol")
VOLATILITY_SAFE_PLUGINS = {
    "windows.pslist", "windows.pstree", "windows.cmdline",
    "windows.dlllist", "windows.netscan", "windows.netstat",
    "windows.malfind", "windows.handles", "windows.filescan",
    "windows.registry.printkey", "windows.registry.hivelist",
    "windows.hashdump", "windows.sessions",
    "linux.pslist", "linux.bash", "linux.check_modules",
}


def volatility_run(image_path: str, plugin: str, plugin_args: str = "") -> dict:
    """
    Ejecuta un plugin de Volatility3 sobre una imagen de memoria (read-only).
    Solo se permiten plugins de análisis — no se permite escribir ni modificar la imagen.

    Args:
        image_path:  Ruta a la imagen de memoria (.raw, .vmem, .lime, etc.)
        plugin:      Plugin a ejecutar (ej: "windows.pslist", "windows.netscan")
        plugin_args: Argumentos adicionales del plugin (ej: "--pid 1234")
    """
    image_path = str(check_path(image_path))
    plugin     = plugin.lower().strip()

    if plugin not in VOLATILITY_SAFE_PLUGINS:
        return {
            "ok":    False,
            "error": f"Plugin '{plugin}' no está en la lista permitida.",
            "allowed_plugins": sorted(VOLATILITY_SAFE_PLUGINS),
        }

    audit("volatility_run", {"image": image_path, "plugin": plugin, "args": plugin_args})

    cmd = [VOLATILITY_BIN, "-f", image_path, plugin]
    if plugin_args:
        cmd += plugin_args.split()

    output = safe_run(cmd, "volatility_run", timeout=180)
    lines  = [l for l in output.splitlines() if l.strip()]

    return {
        "ok":        True,
        "image":     image_path,
        "plugin":    plugin,
        "output":    output[:8000],
        "line_count": len(lines),
    }


# ── log2timeline / plaso ──────────────────────────────────────────────────────

def log2timeline_run(artifact_path: str, output_dir: str | None = None,
                     filter_str: str = "") -> dict:
    """
    Corre log2timeline (plaso) sobre un artefacto para generar una supertimeline.
    El proceso es read-only sobre el artefacto — el output va a un directorio temporal.

    Args:
        artifact_path: Ruta al artefacto (.evtx, imagen de disco, directorio)
        output_dir:    Directorio de salida. Si None, usa /tmp/dfirllama_plaso/
        filter_str:    Filtro temporal (ej: "2024-06-01 00:00:00 2024-06-30 23:59:59")
    """
    artifact_path = str(check_path(artifact_path))
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="dfirllama_plaso_")

    plaso_file = Path(output_dir) / "timeline.plaso"
    csv_file   = Path(output_dir) / "timeline.csv"

    audit("log2timeline_run", {"artifact": artifact_path, "output_dir": output_dir})

    # Paso 1: log2timeline
    cmd1 = ["log2timeline.py", str(plaso_file), artifact_path]
    out1 = safe_run(cmd1, "log2timeline_run", timeout=300)

    if not plaso_file.exists():
        return {"ok": False, "error": "log2timeline no generó el .plaso", "output": out1}

    # Paso 2: psort → CSV
    cmd2 = ["psort.py", "-o", "l2tcsv", "-w", str(csv_file), str(plaso_file)]
    if filter_str:
        cmd2 += ["--slice", filter_str]
    out2 = safe_run(cmd2, "log2timeline_run_psort", timeout=120)

    return {
        "ok":          csv_file.exists(),
        "plaso_file":  str(plaso_file),
        "csv_file":    str(csv_file) if csv_file.exists() else None,
        "output":      (out1 + "\n" + out2)[:3000],
    }


# ── YARA ──────────────────────────────────────────────────────────────────────

def yara_scan(target_path: str, rules_path: str,
              recursive: bool = True, timeout: int = 60) -> dict:
    """
    Aplica reglas YARA a un archivo o directorio. Read-only.

    Args:
        target_path: Archivo o directorio a escanear.
        rules_path:  Archivo .yar o directorio con reglas YARA.
        recursive:   Si True, escanea subdirectorios.
        timeout:     Timeout en segundos por archivo.
    """
    target_path = str(check_path(target_path))
    rules_path  = str(check_path(rules_path))

    audit("yara_scan", {"target": target_path, "rules": rules_path})

    try:
        import yara
        rules = yara.compile(filepath=rules_path) if Path(rules_path).is_file() \
            else yara.compile(rulesdir=rules_path)

        matches_found = []
        target = Path(target_path)
        files  = list(target.rglob("*") if (recursive and target.is_dir()) else [target])
        files  = [f for f in files if f.is_file()]

        for f in files[:500]:  # límite de seguridad
            try:
                hits = rules.match(str(f), timeout=timeout)
                if hits:
                    matches_found.append({
                        "file":  str(f),
                        "rules": [h.rule for h in hits],
                        "tags":  [h.tags for h in hits],
                    })
            except yara.TimeoutError:
                matches_found.append({"file": str(f), "error": "timeout"})
            except Exception:
                continue

        return {
            "ok":           True,
            "files_scanned": len(files),
            "matches":      matches_found,
            "match_count":  len(matches_found),
        }

    except ImportError:
        return {"ok": False, "error": "yara-python no instalado"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── MITRE ATT&CK mapper ───────────────────────────────────────────────────────

MITRE_SCHEMA = {
    "type": "object",
    "properties": {
        "incident_id": {"type": "string"},
        "attack_summary": {"type": "string"},
        "techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id":   {"type": "string"},
                    "sub_technique":  {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {
                        "type": "string",
                        "enum": [
                            "Initial Access", "Execution", "Persistence",
                            "Privilege Escalation", "Defense Evasion",
                            "Credential Access", "Discovery", "Lateral Movement",
                            "Collection", "Command and Control", "Exfiltration", "Impact",
                        ],
                    },
                    "evidence":    {"type": "string"},
                    "confidence":  {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["technique_id", "technique_name", "tactic", "evidence", "confidence"],
            }
        },
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["techniques", "recommended_actions"],
}


def map_to_mitre(findings_text: str, incident_id: str = "IR-UNKNOWN") -> dict:
    """
    Mapea hallazgos de triage (texto libre) a técnicas MITRE ATT&CK.
    Usa structured output JSON — el resultado es importable a ATT&CK Navigator.
    Output: JSON con técnicas, tácticas, evidencia y acciones recomendadas.

    Args:
        findings_text: Notas de triage en texto libre (como las escribe un analista).
        incident_id:   Identificador del incidente (ej: "IR-2024-0622").
    """
    audit("map_to_mitre", {"incident_id": incident_id, "text_len": len(findings_text)})

    result_text = chat_completion(
        messages=[
            {"role": "system", "content": (
                "You are a senior DFIR analyst and MITRE ATT&CK expert. "
                "Map each forensic finding to the most specific ATT&CK technique/sub-technique. "
                "Use exact technique IDs (e.g., T1059.001 for PowerShell). "
                "Reply ONLY with valid JSON matching the schema provided."
            )},
            {"role": "user", "content": (
                f"Incident ID: {incident_id}\n\n"
                f"Forensic findings:\n{findings_text}\n\n"
                f"Required JSON schema:\n{json.dumps(MITRE_SCHEMA, indent=2)}"
            )},
        ],
        response_json=True,
        temperature=0.1,
    )

    try:
        result = json.loads(result_text)
        result["incident_id"] = incident_id

        # Generar Navigator layer
        layer = {
            "name": f"{incident_id} — DFIRLlama-SIFT",
            "versions": {"attack": "14", "navigator": "4.9"},
            "domain": "enterprise-attack",
            "description": f"Auto-generated by DFIRLlama-SIFT | {incident_id}",
            "techniques": [],
        }
        conf_score = {"high": 1.0, "medium": 0.6, "low": 0.3}
        for t in result.get("techniques", []):
            tid = t.get("technique_id", "")
            sub = t.get("sub_technique", "")
            layer["techniques"].append({
                "techniqueID": f"{tid}.{sub}" if sub else tid,
                "tactic": t.get("tactic", "").lower().replace(" ", "-"),
                "score":  conf_score.get(t.get("confidence", "low"), 0.3),
                "comment": t.get("evidence", "")[:200],
                "enabled": True,
            })

        result["navigator_layer"] = layer
        result["technique_count"] = len(result.get("techniques", []))
        return {"ok": True, **result}

    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"JSON parse error: {e}", "raw": result_text[:500]}
