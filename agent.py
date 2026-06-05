#!/usr/bin/env python3
"""
DFIRLlama-SIFT — Evidence Interrogation Loop Agent
====================================================
Orquestador autónomo que corre el EIL de 6 fases usando un loop ReAct.
Funciona sin Claude Code — usa cualquier backend LLM configurado.

Uso:
    python3 agent.py /cases/IR-2024-0622
    python3 agent.py /cases/IR-2024-0622 --model mistral:7b
    python3 agent.py demo/data --demo          # modo demo con tslsm_demo.db
    python3 agent.py /cases/IR-2024-0622 --phase interrogate  # solo una fase

Variables de entorno:
    LLM_BACKEND    claude-cli | claude-api | ollama (default: auto)
    OLLAMA_MODEL   modelo a usar con Ollama (default: mistral:7b)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from llm.client import chat_completion, get_model_name, _get_backend
from guardrails import audit

# ── Colores ───────────────────────────────────────────────────────────────────
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
MAGENTA= "\033[95m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def banner(phase: str, color: str = CYAN):
    print(f"\n{color}{BOLD}{'━'*65}{RESET}")
    print(f"{color}{BOLD}  {phase}{RESET}")
    print(f"{color}{BOLD}{'━'*65}{RESET}")

def log(msg: str, color: str = GREEN):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {color}{msg}{RESET}")

def finding(msg: str):
    print(f"\n{RED}{BOLD}  ★ HALLAZGO: {msg}{RESET}\n")

def thought(msg: str):
    print(f"{MAGENTA}{DIM}  Thought: {msg}{RESET}")

def action(tool: str, args: str = ""):
    print(f"{CYAN}  → {BOLD}{tool}{RESET}{CYAN}({args[:80]}){RESET}")

def observation(result: str):
    preview = str(result)[:200].replace('\n', ' ')
    print(f"{DIM}    Obs: {preview}...{RESET}" if len(str(result)) > 200
          else f"{DIM}    Obs: {result}{RESET}")


# ── Herramientas disponibles para el agente ───────────────────────────────────

def _load_tools(case_dir: str) -> dict:
    """
    Retorna el mapa de herramientas disponibles para el agente.
    Cada tool es una función Python que retorna dict JSON-serializable.
    """
    from tools.evtx_tools  import evtx_to_sqlite, query_evtx_nl
    from tools.nlsql       import query_nl
    from tools.sift_tools  import volatility_run, yara_scan, map_to_mitre
    from tools.ioc_tools   import analyze_ioc, extract_iocs
    from tools.validator   import validate_findings
    from tools.forensic_tools import file_hash, strings_extract
    from tools.zimmerman_tools import (
        amcache_parse, prefetch_parse, shimcache_parse, registry_query
    )

    return {
        "evtx_to_sqlite":    evtx_to_sqlite,
        "query_forensic_db": query_nl,
        "query_evtx_nl":     query_evtx_nl,
        "file_hash":         file_hash,
        "volatility_run":    volatility_run,
        "yara_scan":         yara_scan,
        "analyze_ioc":       analyze_ioc,
        "extract_iocs":      extract_iocs,
        "map_to_mitre":      map_to_mitre,
        "validate_findings": validate_findings,
        "strings_extract":   strings_extract,
        "amcache_parse":     amcache_parse,
        "prefetch_parse":    prefetch_parse,
        "shimcache_parse":   shimcache_parse,
        "registry_query":    registry_query,
    }


TOOL_DOCS = """
HERRAMIENTAS DISPONIBLES:
  evtx_to_sqlite(evtx_path)                        → parsea .evtx a SQLite, retorna db_path
  query_forensic_db(db_path, question)              → NL→SQL sobre EVTX, retorna filas exactas
  file_hash(file_path)                              → MD5/SHA1/SHA256/ssdeep del archivo
  volatility_run(image_path, plugin)                → corre plugin Volatility3
  analyze_ioc(ioc_value)                            → ReAct agent investiga IP/dominio/hash
  extract_iocs(text)                                → extrae IOCs de texto libre como JSON
  map_to_mitre(findings_text, incident_id)          → mapea hallazgos a ATT&CK Navigator
  validate_findings(findings, evidence_db)          → valida hallazgos, retorna hallucination_score
  amcache_parse(hive_path)                          → historial ejecución de programas
  prefetch_parse(path)                              → timestamps ejecución de ejecutables
  shimcache_parse(system_hive)                      → interacción con OS (contexto Amcache)
  registry_query(hive_path, key_path)               → consulta colmenas registro Windows
  strings_extract(file_path)                        → strings clasificados de binarios
"""


# ── EIL — 6 fases ────────────────────────────────────────────────────────────

class EILAgent:
    """
    Evidence Interrogation Loop — agente ReAct autónomo.
    Ejecuta las 6 fases del EIL usando un loop Thought/Action/Observation.
    """

    def __init__(self, case_dir: str, output_dir: str = "./analysis"):
        self.case_dir    = Path(case_dir).resolve()
        self.output_dir  = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Allow guardrails to access the case directory
        if str(self.case_dir) not in os.environ.get("EVIDENCE_ROOT", "/cases"):
            os.environ["EVIDENCE_ROOT"] = str(self.case_dir)
        self.tools       = _load_tools(str(self.case_dir))
        self.findings    = []        # hallazgos acumulados
        self.evtx_dbs    = {}        # {evtx_name: db_path}
        self.iocs_found  = []        # IOCs para ENRICH
        self.model       = get_model_name()
        self.backend     = _get_backend()

    # ── Loop ReAct central ────────────────────────────────────────────────────

    def react(self, objective: str, context: str = "",
              max_iterations: int = 12) -> str:
        """
        Loop ReAct para una fase específica del EIL.
        Retorna la respuesta final del agente.
        """
        system = f"""Eres un analista DFIR experto ejecutando el Evidence Interrogation Loop.
OBJETIVO DE ESTA FASE: {objective}

{TOOL_DOCS}

CONTEXTO ACTUAL:
{context or "Inicio de fase — sin contexto previo."}

FORMATO ESTRICTO — usa exactamente esto en cada turno:
Thought: <razonamiento sobre qué hacer>
Action: <nombre_exacto_de_herramienta>
Action Input: <JSON con argumentos>

Cuando hayas completado el objetivo:
Final Answer: <resumen estructurado de hallazgos de esta fase>

REGLAS:
- Responde SOLO en el formato Thought/Action/Action Input o Final Answer
- JSON en Action Input debe ser válido
- Si una herramienta falla, razona el error y prueba alternativa
- No inventes resultados — solo reporta lo que las herramientas retornan
- Si no hay más herramientas útiles para el objetivo, escribe Final Answer
"""
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": f"Inicia la fase. Case directory: {self.case_dir}"},
        ]

        iterations = 0
        while iterations < max_iterations:
            iterations += 1
            response = chat_completion(messages, temperature=0.1)
            messages.append({"role": "assistant", "content": response})

            # Mostrar Thought
            if "Thought:" in response:
                t = response.split("Thought:")[-1].split("Action:")[0].strip()
                thought(t[:120])

            # Final Answer — terminar
            if "Final Answer:" in response:
                answer = response.split("Final Answer:")[-1].strip()
                return answer

            # Parsear y ejecutar Action
            tool_name, args = self._parse_action(response)
            if tool_name:
                action(tool_name, json.dumps(args)[:60])
                result = self._call_tool(tool_name, args)
                observation(result)
                audit(f"eil.{tool_name}", args,
                      result_summary=str(result)[:200])
                messages.append({
                    "role":    "user",
                    "content": f"Observation: {json.dumps(result, ensure_ascii=False)[:1500]}\n\nContinúa.",
                })
            else:
                # El modelo no siguió el formato — pedirle que lo corrija
                messages.append({
                    "role":    "user",
                    "content": "No detecté Action válida. Usa el formato:\nThought: ...\nAction: nombre_herramienta\nAction Input: {\"arg\": \"valor\"}",
                })

        return f"[max_iterations={max_iterations} alcanzado]"

    def _parse_action(self, text: str) -> tuple[str, dict]:
        import re
        m_action = re.search(r"Action:\s*(\w+)", text)
        m_input  = re.search(r"Action Input:\s*(\{.*?\})", text, re.DOTALL)
        if not m_action:
            return "", {}
        tool_name = m_action.group(1).strip()
        try:
            args = json.loads(m_input.group(1)) if m_input else {}
        except json.JSONDecodeError:
            args = {}
        return tool_name, args

    def _call_tool(self, tool_name: str, args: dict):
        fn = self.tools.get(tool_name)
        if not fn:
            return {"error": f"Herramienta '{tool_name}' no encontrada",
                    "available": list(self.tools.keys())}
        try:
            return fn(**args)
        except Exception as e:
            return {"error": str(e), "tool": tool_name}

    # ── Fase 1: INVENTORY ─────────────────────────────────────────────────────

    def phase_inventory(self) -> dict:
        banner("FASE 1 — INVENTORY", CYAN)
        log("Mapeando evidencia disponible...")

        manifest = {"case_dir": str(self.case_dir), "artifacts": []}
        extensions = {
            ".evtx": "Windows Event Log",
            ".raw": "Memory Image", ".vmem": "Memory Image",
            ".lime": "Memory Image", ".mem": "Memory Image",
            ".hve": "Registry Hive",
            ".pf":  "Prefetch File",
            ".lnk": "LNK Shortcut",
            ".db":  "SQLite Database",
            ".pcap": "Network Capture", ".pcapng": "Network Capture",
            ".E01": "Disk Image", ".dd": "Disk Image",
        }

        for f in sorted(self.case_dir.rglob("*")):
            if not f.is_file():
                continue
            ext  = f.suffix.lower()
            kind = extensions.get(ext, "Other")
            size = f.stat().st_size

            entry = {
                "path": str(f),
                "name": f.name,
                "type": kind,
                "size_mb": round(size / 1_048_576, 2),
                "extension": ext,
            }

            # Hash de artefactos pequeños (< 500 MB)
            if size < 500 * 1_048_576 and ext in extensions:
                log(f"Hasheando {f.name}...", DIM)
                h = self._call_tool("file_hash", {"file_path": str(f)})
                entry["sha256"] = h.get("sha256", "error")
                entry["file_type"] = h.get("file_type", "unknown")
                action("file_hash", f.name)
                observation(f"SHA256: {entry['sha256'][:16]}...")

            manifest["artifacts"].append(entry)

            # Registrar EVTX para fases siguientes
            if ext == ".evtx":
                self.evtx_dbs[f.stem] = None  # db_path se llena en ORIENT

        manifest["total_artifacts"] = len(manifest["artifacts"])
        manifest["evtx_count"]  = sum(1 for a in manifest["artifacts"] if a["extension"] == ".evtx")
        manifest["memory_count"] = sum(1 for a in manifest["artifacts"] if a["type"] == "Memory Image")

        # Guardar
        out = self.output_dir / "evidence_manifest.json"
        out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
        log(f"Inventario: {manifest['total_artifacts']} artefactos → {out}")

        return manifest

    # ── Fase 2: ORIENT ────────────────────────────────────────────────────────

    def phase_orient(self, manifest: dict) -> dict:
        banner("FASE 2 — ORIENT", CYAN)
        log("Construyendo eje temporal...")

        orient_results = {}

        for art in manifest["artifacts"]:
            path = art["path"]
            ext  = art["extension"]

            if ext == ".evtx":
                log(f"Parseando {art['name']} → SQLite...")
                action("evtx_to_sqlite", art["name"])
                result = self._call_tool("evtx_to_sqlite",
                                         {"evtx_path": path})
                observation(result)
                if result.get("ok"):
                    db_path = result["db_path"]
                    stem    = Path(path).stem
                    self.evtx_dbs[stem] = db_path
                    orient_results[stem] = {
                        "db_path":      db_path,
                        "total_events": result.get("total_events"),
                        "time_range":   result.get("time_range"),
                        "top_event_ids": result.get("top_event_ids", []),
                    }
                    log(f"  {result.get('total_events',0):,} eventos | {result.get('time_range','?')}", GREEN)

            elif art["type"] == "Memory Image":
                log(f"Analizando memoria: {art['name']}...")
                for plugin in ["windows.pslist", "windows.netscan"]:
                    action("volatility_run", f"{art['name']} | {plugin}")
                    r = self._call_tool("volatility_run",
                                        {"image_path": path, "plugin": plugin})
                    orient_results[f"{Path(path).stem}_{plugin}"] = {
                        "output": str(r.get("output",""))[:500],
                        "lines":  r.get("line_count", 0),
                    }
                    observation(f"{r.get('line_count',0)} líneas de output")

        # Register pre-existing SQLite databases (demo mode / pre-parsed EVTX)
        import sqlite3
        for f in sorted(Path(self.case_dir).iterdir()):
            if f.suffix == ".db" and f.is_file() and f.stem not in orient_results:
                try:
                    with sqlite3.connect(str(f)) as con:
                        tables = [r[0] for r in con.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                        count = con.execute(
                            f"SELECT COUNT(*) FROM {tables[0]}").fetchone()[0] if tables else 0
                    orient_results[f.stem] = {
                        "db_path":       str(f),
                        "total_events":  count,
                        "time_range":    "pre-parsed SQLite database",
                        "top_event_ids": [],
                    }
                    self.evtx_dbs[f.stem] = str(f)
                    log(f"Pre-parsed DB found: {f.name} ({count:,} events)", GREEN)
                except Exception:
                    pass

        out = self.output_dir / "orient_results.json"
        out.write_text(json.dumps(orient_results, indent=2, ensure_ascii=False))
        log(f"Orientación completa → {out}")
        return orient_results

    # ── Fase 3: INTERROGATE ───────────────────────────────────────────────────

    def phase_interrogate(self, orient: dict) -> list[dict]:
        banner("FASE 3 — INTERROGATE", YELLOW)
        log("Interrogando evidencia con NL→SQL...")

        findings = []

        for evtx_name, info in orient.items():
            if "db_path" not in info:
                continue
            db = info["db_path"]
            log(f"Analizando {evtx_name} ({info.get('total_events',0):,} eventos)...")

            triage_questions = [
                ("logons_externos",
                 "Are there any logons or RDP connections from external IPs (not 10.x.x.x)?"),
                ("logon_fallidos",
                 "Were there any failed logon attempts? How many and from which IPs?"),
                ("log_clearing",
                 "Were there any log clearing events (EventId 1102 or EventId 104)?"),
                ("admin_multiples_ips",
                 "Did the administrator account connect from more than one different IP on the same day?"),
                ("powershell_sospechoso",
                 "Were there any PowerShell executions with -ExecutionPolicy Bypass or encoded commands?"),
                ("scheduled_tasks",
                 "Were there any new scheduled tasks created (EventId 4698)?"),
                ("nuevos_servicios",
                 "Were any new services installed (EventId 7045)?"),
                ("nuevas_cuentas",
                 "Were any new user accounts created (EventId 4720)?"),
            ]

            for q_id, question in triage_questions:
                action("query_forensic_db", question[:50])
                result = self._call_tool("query_forensic_db",
                                         {"db_path": db, "question": question})
                observation(result)

                if result.get("ok") and result.get("row_count", 0) > 0:
                    rows = result.get("results", [])
                    f = {
                        "phase":            "interrogate",
                        "query_id":         q_id,
                        "description":      question,
                        "sql":              result.get("sql", ""),
                        "row_count":        result.get("row_count", 0),
                        "evidence_sample":  rows[:5],
                        "evtx_source":      evtx_name,
                        "db_path":          db,
                        "confidence":       "high",
                        "ioc_type":         None,
                        "ioc_value":        None,
                    }

                    # Extraer IOCs para ENRICH
                    for row in rows[:10]:
                        for col, val in row.items():
                            if isinstance(val, str):
                                if _looks_like_ip(val) and not val.startswith("10."):
                                    self.iocs_found.append(
                                        {"type": "ip", "value": val, "source": q_id}
                                    )
                                    f["ioc_type"]  = "ip"
                                    f["ioc_value"] = val

                    findings.append(f)
                    finding(f"[{q_id}] {result['row_count']} resultados")

        # Persist findings before the deep-dive so they survive a ReAct timeout
        self.findings.extend(findings)
        out = self.output_dir / "interrogate_findings.json"
        out.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        log(f"{len(findings)} hallazgos → {out}")

        # ReAct deep dive (skip if no findings to avoid empty loops)
        if findings and self.evtx_dbs:
            db_path = next(iter(self.evtx_dbs.values()))
            context = f"EVTX DB: {db_path}\nHallazgos iniciales: {len(findings)}\n"
            context += "IPs sospechosas encontradas: " + str(
                [i["value"] for i in self.iocs_found[:5]]
            )
            log("Profundizando con ReAct (max 3 iteraciones)...")
            deep_result = self.react(
                objective="Profundizar en los hallazgos del triage. "
                          "Para cada IP externa encontrada, determinar cuántas "
                          "veces se conectó y qué usuarios usó. "
                          "Buscar evidencia de timestomping o actividad nocturna.",
                context=context,
                max_iterations=3,
            )
            if deep_result and "max_iterations" not in deep_result:
                deep_f = {
                    "phase":       "interrogate_deep",
                    "description": "Análisis profundo ReAct",
                    "verdict":     deep_result,
                    "confidence":  "medium",
                }
                findings.append(deep_f)
                self.findings.append(deep_f)
                out.write_text(json.dumps(findings, indent=2, ensure_ascii=False))

        return findings

    # ── Fase 4: ENRICH ───────────────────────────────────────────────────────

    def phase_enrich(self) -> list[dict]:
        banner("FASE 4 — ENRICH", YELLOW)

        enrich_results = []
        seen = set()

        for ioc in self.iocs_found:
            val = ioc["value"]
            if val in seen:
                continue
            seen.add(val)

            log(f"Investigando IOC: {val} ({ioc['type']})")
            action("analyze_ioc", val)
            result = self._call_tool("analyze_ioc",
                                     {"ioc_value": val, "ioc_type": ioc["type"]})
            observation(result)

            enrich_results.append({
                "ioc":    val,
                "type":   ioc["type"],
                "source": ioc["source"],
                "verdict": result.get("verdict", "")[:500],
                "tool_calls": len(result.get("tool_calls", [])),
            })

            if result.get("ok"):
                self.findings.append({
                    "phase":       "enrich",
                    "description": f"IOC investigation: {val}",
                    "ioc_type":    ioc["type"],
                    "ioc_value":   val,
                    "verdict":     result.get("verdict", ""),
                    "confidence":  "high",
                })

        out = self.output_dir / "enrich_results.json"
        out.write_text(json.dumps(enrich_results, indent=2, ensure_ascii=False))
        log(f"{len(enrich_results)} IOCs enriquecidos → {out}")
        return enrich_results

    # ── Fase 5: VALIDATE ─────────────────────────────────────────────────────

    def phase_validate(self) -> dict:
        banner("FASE 5 — VALIDATE", MAGENTA)
        log(f"Validando {len(self.findings)} hallazgos...")

        if not self.findings:
            log("Sin hallazgos para validar.", YELLOW)
            return {"ok": True, "hallucination_score": 0, "total_findings": 0}

        evidence_db = next(iter(self.evtx_dbs.values())) if self.evtx_dbs else None

        action("validate_findings",
               f"{len(self.findings)} findings, db={Path(evidence_db).name if evidence_db else 'none'}")
        result = self._call_tool("validate_findings", {
            "findings":    self.findings,
            "evidence_db": evidence_db or "",
        })
        observation(result)

        score = result.get("hallucination_score", 0)
        color = GREEN if score < 0.10 else YELLOW if score < 0.25 else RED
        log(f"Hallucination score: {color}{score:.1%}{RESET} | {result.get('verdict','')}", "")

        # Auto-corrección
        triggers = result.get("self_correction_triggers", [])
        if triggers and evidence_db:
            log(f"{len(triggers)} triggers de auto-corrección — re-investigando...", YELLOW)
            for t in triggers[:3]:
                log(f"  Corrigiendo: {t['finding'][:60]}...", YELLOW)
                action("query_forensic_db", t.get("suggestion","")[:50])
                correction = self._call_tool("query_forensic_db", {
                    "db_path":  evidence_db,
                    "question": t.get("suggestion",
                                      f"Verify: {t['finding'][:100]}"),
                })
                observation(correction)
                if correction.get("ok"):
                    self.findings.append({
                        "phase":       "validate_correction",
                        "description": f"Corrección: {t['finding'][:80]}",
                        "evidence":    correction.get("results", [])[:3],
                        "confidence":  "high",
                    })

        out = self.output_dir / "validation_results.json"
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False))
        log(f"Validación completa → {out}")
        return result

    # ── Fase 6: REPORT ───────────────────────────────────────────────────────

    def phase_report(self, incident_id: str = "IR-UNKNOWN") -> dict:
        banner("FASE 6 — REPORT", GREEN)
        log("Generando reporte final...")

        # Narrativa para el mapper
        findings_text = "\n".join(
            f"- {f.get('description','')}: {str(f.get('evidence_sample', f.get('verdict','')))[:200]}"
            for f in self.findings
            if f.get("phase") not in ("validate_correction",)
        )

        action("map_to_mitre", incident_id)
        mitre_result = self._call_tool("map_to_mitre", {
            "findings_text": findings_text[:3000],
            "incident_id":   incident_id,
        })
        observation(mitre_result)

        technique_count = mitre_result.get("technique_count", 0)
        log(f"{technique_count} técnicas ATT&CK identificadas", GREEN)

        # Reporte estructurado
        report = {
            "incident_id":        incident_id,
            "case_dir":           str(self.case_dir),
            "timestamp_utc":      datetime.now(timezone.utc).isoformat(),
            "model":              self.model,
            "backend":            self.backend,
            "total_findings":     len(self.findings),
            "iocs_investigated":  len(self.iocs_found),
            "mitre_techniques":   mitre_result.get("techniques", []),
            "technique_count":    technique_count,
            "navigator_layer":    mitre_result.get("navigator_layer", {}),
            "findings":           self.findings,
            "recommended_actions": mitre_result.get("recommended_actions", []),
        }

        # Guardar JSON
        report_json = self.output_dir / f"{incident_id}_findings.json"
        report_json.write_text(json.dumps(report, indent=2, ensure_ascii=False))

        # Navigator layer
        if report["navigator_layer"]:
            nav_path = self.output_dir / f"{incident_id}_navigator.json"
            nav_path.write_text(
                json.dumps(report["navigator_layer"], indent=2, ensure_ascii=False)
            )
            log(f"Navigator layer → {nav_path}", GREEN)

        # Resumen ejecutivo Markdown
        summary = _build_summary(report)
        summary_path = self.output_dir / f"{incident_id}_executive_summary.md"
        summary_path.write_text(summary)

        log(f"Reporte JSON      → {report_json}", GREEN)
        log(f"Resumen ejecutivo → {summary_path}", GREEN)

        return report

    # ── Runner principal ──────────────────────────────────────────────────────

    def run(self, incident_id: str = "IR-UNKNOWN",
            start_phase: str = "inventory") -> dict:

        phases = ["inventory", "orient", "interrogate", "enrich", "validate", "report"]
        start  = phases.index(start_phase) if start_phase in phases else 0

        t0 = time.time()
        print(f"\n{CYAN}{BOLD}DFIRLlama-SIFT — Evidence Interrogation Loop{RESET}")
        print(f"{CYAN}Case: {self.case_dir}{RESET}")
        print(f"{CYAN}Model: {self.model} [{self.backend}]{RESET}")
        print(f"{CYAN}Incident ID: {incident_id}{RESET}\n")

        manifest = orient = None

        if start <= 0:
            manifest = self.phase_inventory()
        if start <= 1:
            manifest = manifest or {}
            orient   = self.phase_orient(manifest)
        if start <= 2:
            orient = orient or {}
            self.phase_interrogate(orient)
        if start <= 3:
            self.phase_enrich()
        if start <= 4:
            self.phase_validate()

        report = {}
        if start <= 5:
            report = self.phase_report(incident_id)

        elapsed = time.time() - t0
        banner("INVESTIGACIÓN COMPLETA", GREEN)
        log(f"Tiempo total: {elapsed/60:.1f} minutos", GREEN)
        log(f"Hallazgos: {len(self.findings)}", GREEN)
        log(f"Técnicas ATT&CK: {report.get('technique_count',0)}", GREEN)
        log(f"Outputs en: {self.output_dir}/", GREEN)

        # Guardar audit log de la sesión
        session_log = {
            "incident_id": incident_id,
            "case_dir":    str(self.case_dir),
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "total_findings": len(self.findings),
            "model": self.model,
        }
        (self.output_dir / "eil_session.json").write_text(
            json.dumps(session_log, indent=2)
        )

        return report


# ── Helpers ───────────────────────────────────────────────────────────────────

def _looks_like_ip(s: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(s)))


def _build_summary(report: dict) -> str:
    lines = [
        f"# IR Report — {report['incident_id']}",
        f"**Date (UTC):** {report['timestamp_utc']}",
        f"**Case:** `{report['case_dir']}`",
        f"**Model:** {report['model']} [{report['backend']}]",
        "",
        "## Executive Summary",
        f"- Total findings: {report['total_findings']}",
        f"- IOCs investigated: {report['iocs_investigated']}",
        f"- MITRE ATT&CK techniques identified: {report['technique_count']}",
        "",
        "## MITRE ATT&CK Techniques",
    ]
    for t in report.get("mitre_techniques", []):
        tid  = t.get("technique_id","")
        name = t.get("technique_name","")
        tac  = t.get("tactic","")
        conf = t.get("confidence","")
        ev   = t.get("evidence","")[:100]
        lines.append(f"- **{tid}** {name} ({tac}) [{conf}] — {ev}")

    lines += ["", "## Recommended Actions"]
    for a in report.get("recommended_actions", []):
        lines.append(f"- {a}")

    lines += ["", "## Key Findings"]
    for f in report.get("findings", [])[:15]:
        desc = f.get("description","")[:100]
        conf = f.get("confidence","")
        lines.append(f"- [{conf}] {desc}")

    lines += [
        "",
        "---",
        "*Generated by DFIRLlama-SIFT — SANS FIND EVIL! Hackathon 2026*",
        "*All evidence processed locally. No raw evidence sent to external services.*",
    ]
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="DFIRLlama-SIFT — Evidence Interrogation Loop Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 agent.py /cases/IR-2024-0622
  python3 agent.py /cases/IR-2024-0622 --id IR-2024-0622
  python3 agent.py demo/data --demo
  python3 agent.py /cases/IR-2024-0622 --phase interrogate
        """,
    )
    p.add_argument("case_dir",        help="Directorio del caso con artefactos forenses")
    p.add_argument("--id",            default=None,    help="Incident ID (ej: IR-2024-0622)")
    p.add_argument("--output",        default="./analysis", help="Directorio de output")
    p.add_argument("--phase",         default="inventory",
                   choices=["inventory","orient","interrogate","enrich","validate","report"],
                   help="Fase desde donde empezar")
    p.add_argument("--demo",          action="store_true",
                   help="Modo demo — usa tslsm_demo.db directamente")
    args = p.parse_args()

    case_dir = args.case_dir

    # Modo demo: apuntar al directorio con tslsm_demo.db
    if args.demo:
        demo_db = Path(__file__).parent / "demo" / "data" / "tslsm_demo.db"
        if not demo_db.exists():
            print(f"{RED}[!] Demo DB no encontrada: {demo_db}{RESET}")
            sys.exit(1)
        case_dir = str(demo_db.parent)
        print(f"{CYAN}[DEMO] Usando dataset demo RDP compromise: {demo_db}{RESET}")

    if not Path(case_dir).exists():
        print(f"{RED}[!] Directorio no encontrado: {case_dir}{RESET}")
        sys.exit(1)

    incident_id = args.id or f"IR-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"

    agent = EILAgent(case_dir=case_dir, output_dir=args.output)
    agent.run(incident_id=incident_id, start_phase=args.phase)


if __name__ == "__main__":
    main()
