# DFIRLlama — Evidence Interrogation Loop (EIL)
## SKILL para Claude Code | DFIRLlama-SIFT

---

## Cuándo usar este skill

Cuando el objetivo es investigar artefactos de Windows — EVTX, registro, prefetch, amcache,
memoria — para encontrar evidencia de compromiso, persistencia, lateral movement, o exfiltración.

**Principio central**: No le des datos al LLM. Dale la capacidad de hacer preguntas precisas
sobre los datos. Cada tool call retorna JSON exacto — nunca texto crudo de 10,000 líneas.

---

## Las 6 Fases del EIL

### FASE 1 — INVENTORY
**Objetivo**: Saber exactamente qué evidencia tienes antes de tocar nada.

```
Para cada artefacto en el case directory:
  - Identificar tipo (EVTX, imagen disco, volcado memoria, hive registro)
  - Registrar tamaño, rango temporal si aplica
  - Calcular hash SHA256 → guardar en ./analysis/evidence_manifest.json
```

Usa: `file_hash_tool` para cada artefacto, `ls` para listar, `file` para identificar tipo.

**Output esperado**: `./analysis/evidence_manifest.json` con inventario completo.

### FASE 2 — ORIENT
**Objetivo**: Construir el eje temporal — ¿cuándo pasaron las cosas?

Para EVTX:
1. `evtx_to_sqlite_tool` sobre cada .evtx → obtener db_path
2. `query_evtx_nl_tool(db, "¿cuál es el rango temporal de los eventos?", train_first=True)`
3. Identificar picos de actividad inusual

Para memoria (si existe):
- `volatility_run_tool(image, "windows.pslist")`
- `volatility_run_tool(image, "windows.netscan")`

Para disco (si existe):
- `@~/.claude/skills/plaso-timeline/SKILL.md` para supertimeline

**Output esperado**: Timeline aproximada con ventanas de interés anotadas.

### FASE 3 — INTERROGATE
**Objetivo**: Hacer preguntas forenses específicas sobre cada fuente de evidencia.

#### Para EVTX (SIEMPRE usar NL→SQL, nunca leer CSV crudo):

Preguntas estándar de triage — hacer TODAS antes de proceder:
```
query_evtx_nl_tool(db, "¿hubo logons fallidos masivos? ¿desde qué IPs?")
query_evtx_nl_tool(db, "¿hubo logons exitosos desde IPs externas?")
query_evtx_nl_tool(db, "¿se ejecutó PowerShell con -ExecutionPolicy Bypass?")
query_evtx_nl_tool(db, "¿hubo limpieza de logs (EventId 1102)?")
query_evtx_nl_tool(db, "¿se crearon scheduled tasks nuevas?")
query_evtx_nl_tool(db, "¿hay servicios instalados recientemente?")
query_evtx_nl_tool(db, "¿hubo creación de cuentas de usuario nuevas?")
```

Si encuentras algo sospechoso → profundizar:
```
query_evtx_nl_tool(db, "¿qué hizo el usuario [X] durante la ventana [T1]-[T2]?")
query_evtx_nl_tool(db, "¿el mismo usuario se conectó desde más de una IP el mismo día?")
```

#### Para artefactos Windows:
```
amcache_parse_tool(hive)       → ¿qué ejecutables nuevos aparecieron?
prefetch_parse_tool(dir)       → ¿cuándo corrió [sospechoso].exe?
shimcache_parse_tool(system)   → ¿qué binarios interactuaron con el OS?
registry_query_tool(ntuser, "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
mft_timeline_tool(mft)         → ¿hay timestomping? ¿archivos en /Temp con timestamps recientes?
```

#### Para memoria:
```
volatility_run_tool(image, "windows.malfind")
volatility_run_tool(image, "windows.cmdline")
volatility_run_tool(image, "windows.netscan")
```

### FASE 4 — ENRICH
**Objetivo**: Investigar cada IOC encontrado en FASE 3.

Para cada IP sospechosa, dominio, hash o PowerShell encontrado:
```
analyze_ioc_tool(ioc_value)
```

El agente ReAct interno decide qué herramientas usar.
Registrar veredicto: malicious / suspicious / benign / unknown.

### FASE 5 — VALIDATE
**Objetivo**: Verificar hallazgos contra evidencia real. Detectar alucinaciones.

```
validate_findings_tool(
    findings=[lista de hallazgos acumulados],
    evidence_db="/tmp/dfirllama_Security.db",  # la DB de EVTX
    source_text=""  # si tienes reportes de texto
)
```

**Regla de self-correction**: Si `needs_correction: true`:
- Leer cada `self_correction_trigger`
- Para cada uno: volver a INTERROGATE con la pregunta específica que resuelve la contradicción
- Registrar en `./analysis/self_corrections.json`: qué encontré, cuál era el error, qué encontré al re-investigar

**Stagnation rule**: Si llevas más de 3 rondas de VALIDATE → INTERROGATE sin nuevos hallazgos confirmados:
- Cambiar a un artefacto diferente (ej: si estabas en EVTX, pasa a memoria o prefetch)
- Anotar "stagnation detected" en el audit log

### FASE 6 — REPORT
**Objetivo**: Output estructurado con hallazgos verificados.

```
map_to_mitre_tool(
    findings_text=resumen_narrativo,
    incident_id="IR-YYYY-MMDD"
)
```

Escribir a `./reports/IR-[ID]_findings.json`:
```json
{
  "incident_id": "...",
  "investigation_summary": "...",
  "confirmed_findings": [...],
  "iocs": [...],
  "mitre_techniques": [...],
  "navigator_layer": {...},
  "hallucination_score": 0.XX,
  "self_corrections": [...],
  "evidence_citations": [...]
}
```

Escribir a `./reports/IR-[ID]_executive_summary.md`: narrativa en español para el cliente.

---

## Reglas de auto-corrección (self-correction protocol)

**Cuando una tool falla:**
1. Leer el error completo
2. Identificar causa: ¿columna incorrecta? ¿archivo no encontrado? ¿formato incorrecto?
3. Formular hipótesis de corrección
4. Reintentar con enfoque diferente
5. Si falla 3 veces: documentar como "gap en evidencia" y continuar

**Cuando validate_findings retorna contradicted:**
1. Identificar qué hallazgo está en contradicción
2. Volver a INTERROGATE con query más específica que resuelva la contradicción
3. Actualizar el hallazgo con el resultado correcto
4. Registrar la corrección en self_corrections.json

**Ejemplo real de self-correction:**
```
FASE 3: query_evtx_nl → "CommandLine column not found"
CORRECCIÓN: La tabla TSLSM no tiene CommandLine. Usar Security.evtx con EID 4688.
ACCIÓN: evtx_to_sqlite_tool("Security.evtx") → nueva DB → reintentar query
```

---

## Qué NO hacer

- NO pasar CSV de 10,000+ líneas al LLM directamente — usar query_evtx_nl_tool
- NO asumir que ShimCache prueba ejecución — solo prueba interacción con OS
- NO reportar hallazgos sin evidence_citation verificable
- NO continuar si hallucination_score > 0.30 sin re-investigar
- NO modificar ningún archivo en /cases/, /mnt/, /media/, o evidence/

---

## Output del audit trail

Cada fase se registra automáticamente en `./analysis/forensic_audit.log`.
El MCP server registra cada tool call en `/tmp/dfirllama_audit.log` (JSONL).
Al finalizar: `./analysis/self_corrections.json` con historial de correcciones.
