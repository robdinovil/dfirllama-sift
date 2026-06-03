# DFIRLlama-SIFT — Manual de Usuario
## Instalación, Configuración y Uso

**Versión:** 1.0 — SANS FIND EVIL! Hackathon 2026  
**Tiempo estimado de instalación:** 15–20 minutos  
**Nivel requerido:** Analista DFIR con Python básico

---

## Índice

1. [Requisitos](#1-requisitos)
2. [Instalación en 5 pasos](#2-instalación-en-5-pasos)
3. [Modo 1 — Claude Code + MCP](#3-modo-1--claude-code--mcp-recomendado)
4. [Modo 2 — Agente standalone (Ollama / air-gap)](#4-modo-2--agente-standalone-ollama--air-gap)
5. [Modo 3 — Web UI](#5-modo-3--web-ui)
6. [Qué evidencias puedo analizar](#6-qué-evidencias-puedo-analizar)
7. [Ejemplos de uso real](#7-ejemplos-de-uso-real)
8. [Cómo leer los outputs](#8-cómo-leer-los-outputs)
9. [Solución de problemas](#9-solución-de-problemas)
10. [Referencia rápida de herramientas](#10-referencia-rápida-de-herramientas)

---

## 1. Requisitos

### Hardware mínimo
| Componente | Mínimo | Recomendado |
|-----------|--------|-------------|
| RAM | 8 GB | 16 GB+ |
| Disco libre | 2 GB | 10 GB+ |
| CPU | Cualquier x86-64 | 4+ cores |
| GPU | No requerida | Opcional (acelera Ollama) |

### Software requerido
| Software | Versión mínima | Cómo verificar |
|---------|----------------|----------------|
| SANS SIFT Workstation | Ubuntu 20.04+ | `lsb_release -a` |
| Python | 3.10+ | `python3 --version` |
| Claude Code CLI | Cualquiera | `claude --version` |
| pip | 21+ | `pip3 --version` |

### Software opcional (para modo air-gap)
| Software | Para qué | Instalación |
|---------|----------|-------------|
| Ollama | LLM local sin internet | `curl -fsSL https://ollama.ai/install.sh \| sh` |
| mistral:7b | Modelo recomendado | `ollama pull mistral:7b` |

### Verificar que Claude Code está autenticado
```bash
claude --version
# Debe mostrar versión sin error
# Si falla: claude auth login
```

---

## 2. Instalación en 5 pasos

### Paso 1 — Clonar el repositorio

```bash
cd ~
git clone https://github.com/[tu-usuario]/dfirllama-sift
cd dfirllama-sift
```

### Paso 2 — Instalar dependencias Python

```bash
pip3 install -r requirements.txt
```

Esto instala: `fastmcp`, `vanna[chromadb]`, `pandas`, `anthropic`, `openai`, `flask`, `yara-python`, `python-whois`, `requests`

**Si alguna instalación falla:**
```bash
# Intentar una por una
pip3 install fastmcp
pip3 install "vanna[chromadb]"
pip3 install pandas flask anthropic openai requests python-whois yara-python
```

### Paso 3 — Configurar el entorno

```bash
cp .env.example .env
```

Editar `.env` con tu editor preferido:
```bash
nano .env
```

Contenido del `.env`:
```bash
# Elige tu modo LLM:

# Opción A — Claude Code (hackathon, requiere internet)
LLM_BACKEND=claude

# Opción B — Ollama local (air-gap, 100% sin internet)
# LLM_BACKEND=ollama
# OLLAMA_MODEL=mistral:7b

# Directorio donde están tus casos forenses
EVIDENCE_ROOT=/cases

# Dónde guardar el audit trail
AUDIT_LOG=/tmp/dfirllama_audit.log
```

### Paso 4 — Registrar el servidor MCP con Claude Code

Abrir el archivo de configuración de Claude Code:
```bash
nano ~/.claude/settings.json
```

Agregar la sección `mcpServers` (si ya existe el archivo, agregar dentro del JSON):
```json
{
  "mcpServers": {
    "dfirllama-sift": {
      "command": "python3",
      "args": ["/home/TU_USUARIO/dfirllama-sift/server.py"],
      "env": {
        "LLM_BACKEND": "claude",
        "EVIDENCE_ROOT": "/cases",
        "AUDIT_LOG": "/tmp/dfirllama_audit.log"
      }
    }
  }
}
```

> **Importante:** Reemplaza `/home/TU_USUARIO/` con la ruta real.  
> Para verificarla: `pwd` en el directorio del proyecto.

### Paso 5 — Instalar el skill EIL en Claude Code

```bash
# El directorio skills/dfirllama-eil/ ya viene en el repo
# Solo necesitas copiarlo si no está en ~/.claude/skills/
ls ~/.claude/skills/dfirllama-eil/SKILL.md

# Si no existe:
mkdir -p ~/.claude/skills/dfirllama-eil
cp skills/dfirllama-eil/SKILL.md ~/.claude/skills/dfirllama-eil/
```

### Verificar instalación

```bash
# Verificar que todos los módulos importan correctamente
python3 -c "
import server, agent, webui, guardrails
from tools import nlsql, evtx_tools, ioc_tools, validator
from llm import client
print('✓ Todos los módulos OK')
"

# Correr el benchmark de prueba (no necesita LLM)
python3 benchmark/run_benchmark.py --dry-run
# Debe mostrar: Correctas: 20 (100.0%)

# Verificar que el servidor MCP arranca
python3 server.py --help
```

---

## 3. Modo 1 — Claude Code + MCP (recomendado)

Este es el modo principal. Claude Code actúa como el cerebro, lee el protocolo EIL, y llama a las 22 herramientas del servidor MCP automáticamente.

### Cómo funciona internamente

```
Tu terminal
    │
    ▼ claude
Claude Code
    │  lee → ~/.claude/CLAUDE.md (comportamiento base)
    │  lee → ~/.claude/skills/dfirllama-eil/SKILL.md (protocolo EIL)
    │
    │  JSON-RPC stdio
    ▼
server.py (DFIRLlama-SIFT MCP Server)
    │
    ▼
22 herramientas forenses → EVTX, memoria, registro, red, IOCs...
```

### Uso básico

```bash
# 1. Ir al directorio del caso
cd /cases/IR-2024-0622

# 2. Abrir Claude Code
claude

# 3. Decirle qué quieres en lenguaje natural
```

### Ejemplos de prompts

**Investigación completa autónoma:**
```
Investiga todos los artefactos en este directorio. Busca evidencia
de compromiso, lateral movement, persistencia y exfiltración.
Genera un reporte con las técnicas ATT&CK identificadas.
```

**Análisis específico de EVTX:**
```
Analiza el archivo Security.evtx. Busca logons externos,
creación de cuentas y ejecución de PowerShell sospechoso.
```

**Pregunta forense directa:**
```
En el EVTX de este directorio, ¿el usuario administrator
se conectó desde más de una IP diferente el mismo día?
```

**Investigar una IP específica:**
```
Investiga la IP 102.20.90.8. ¿Es maliciosa?
¿A qué país pertenece? ¿Está en listas de amenazas?
```

**Análisis de memoria:**
```
Corre Volatility sobre el archivo memory.raw.
Muestra procesos, conexiones de red activas,
y busca código inyectado con malfind.
```

### El EIL corre solo — qué verás

Claude Code ejecutará automáticamente las 6 fases del Evidence Interrogation Loop:

```
[EIL Phase 1 — INVENTORY]
  Calculando SHA256 de todos los artefactos...
  → Security.evtx (44,281 eventos)
  → memory.raw (2.1 GB)
  → Amcache.hve

[EIL Phase 2 — ORIENT]
  Parseando Security.evtx → SQLite...
  44,281 eventos | 2024-01-01 → 2024-06-28
  Analizando memoria: windows.pslist, windows.netscan

[EIL Phase 3 — INTERROGATE]
  Q: ¿Hubo logons desde IPs externas?
  SQL: SELECT TimeCreated, UserName, RemoteHost FROM events
       WHERE EventId=21 AND RemoteHost NOT LIKE '10.%'
  → 234 resultados

  ★ HALLAZGO: administrator conectado desde 102.20.90.8 (África)

[EIL Phase 4 — ENRICH]
  Investigando 102.20.90.8...
  → País: Nigeria, AS37282
  → En blocklist IPSum: score 7/10 (MALICIOSO)

[EIL Phase 5 — VALIDATE]
  18 hallazgos validados. Hallucination score: 5.6%
  1 auto-corrección aplicada.

[EIL Phase 6 — REPORT]
  14 técnicas ATT&CK identificadas.
  Navigator layer generado.
  Reporte escrito en ./analysis/

Tiempo total: 12 minutos
```

---

## 4. Modo 2 — Agente standalone (Ollama / air-gap)

Para casos donde la evidencia **no puede salir de la red**. Funciona idéntico al Modo 1 pero con un modelo local.

### Configurar Ollama

```bash
# Instalar Ollama (requiere internet una vez)
curl -fsSL https://ollama.ai/install.sh | sh

# Descargar el modelo (requiere internet una vez)
ollama pull mistral:7b          # 4 GB, bueno para la mayoría de tareas
# o
ollama pull qwen2.5:14b         # 9 GB, mejor calidad si tienes RAM

# Verificar que Ollama corre
ollama list
```

### Configurar para modo air-gap

```bash
# Editar .env
LLM_BACKEND=ollama
OLLAMA_MODEL=mistral:7b
```

Una vez configurado, Ollama no necesita internet. El modelo está en disco.

### Uso

```bash
# Investigación completa
python3 agent.py /cases/IR-2024-0622

# Con incident ID específico
python3 agent.py /cases/IR-2024-0622 --id IR-2024-0622

# Empezar desde una fase específica (si ya tienes EVTX parseado)
python3 agent.py /cases/IR-2024-0622 --phase interrogate

# Solo el reporte final
python3 agent.py /cases/IR-2024-0622 --phase report

# Demo inmediata con el dataset incluido (no necesita evidencia real)
python3 agent.py demo/data --demo
```

### Qué verás en terminal

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FASE 1 — INVENTORY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[07:14:22] Mapeando evidencia disponible...
  → file_hash(Security.evtx)
    Obs: SHA256: a3f8b2c19d4e5f67...
[07:14:23] Inventario: 3 artefactos → ./analysis/evidence_manifest.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  FASE 3 — INTERROGATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Thought: Primero busco logons externos...
  → query_forensic_db("external RDP connections?")
    Obs: {'row_count': 234, 'results': [...]}

★ HALLAZGO: [logons_externos] 234 resultados

  Thought: Hay IPs externas, investigar la más frecuente
  → query_forensic_db("administrator from multiple IPs same day?")
    Obs: {'row_count': 2, 'results': [{'fecha': '2024-06-22', ...}]}

★ HALLAZGO: [admin_multiples_ips] 2 resultados
```

---

## 5. Modo 3 — Web UI

Interfaz web local para usar DFIRLlama-SIFT desde el navegador. Ideal para demos o usuarios no acostumbrados al terminal.

### Iniciar

```bash
python3 webui.py
# Abre http://localhost:7860 en el navegador
```

### Funciones disponibles en la UI

**Panel izquierdo — Controles:**

| Sección | Qué hace |
|---------|----------|
| Evidence Interrogation Loop | Lanza el EIL completo. Pon la ruta del caso y click en "Run EIL" |
| Demo mode | Usa el dataset sintético incluido. No necesitas evidencia propia |
| NL→SQL Query | Escribe una pregunta en lenguaje natural sobre cualquier EVTX |
| IOC Analyzer | Investiga una IP, dominio, hash o comando PowerShell |

**Panel derecho — Resultados:**

| Pestaña | Qué muestra |
|---------|-------------|
| Terminal | El EIL corriendo en tiempo real (streaming) |
| Findings | Lista de hallazgos con nivel de confianza |
| ATT&CK | Técnicas MITRE identificadas. Botón para abrir Navigator |
| NL→SQL | SQL generada + resultados de la query |

### Flujo típico en la Web UI

1. Poner la ruta del caso en "Case directory": `/cases/IR-2024-0622`
2. Asignar un Incident ID: `IR-2024-0622`
3. Click en **▶ Run EIL**
4. Ver el análisis en tiempo real en la pestaña Terminal
5. Al terminar, ir a Findings y ATT&CK para ver resultados
6. Click en **Open in Navigator** para visualizar en MITRE ATT&CK Navigator

---

## 6. Qué evidencias puedo analizar

### Artefactos Windows (análisis completo)

| Archivo | Herramienta | Qué encuentra |
|---------|-------------|---------------|
| `*.evtx` | EvtxECmd + NL→SQL | Logons, PowerShell, log clearing, tareas programadas, servicios |
| `Amcache.hve` | AmcacheParser | Historial de ejecución con SHA1 y timestamps |
| `*.pf` (prefetch) | PECmd | Cuántas veces corrió cada ejecutable y cuándo |
| `SYSTEM` hive | AppCompatCacheParser | Archivos que interactuaron con el OS |
| `NTUSER.DAT` / `UsrClass.dat` | SBECmd | Carpetas que visitó el usuario (shellbags) |
| `SOFTWARE`, `SYSTEM` hives | RECmd | Persistencia, USB history, configuración de red |
| `$MFT` | MFTECmd | Todos los archivos con 4 timestamps + detección de timestomping |
| `*.lnk` | LECmd | Archivos abiertos, incluyendo en USBs |
| `AutomaticDestinations/` | JLECmd | Archivos recientes por aplicación (Jump Lists) |
| `$Recycle.Bin` | RBCmd | Archivos eliminados con ruta y timestamp original |

### Memoria y red

| Archivo | Herramienta | Qué encuentra |
|---------|-------------|---------------|
| `*.raw`, `*.vmem`, `*.lime` | Volatility 3 | Procesos, conexiones, código inyectado, DLLs |
| `*.pcap`, `*.pcapng` | tshark | Conversaciones, DNS, hosts HTTP, IPs externas |

### Archivos y binarios

| Archivo | Herramienta | Qué encuentra |
|---------|-------------|---------------|
| `*.exe`, `*.dll`, `*.bin` | strings + YARA + bulk_extractor | IOCs embebidos, patrones de malware |
| Cualquier archivo | file_hash | MD5/SHA1/SHA256/SHA512/ssdeep |
| Imagen de disco `.E01` | log2timeline (plaso) | Supertimeline completa |

### Texto e inteligencia de amenazas

| Input | Herramienta | Output |
|-------|-------------|--------|
| Reporte de TI (texto) | extract_iocs | JSON con IPs, dominios, hashes, URLs |
| Notas de triage | map_to_mitre | ATT&CK Navigator layer |
| IP / dominio / hash / PowerShell | analyze_ioc | Veredicto malicioso/sospechoso/benigno |

---

## 7. Ejemplos de uso real

### Caso 1: Tienes un .evtx y quieres saber qué pasó

```bash
# Opción A — pregunta directa en Claude Code
cd /casos/mi_caso
claude
> "Analiza el Security.evtx. ¿Hubo accesos externos? ¿Se limpiaron logs?"

# Opción B — NL→SQL directo desde terminal
python3 -c "
from tools.nlsql import query_nl
r = query_nl('/tmp/mi_evtx.db', 'Were there logon failures from external IPs?')
print(r['sql'])
print(r['results'])
"
```

### Caso 2: Tienes una IP sospechosa de los logs

```bash
# Desde terminal
python3 -c "
from tools.ioc_tools import analyze_ioc
r = analyze_ioc('102.20.90.8', 'ip')
print(r['verdict'])
"

# O desde la Web UI: pegar la IP en IOC Analyzer y click Investigate
python3 webui.py
```

### Caso 3: Quieres saber qué ejecutó el usuario en el equipo comprometido

```bash
# Parsear Amcache
python3 -c "
from tools.zimmerman_tools import amcache_parse
r = amcache_parse('/cases/IR-001/Amcache.hve')
for entry in r['summary']['suspicious_paths']:
    print(entry.get('FullPath'), entry.get('SHA1'))
"
```

### Caso 4: Investigación completa air-gap (sin internet)

```bash
# 1. Asegurarse de que Ollama corre
ollama serve &

# 2. Configurar el backend
export LLM_BACKEND=ollama
export OLLAMA_MODEL=mistral:7b

# 3. Correr el agente
python3 agent.py /cases/IR-2024-0622 --id IR-2024-0622

# 4. Revisar outputs
ls ./analysis/
# IR-2024-0622_findings.json
# IR-2024-0622_navigator.json
# IR-2024-0622_executive_summary.md
# evidence_manifest.json
# forensic_audit.log
```

### Caso 5: Demo rápida para mostrar el sistema (sin evidencia real)

```bash
# Demo mode — uses the included synthetic RDP compromise dataset
python3 agent.py demo/data --demo

# O desde Web UI con botón "Demo mode"
python3 webui.py
# → Click "🎬 Demo mode"
```

---

## 8. Cómo leer los outputs

Todos los outputs van a `./analysis/` (relativo a donde corriste el comando).

### `evidence_manifest.json` — Inventario de evidencia

```json
{
  "case_dir": "/cases/IR-2024-0622",
  "artifacts": [
    {
      "name": "Security.evtx",
      "type": "Windows Event Log",
      "size_mb": 45.2,
      "sha256": "a3f8b2c19d4e..."    ← hash para chain of custody
    }
  ]
}
```

### `IR-XXXX_findings.json` — Hallazgos verificados

```json
{
  "total_findings": 18,
  "hallucination_score": 0.056,      ← 5.6% = aceptable
  "technique_count": 14,
  "findings": [
    {
      "phase": "interrogate",
      "description": "administrator connected from external IP 102.20.90.8",
      "confidence": "high",
      "ioc_value": "102.20.90.8",
      "evidence_sample": [...]        ← filas reales del EVTX
    }
  ]
}
```

### `IR-XXXX_navigator.json` — ATT&CK Navigator layer

Importar en https://mitre-attack.github.io/attack-navigator/:
1. Abrir el Navigator
2. "Open Existing Layer" → "Upload from local"
3. Seleccionar el archivo `.json`

### `IR-XXXX_executive_summary.md` — Reporte para el cliente

Markdown listo para convertir a PDF o Word. Contiene:
- Resumen ejecutivo
- Técnicas ATT&CK identificadas con evidencia
- Hallazgos clave
- Acciones recomendadas

### `forensic_audit.log` — Audit trail completo

```jsonl
{"ts":"2026-06-03T07:14:22Z","tool":"evtx_to_sqlite","args":{"evtx_path":"/cases/..."},"result":"ok, 44281 events"}
{"ts":"2026-06-03T07:14:35Z","tool":"query_forensic_db","args":{"question":"external IPs?"},"result":"234 rows"}
```

Cada línea = una llamada a una herramienta. Útil para cadena de custodia.

### `hallucination_score` — Cómo interpretarlo

| Score | Significado | Acción |
|-------|-------------|--------|
| 0.0–10% | ✅ Limpio | Confiar en los hallazgos |
| 10–25% | ⚠️ Revisar | Validar manualmente los `contradicted` |
| >25% | ❌ Alto riesgo | Re-investigar antes de reportar |

---

## 9. Solución de problemas

### "No module named 'fastmcp'"
```bash
pip3 install fastmcp>=3.4.0
```

### "No module named 'vanna'"
```bash
pip3 install "vanna[chromadb]"
```

### "EvtxECmd not found" al parsear EVTX
El sistema usará automáticamente `python-evtx` como fallback. Para instalar EvtxECmd:
```bash
# En SIFT ya debería estar disponible como:
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll --help
```

### "claude: command not found"
Claude Code CLI no está instalado o no está en PATH:
```bash
which claude
# Si no aparece, seguir instrucciones de instalación en claude.ai/code
```

### El MCP server no conecta con Claude Code
Verificar que el path en settings.json es absoluto y correcto:
```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 "dfirllama"
# Debe mostrar el path completo a server.py
```

### Ollama no responde
```bash
ollama serve       # iniciar el servidor
ollama list        # verificar modelos instalados
ollama pull mistral:7b  # descargar el modelo si no está
```

### "timeout" en analyze_ioc
El agente ReAct espera respuesta de APIs externas (ipinfo.io, Google DNS).
En entornos air-gap, estas llamadas fallarán. Solución:
```bash
# El agente continuará sin esos datos y marcará el IOC como "unverified"
# Para forzar modo air-gap completo, bloquear las llamadas a nivel de red
```

### Los resultados del benchmark no coinciden con el paper
El benchmark `--dry-run` usa SQL de ground truth directamente (F1=100%).
Para resultados con LLM real, necesitas Ollama configurado:
```bash
python3 benchmark/run_benchmark.py --model mistral:7b --db demo/data/tslsm_demo.db
```

---

## 10. Referencia rápida de herramientas

### Llamar herramientas directamente desde Python

```python
import sys
sys.path.insert(0, '/ruta/a/dfirllama-sift')

# NL→SQL sobre EVTX
from tools.nlsql import query_nl
result = query_nl('/tmp/Security.db', '¿Hubo logons fallidos masivos?')
print(result['sql'])          # SQL generada
print(result['row_count'])    # filas encontradas
print(result['results'])      # datos

# Parsear EVTX
from tools.evtx_tools import evtx_to_sqlite
r = evtx_to_sqlite('/cases/Security.evtx')
db_path = r['db_path']        # usar este en query_nl

# Investigar IOC
from tools.ioc_tools import analyze_ioc
r = analyze_ioc('102.20.90.8', 'ip')
print(r['verdict'])

# Extraer IOCs de texto
from tools.ioc_tools import extract_iocs
r = extract_iocs("La IP 192.168.1.1 se conectó a evil.com el 2024-06-22")
print(r['iocs'])              # lista de IOCs estructurados

# Mapear a MITRE ATT&CK
from tools.sift_tools import map_to_mitre
r = map_to_mitre("PowerShell ejecutó payload Base64. IP africana en logs RDP.", "IR-001")
print(r['technique_count'])
# r['navigator_layer'] → importar en attack-navigator

# Validar hallazgos
from tools.validator import validate_findings
findings = [
    {"description": "Admin from 102.20.90.8", "ioc_type": "ip",
     "ioc_value": "102.20.90.8", "confidence": "high",
     "evidence_citation": "EventId=21 RemoteHost=102.20.90.8"}
]
r = validate_findings(findings, evidence_db='/tmp/Security.db')
print(r['hallucination_score'])  # 0.0 = todo verificado
print(r['needs_correction'])     # True si hay contradicciones
```

### Herramientas Zimmerman desde Python

```python
from tools.zimmerman_tools import amcache_parse, prefetch_parse, registry_query

# Ejecución de programas
r = amcache_parse('/cases/Amcache.hve')
print(r['summary']['suspicious_paths'])   # ejecutables en rutas sospechosas

# Timestamps de ejecución
r = prefetch_parse('/cases/Windows/Prefetch/')
print(r['suspicious_executables'])        # powershell, cmd, mshta, etc.

# Persistencia en registro
r = registry_query('/cases/NTUSER.DAT',
                   'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
print(r['data'])
```

### Variables de entorno disponibles

| Variable | Default | Descripción |
|---------|---------|-------------|
| `LLM_BACKEND` | `auto` | `claude`, `claude-api`, `ollama` |
| `ANTHROPIC_API_KEY` | — | API key de Anthropic (si LLM_BACKEND=claude-api) |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | URL del servidor Ollama |
| `OLLAMA_MODEL` | `mistral:7b` | Modelo a usar con Ollama |
| `CLAUDE_MODEL` | `claude-haiku-4-5-20251001` | Modelo Claude a usar |
| `EVIDENCE_ROOT` | `/cases` | Directorio raíz de evidencia (guardrail) |
| `AUDIT_LOG` | `/tmp/dfirllama_audit.log` | Ruta del audit trail |
| `CHROMA_PATH` | `/tmp/dfirllama_chroma` | Base de datos vectorial de Vanna |

---

## Estructura de archivos de outputs

```
./analysis/                          ← directorio de salida
├── evidence_manifest.json           ← inventario con hashes SHA256
├── orient_results.json              ← eje temporal y stats de EVTX
├── interrogate_findings.json        ← hallazgos del triage NL→SQL
├── enrich_results.json              ← resultados de investigación de IOCs
├── validation_results.json          ← validate_findings con hallucination_score
├── eil_session.json                 ← metadata de la sesión EIL
├── IR-XXXX_findings.json            ← reporte completo JSON
├── IR-XXXX_navigator.json           ← ATT&CK Navigator layer
├── IR-XXXX_executive_summary.md     ← reporte para el cliente
└── forensic_audit.log               ← audit trail JSONL de cada tool call
```

---

*DFIRLlama-SIFT v1.0 — SANS FIND EVIL! Hackathon 2026*  
*DFIRLlama Research*  
*MIT License — TLP:CLEAR*
