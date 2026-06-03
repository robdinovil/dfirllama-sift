#!/usr/bin/env python3
"""Genera el Manual de Usuario de DFIRLlama-SIFT en formato .docx"""

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

def add_heading(doc, text, level=1, color=None):
    h = doc.add_heading(text, level=level)
    if color:
        for run in h.runs:
            run.font.color.rgb = color
    return h

def add_para(doc, text, bold=False, italic=False, color=None, size=None):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    if color:
        run.font.color.rgb = color
    if size:
        run.font.size = Pt(size)
    return p

def add_code(doc, text):
    p = doc.add_paragraph()
    p.style = doc.styles['Normal']
    run = p.add_run(text)
    run.font.name = 'Courier New'
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x58, 0xa6, 0xff)
    p.paragraph_format.left_indent = Cm(1)
    shading = OxmlElement('w:shd')
    shading.set(qn('w:val'), 'clear')
    shading.set(qn('w:color'), 'auto')
    shading.set(qn('w:fill'), '0D1117')
    p._p.get_or_add_pPr().append(shading)
    return p

def add_table(doc, headers, rows, col_widths=None):
    table = doc.add_table(rows=1+len(rows), cols=len(headers))
    table.style = 'Table Grid'
    hdr = table.rows[0].cells
    for i, h in enumerate(headers):
        hdr[i].text = h
        hdr[i].paragraphs[0].runs[0].bold = True
        hdr[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(0x58, 0xa6, 0xff)
    for ri, row in enumerate(rows):
        cells = table.rows[ri+1].cells
        for ci, val in enumerate(row):
            cells[ci].text = str(val)
    return table

def add_bullet(doc, text, level=0):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.left_indent = Cm(level * 0.5 + 0.5)
    run = p.add_run(text)
    return p

def build():
    doc = Document()

    # ── Estilos globales ──────────────────────────────────────────────────────
    style = doc.styles['Normal']
    style.font.name = 'Calibri'
    style.font.size = Pt(11)

    # ── Portada ───────────────────────────────────────────────────────────────
    doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run('DFIRLlama-SIFT')
    run.bold = True
    run.font.size = Pt(28)
    run.font.color.rgb = RGBColor(0x58, 0xa6, 0xff)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run2 = sub.add_run('Manual de Usuario — Guía Completa de Instalación y Uso')
    run2.font.size = Pt(16)
    run2.font.color.rgb = RGBColor(0x8b, 0x94, 0x9e)

    doc.add_paragraph()
    badge = doc.add_paragraph()
    badge.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = badge.add_run('SANS FIND EVIL! Hackathon 2026  |  Protocol SIFT Extension  |  MIT License')
    r.font.size = Pt(11)
    r.italic = True

    doc.add_paragraph()
    info = doc.add_paragraph()
    info.alignment = WD_ALIGN_PARAGRAPH.CENTER
    info.add_run('DFIRLlama Research\nSANS FIND EVIL! Hackathon 2026')

    doc.add_page_break()

    # ── Índice ────────────────────────────────────────────────────────────────
    add_heading(doc, 'Contenido', level=1)
    toc = [
        '1. Qué es DFIRLlama-SIFT',
        '2. El problema que resuelve',
        '3. Arquitectura del sistema',
        '4. Requisitos del sistema',
        '5. Instalación paso a paso',
        '6. Configuración',
        '7. Modo 1 — Claude Code + MCP',
        '8. Modo 2 — Agente standalone (Ollama / air-gap)',
        '9. Modo 3 — Web UI',
        '10. Qué evidencias puede analizar',
        '11. Los agentes ReAct',
        '12. El EIL — Evidence Interrogation Loop',
        '13. Cómo leer los outputs',
        '14. Referencia de herramientas',
        '15. Solución de problemas',
        '16. Seguridad y cadena de custodia',
        '17. Preguntas frecuentes',
    ]
    for item in toc:
        add_bullet(doc, item)

    doc.add_page_break()

    # ── 1. Qué es ─────────────────────────────────────────────────────────────
    add_heading(doc, '1. Qué es DFIRLlama-SIFT', level=1)
    add_para(doc,
        'DFIRLlama-SIFT es una extensión del SIFT Workstation de SANS que permite '
        'investigar artefactos forenses Windows usando inteligencia artificial '
        'completamente local. El analista DFIR describe en lenguaje natural lo que '
        'quiere saber, y el sistema lo investiga autónomamente.')
    doc.add_paragraph()
    add_para(doc, 'Lo que hace en 12 minutos que manualmente toma 3-4 horas:', bold=True)
    bullets = [
        'Inventaria y hashea todos los artefactos del caso',
        'Parsea archivos EVTX (.evtx) a SQLite y los interroga con preguntas en español/inglés',
        'Analiza volcados de memoria con Volatility 3',
        'Procesa Amcache, Prefetch, ShimCache, MFT, LNK, Shellbags, Jump Lists',
        'Investiga IPs, dominios y hashes con threat intelligence',
        'Valida cada hallazgo contra la evidencia real (detecta alucinaciones)',
        'Genera reporte con técnicas MITRE ATT&CK y Navigator layer',
    ]
    for b in bullets:
        add_bullet(doc, b)

    doc.add_paragraph()
    add_heading(doc, '1.1 Los tres agentes del sistema', level=2)
    add_table(doc,
        ['Agente', 'Nivel', 'Qué hace'],
        [
            ['Claude Code / agent.py', 'Macro-orquestador', 'Lee el SKILL.md, decide qué fases ejecutar, coordina todo'],
            ['EILAgent.react()', 'EIL por fase', 'Loop Thought→Action→Observation por cada fase de investigación'],
            ['analyze_ioc()', 'Micro-especializado', 'Investiga un solo IOC: decode_base64 → whois → DNS → GeoIP → threat list'],
        ]
    )

    doc.add_page_break()

    # ── 2. El problema ────────────────────────────────────────────────────────
    add_heading(doc, '2. El problema que resuelve', level=1)
    add_para(doc,
        'Los analistas DFIR enfrentan una contradicción: quieren usar IA para '
        'acelerar el análisis, pero sus evidencias son sensibles. Mandarlas a '
        'ChatGPT/Claude cloud rompe cadena de custodia, viola NDAs y puede '
        'comprometer procesos legales. Cyberhaven (2023) documentó que el 11% de '
        'todo el contenido empresarial enviado a IA cloud es confidencial.')
    doc.add_paragraph()
    add_para(doc, 'El segundo problema es técnico:', bold=True)
    add_para(doc,
        'Un EVTX de 72 horas de un servidor comprometido puede tener 500,000 eventos. '
        'Los LLMs colapsan de atención después de ~4,000 tokens útiles (benchmark '
        'NoLiMa, arXiv 2502.05167). Pasar el CSV completo al LLM produce alucinaciones, '
        'no análisis.')
    doc.add_paragraph()
    add_heading(doc, '2.1 La solución: interrogación en lugar de lectura', level=2)
    add_para(doc, 'Patrón convencional (el que todos usan):', bold=True)
    add_code(doc, 'EvtxECmd → CSV 50,000 filas → LLM intenta leer → contexto colapsa → alucina')
    add_para(doc, 'DFIRLlama-SIFT:', bold=True)
    add_code(doc, 'EvtxECmd → SQLite → NL→SQL → "12 filas exactas" → LLM razona sobre resultado')
    add_para(doc,
        'El LLM escribe 5 líneas de SQL (problema pequeño). SQL opera sobre el dataset '
        'completo sin importar el tamaño. El LLM recibe el resultado exacto. La '
        'alucinación por desbordamiento de contexto es estructuralmente imposible.')

    doc.add_page_break()

    # ── 3. Arquitectura ───────────────────────────────────────────────────────
    add_heading(doc, '3. Arquitectura del sistema', level=1)
    add_code(doc,
        'Tu terminal\n'
        '    │\n'
        '    ▼  claude  (ó  python3 agent.py  ó  python3 webui.py)\n'
        'Claude Code / EILAgent\n'
        '    │  Lee: CLAUDE.md + skills/dfirllama-eil/SKILL.md\n'
        '    │\n'
        '    │  JSON-RPC stdio (MCP)\n'
        '    ▼\n'
        'server.py  ←  22 herramientas forenses tipadas\n'
        '    │\n'
        '    ├── tools/evtx_tools.py    ←  EvtxECmd + NL→SQL\n'
        '    ├── tools/nlsql.py         ←  NL→SQL engine propio\n'
        '    ├── tools/ioc_tools.py     ←  ReAct IOC agent\n'
        '    ├── tools/sift_tools.py    ←  Volatility3 + plaso + YARA\n'
        '    ├── tools/zimmerman_tools.py  ←  9 EZ Tools wrappers\n'
        '    ├── tools/forensic_tools.py   ←  bulk_extractor + tshark\n'
        '    └── tools/validator.py    ←  validador de alucinaciones\n'
        '    │\n'
        'guardrails.py  ←  read-only + path check + audit trail JSONL'
    )
    doc.add_paragraph()
    add_heading(doc, '3.1 Los tres backends LLM', level=2)
    add_table(doc,
        ['Backend', 'Cuándo usar', 'Internet', 'Config'],
        [
            ['claude-cli (default)', 'Hackathon, SIFT con Claude Code', 'Sí', 'LLM_BACKEND=claude'],
            ['claude-api', 'Producción con API key propia', 'Sí', 'LLM_BACKEND=claude-api + API key'],
            ['ollama (air-gap)', 'Evidencia sensible, sin internet', 'No', 'LLM_BACKEND=ollama'],
        ]
    )

    doc.add_page_break()

    # ── 4. Requisitos ─────────────────────────────────────────────────────────
    add_heading(doc, '4. Requisitos del sistema', level=1)
    add_heading(doc, '4.1 Hardware', level=2)
    add_table(doc,
        ['Componente', 'Mínimo', 'Recomendado'],
        [
            ['RAM', '8 GB', '16 GB+'],
            ['Disco libre', '2 GB', '10 GB+'],
            ['CPU', 'Cualquier x86-64', '4+ cores'],
            ['GPU', 'No requerida', 'Opcional (acelera Ollama)'],
        ]
    )
    doc.add_paragraph()
    add_heading(doc, '4.2 Software', level=2)
    add_table(doc,
        ['Software', 'Versión mínima', 'Verificar con'],
        [
            ['SANS SIFT Workstation', 'Ubuntu 20.04+', 'lsb_release -a'],
            ['Python', '3.10+', 'python3 --version'],
            ['Claude Code CLI', 'Cualquiera', 'claude --version'],
            ['Ollama (opcional, air-gap)', 'Cualquiera', 'ollama --version'],
        ]
    )

    doc.add_page_break()

    # ── 5. Instalación ────────────────────────────────────────────────────────
    add_heading(doc, '5. Instalación paso a paso', level=1)
    add_heading(doc, 'Opción A — Instalación automática (recomendada)', level=2)
    add_code(doc,
        'git clone https://github.com/[usuario]/dfirllama-sift\n'
        'cd dfirllama-sift\n'
        'bash setup.sh'
    )
    add_para(doc, 'El script setup.sh hace todo automáticamente: instala dependencias, '
             'crea el .env, instala el skill EIL en Claude Code, y registra el servidor MCP.')

    doc.add_paragraph()
    add_heading(doc, 'Opción B — Instalación manual', level=2)
    steps = [
        ('Paso 1 — Clonar el repositorio',
         'git clone https://github.com/[usuario]/dfirllama-sift\ncd dfirllama-sift'),
        ('Paso 2 — Instalar dependencias Python',
         'pip3 install -r requirements.txt'),
        ('Paso 3 — Configurar entorno',
         'cp .env.example .env\nnano .env  # elegir LLM_BACKEND'),
        ('Paso 4 — Instalar skill EIL',
         'mkdir -p ~/.claude/skills/dfirllama-eil\ncp skills/dfirllama-eil/SKILL.md ~/.claude/skills/dfirllama-eil/'),
        ('Paso 5 — Registrar MCP en Claude Code',
         'nano ~/.claude/settings.json  # agregar sección mcpServers'),
        ('Paso 6 — Verificar',
         'python3 -c "import server, agent; print(\'OK\')"\npython3 benchmark/run_benchmark.py --dry-run'),
    ]
    for title, code in steps:
        add_para(doc, title, bold=True)
        add_code(doc, code)
        doc.add_paragraph()

    doc.add_page_break()

    # ── 6. Configuración ──────────────────────────────────────────────────────
    add_heading(doc, '6. Configuración', level=1)
    add_heading(doc, '6.1 Archivo .env', level=2)
    add_code(doc,
        '# Backend LLM — elige uno:\n'
        'LLM_BACKEND=claude        # Claude Code (hackathon)\n'
        '# LLM_BACKEND=ollama      # Ollama local (air-gap)\n\n'
        '# Si usas Ollama:\n'
        'OLLAMA_BASE_URL=http://localhost:11434/v1\n'
        'OLLAMA_MODEL=mistral:7b\n\n'
        '# Directorio raíz de evidencia (guardrail de seguridad)\n'
        'EVIDENCE_ROOT=/cases\n\n'
        '# Audit trail\n'
        'AUDIT_LOG=/tmp/dfirllama_audit.log'
    )
    doc.add_paragraph()
    add_heading(doc, '6.2 settings.json de Claude Code', level=2)
    add_code(doc,
        '{\n'
        '  "mcpServers": {\n'
        '    "dfirllama-sift": {\n'
        '      "command": "python3",\n'
        '      "args": ["/ruta/a/dfirllama-sift/server.py"],\n'
        '      "env": {\n'
        '        "LLM_BACKEND": "claude",\n'
        '        "EVIDENCE_ROOT": "/cases",\n'
        '        "AUDIT_LOG": "/tmp/dfirllama_audit.log"\n'
        '      }\n'
        '    }\n'
        '  }\n'
        '}'
    )

    doc.add_page_break()

    # ── 7. Modo 1 ─────────────────────────────────────────────────────────────
    add_heading(doc, '7. Modo 1 — Claude Code + MCP (recomendado)', level=1)
    add_para(doc,
        'Claude Code actúa como el cerebro del sistema. Lee el protocolo EIL del '
        'SKILL.md y llama a las 22 herramientas del servidor MCP automáticamente, '
        'sin que el analista deba indicar cada paso.')
    doc.add_paragraph()
    add_heading(doc, '7.1 Cómo usarlo', level=2)
    add_code(doc,
        '# 1. Copiar evidencia al directorio del caso\n'
        'mkdir -p /cases/IR-2024-0622\n'
        'cp /media/usb/*.evtx /cases/IR-2024-0622/\n'
        'cp /media/usb/memory.raw /cases/IR-2024-0622/\n\n'
        '# 2. (Opcional) crear CLAUDE.md con contexto del caso\n'
        'cat > /cases/IR-2024-0622/CLAUDE.md << \'EOF\'\n'
        '# Caso IR-2024-0622\n'
        'Red interna: 10.0.0.0/8\n'
        'Usuario legítimo: jparker (soporte IT)\n'
        'Período de interés: junio 2024\n'
        'EOF\n\n'
        '# 3. Abrir Claude Code\n'
        'cd /cases/IR-2024-0622\n'
        'claude'
    )
    doc.add_paragraph()
    add_heading(doc, '7.2 Ejemplos de prompts', level=2)
    prompts = [
        ('Investigación completa autónoma',
         '"Investiga todos los artefactos. Busca compromiso, persistencia y exfiltración."'),
        ('Análisis de EVTX específico',
         '"Analiza Security.evtx. Busca logons externos, cuentas creadas y PowerShell."'),
        ('Pregunta forense directa',
         '"¿El usuario administrator se conectó desde más de una IP el mismo día?"'),
        ('Investigar un IOC',
         '"Investiga la IP 102.20.90.8. ¿Es maliciosa? ¿A qué país pertenece?"'),
        ('Análisis de memoria',
         '"Corre Volatility sobre memory.raw. Muestra procesos y busca código inyectado."'),
    ]
    for title, prompt in prompts:
        add_para(doc, title + ':', bold=True)
        add_code(doc, prompt)

    doc.add_page_break()

    # ── 8. Modo 2 ─────────────────────────────────────────────────────────────
    add_heading(doc, '8. Modo 2 — Agente standalone (Ollama / air-gap)', level=1)
    add_para(doc,
        'Para casos donde la evidencia no puede salir de la red. El agente '
        'standalone (agent.py) corre el EIL completo sin Claude Code, usando '
        'Ollama como LLM local. Cero bytes salen de la máquina.')
    doc.add_paragraph()
    add_heading(doc, '8.1 Configurar Ollama (una vez, con internet)', level=2)
    add_code(doc,
        '# Instalar Ollama\n'
        'curl -fsSL https://ollama.ai/install.sh | sh\n\n'
        '# Descargar modelo (4 GB)\n'
        'ollama pull mistral:7b\n\n'
        '# Verificar\n'
        'ollama list'
    )
    add_para(doc, 'Una vez descargado, Ollama funciona sin internet. El modelo queda en disco.')
    doc.add_paragraph()
    add_heading(doc, '8.2 Comandos', level=2)
    add_code(doc,
        '# Investigación completa\n'
        'LLM_BACKEND=ollama python3 agent.py /cases/IR-2024-0622\n\n'
        '# Con ID de incidente\n'
        'python3 agent.py /cases/IR-2024-0622 --id IR-2024-0622\n\n'
        '# Desde una fase específica\n'
        'python3 agent.py /cases/IR-2024-0622 --phase interrogate\n\n'
        '# Demo sin evidencia real\n'
        'python3 agent.py demo/data --demo'
    )

    doc.add_page_break()

    # ── 9. Modo 3 ─────────────────────────────────────────────────────────────
    add_heading(doc, '9. Modo 3 — Web UI', level=1)
    add_para(doc,
        'Interfaz web local accesible desde el navegador. Ideal para demostraciones '
        'o analistas no acostumbrados al terminal.')
    add_code(doc,
        'python3 webui.py\n'
        '# Abrir http://localhost:7860 en el navegador'
    )
    doc.add_paragraph()
    add_heading(doc, '9.1 Funciones disponibles', level=2)
    add_table(doc,
        ['Sección', 'Qué hace'],
        [
            ['▶ Run EIL', 'Lanza investigación completa. Pon la ruta del caso y click.'],
            ['🎬 Demo mode', 'Usa el dataset sintético incluido. No necesitas evidencia propia.'],
            ['⚡ NL→SQL Query', 'Escribe una pregunta en lenguaje natural, ve el SQL generado y resultados.'],
            ['🔍 IOC Analyzer', 'Investiga una IP, dominio o hash con el agente ReAct.'],
            ['Pestaña Terminal', 'El EIL corriendo en tiempo real (streaming).'],
            ['Pestaña Findings', 'Lista de hallazgos con nivel de confianza.'],
            ['Pestaña ATT&CK', 'Técnicas MITRE. Botón para abrir en Navigator directamente.'],
        ]
    )

    doc.add_page_break()

    # ── 10. Evidencias ────────────────────────────────────────────────────────
    add_heading(doc, '10. Qué evidencias puede analizar', level=1)
    add_heading(doc, '10.1 Artefactos Windows', level=2)
    add_table(doc,
        ['Archivo', 'Herramienta SIFT', 'Qué encuentra'],
        [
            ['*.evtx', 'EvtxECmd + NL→SQL', 'Logons, PowerShell, log clearing, tareas, servicios'],
            ['Amcache.hve', 'AmcacheParser', 'Historial ejecución + SHA1 + timestamps'],
            ['*.pf (Prefetch)', 'PECmd', 'Cuántas veces corrió cada exe y cuándo'],
            ['SYSTEM hive', 'AppCompatCacheParser', 'Archivos que interactuaron con el OS (ShimCache)'],
            ['NTUSER.DAT / UsrClass.dat', 'SBECmd', 'Carpetas visitadas por el usuario (Shellbags)'],
            ['SOFTWARE / SYSTEM', 'RECmd', 'Persistencia, USB history, configuración de red'],
            ['$MFT', 'MFTECmd', 'Todos los archivos con 4 timestamps + detección timestomping'],
            ['*.lnk', 'LECmd', 'Archivos abiertos, incluyendo en USBs'],
            ['AutomaticDestinations/', 'JLECmd', 'Archivos recientes por aplicación (Jump Lists)'],
            ['$Recycle.Bin', 'RBCmd', 'Archivos eliminados con ruta y timestamp original'],
        ]
    )
    doc.add_paragraph()
    add_heading(doc, '10.2 Memoria y red', level=2)
    add_table(doc,
        ['Archivo', 'Herramienta', 'Qué encuentra'],
        [
            ['*.raw, *.vmem, *.lime', 'Volatility 3', 'Procesos, conexiones, código inyectado, DLLs cargadas'],
            ['*.pcap, *.pcapng', 'tshark', 'Conversaciones IP, DNS queries, HTTP hosts, IPs externas'],
        ]
    )
    doc.add_paragraph()
    add_heading(doc, '10.3 Texto e inteligencia de amenazas', level=2)
    add_table(doc,
        ['Input', 'Herramienta', 'Output'],
        [
            ['Reporte TI (texto libre)', 'extract_iocs', 'JSON estructurado: IPs, dominios, hashes, URLs'],
            ['Notas de triage', 'map_to_mitre', 'ATT&CK Navigator layer importable'],
            ['IP / dominio / hash / PowerShell', 'analyze_ioc (ReAct)', 'Veredicto malicioso/sospechoso/benigno'],
        ]
    )

    doc.add_page_break()

    # ── 11. Agentes ReAct ─────────────────────────────────────────────────────
    add_heading(doc, '11. Los agentes ReAct', level=1)
    add_para(doc,
        'ReAct (Reasoning + Acting) es el patrón de razonamiento de los agentes. '
        'El loop es: Thought → Action → Observation → repeat hasta tener respuesta final.')
    doc.add_paragraph()
    add_heading(doc, '11.1 Ejemplo real — análisis de IP sospechosa', level=2)
    add_code(doc,
        'Thought: Tengo la IP 102.20.90.8. Verifico geolocalización primero.\n'
        'Action: geoip_lookup\n'
        'Action Input: {"ip": "102.20.90.8"}\n'
        'Observation: {"country": "NG", "org": "AS37282", "city": "Lagos"}\n\n'
        'Thought: Nigeria, ASN africano. Sospechoso. Verifico en listas de amenazas.\n'
        'Action: threat_list_check\n'
        'Action Input: {"ip": "102.20.90.8"}\n'
        'Observation: {"in_blocklist": true, "score": 7}\n\n'
        'Final Answer: MALICIOSA (confianza: alta)\n'
        '  - IP nigeriana, AS37282 (AFRINIC)\n'
        '  - En blocklist IPSum: score 7/10\n'
        '  - Acción: bloquear en firewall, revisar sesiones RDP'
    )
    doc.add_paragraph()
    add_heading(doc, '11.2 Herramientas disponibles para analyze_ioc', level=2)
    add_table(doc,
        ['Herramienta', 'Qué hace'],
        [
            ['decode_base64', 'Decodifica strings Base64 (PowerShell encoded commands)'],
            ['domain_whois', 'WHOIS: registrante, fecha de creación, servidores DNS'],
            ['dns_resolve', 'Resuelve dominio a IP via Google DNS-over-HTTPS'],
            ['geoip_lookup', 'País, ciudad, ASN de una IP via ipinfo.io'],
            ['threat_list_check', 'Verifica IP en blocklist IPSum (30+ fuentes de threat intel)'],
        ]
    )

    doc.add_page_break()

    # ── 12. EIL ───────────────────────────────────────────────────────────────
    add_heading(doc, '12. El EIL — Evidence Interrogation Loop', level=1)
    add_para(doc,
        'El EIL es el protocolo de investigación autónoma de 6 fases. Se define en '
        'el archivo SKILL.md que Claude Code lee antes de comenzar. Cada fase tiene '
        'un objetivo claro y herramientas específicas.')
    doc.add_paragraph()
    fases = [
        ('FASE 1 — INVENTORY',
         'Mapear toda la evidencia disponible',
         'file_hash sobre cada artefacto → evidence_manifest.json con SHA256'),
        ('FASE 2 — ORIENT',
         'Construir el eje temporal',
         'evtx_to_sqlite (parsear EVTX), volatility pslist/netscan (memoria)'),
        ('FASE 3 — INTERROGATE',
         'Hacer preguntas forenses con NL→SQL',
         '8+ queries estándar de triage sobre EVTX, parseo de Amcache/Prefetch/ShimCache'),
        ('FASE 4 — ENRICH',
         'Investigar cada IOC encontrado',
         'analyze_ioc por cada IP, dominio, hash o PowerShell sospechoso'),
        ('FASE 5 — VALIDATE',
         'Verificar hallazgos contra evidencia real',
         'validate_findings → hallucination_score → auto-corrección si necesario'),
        ('FASE 6 — REPORT',
         'Generar reporte estructurado',
         'map_to_mitre → ATT&CK Navigator + executive_summary.md + findings.json'),
    ]
    for fase, objetivo, herramientas in fases:
        add_para(doc, fase, bold=True, color=RGBColor(0x58, 0xa6, 0xff))
        add_para(doc, f'Objetivo: {objetivo}')
        add_para(doc, f'Herramientas: {herramientas}')
        doc.add_paragraph()

    doc.add_page_break()

    # ── 13. Outputs ───────────────────────────────────────────────────────────
    add_heading(doc, '13. Cómo leer los outputs', level=1)
    add_para(doc, 'Todos los outputs van a ./analysis/ relativo al directorio del caso.')
    doc.add_paragraph()
    add_table(doc,
        ['Archivo', 'Contenido', 'Para qué sirve'],
        [
            ['evidence_manifest.json', 'Inventario de artefactos con SHA256', 'Chain of custody'],
            ['IR-XXXX_findings.json', 'Hallazgos verificados con confidence', 'Reporte técnico'],
            ['IR-XXXX_navigator.json', 'ATT&CK Navigator layer JSON', 'Importar en MITRE Navigator'],
            ['IR-XXXX_executive_summary.md', 'Narrativa Markdown para el cliente', 'Reporte ejecutivo'],
            ['forensic_audit.log', 'JSONL de cada tool call con timestamp UTC', 'Auditoría / evidencia'],
            ['validation_results.json', 'hallucination_score y self-corrections', 'Control de calidad'],
        ]
    )
    doc.add_paragraph()
    add_heading(doc, '13.1 Interpretar hallucination_score', level=2)
    add_table(doc,
        ['Score', 'Significado', 'Acción'],
        [
            ['0.0 – 10%', '✅ Limpio', 'Confiar en los hallazgos'],
            ['10% – 25%', '⚠️ Revisar', 'Validar manualmente los contradicted'],
            ['>25%', '❌ Alto riesgo', 'Re-investigar antes de reportar'],
        ]
    )

    doc.add_page_break()

    # ── 14. Referencia herramientas ───────────────────────────────────────────
    add_heading(doc, '14. Referencia de herramientas', level=1)
    add_table(doc,
        ['Herramienta MCP', 'Input principal', 'Output principal'],
        [
            ['evtx_to_sqlite', 'Ruta al .evtx', 'db_path SQLite, total_events, time_range'],
            ['query_forensic_db', 'db_path + pregunta NL', 'SQL generada + filas de resultado'],
            ['analyze_ioc', 'IP/dominio/hash/PowerShell', 'Veredicto + tool_calls log'],
            ['extract_iocs', 'Texto libre', 'Lista de IOCs estructurados (JSON)'],
            ['map_to_mitre', 'Notas de triage', 'Técnicas ATT&CK + Navigator layer'],
            ['validate_findings', 'Lista de hallazgos + db', 'hallucination_score + triggers'],
            ['volatility_run', 'image_path + plugin', 'Output del plugin (texto)'],
            ['amcache_parse', 'Amcache.hve', 'Historial ejecución + rutas sospechosas'],
            ['prefetch_parse', 'Directorio Prefetch/', 'Ejecutables + timestamps + run_count'],
            ['shimcache_parse', 'SYSTEM hive', 'Archivos que interactuaron con el OS'],
            ['registry_query', 'Hive + key_path', 'Valores de registro'],
            ['mft_timeline', '$MFT', 'Timeline + timestomping detectado'],
            ['lnk_parse', 'Directorio Recent/', 'Archivos abiertos con timestamps'],
            ['shellbag_parse', 'NTUSER.DAT', 'Carpetas visitadas'],
            ['jumplist_parse', 'AutoDest/', 'Archivos recientes por aplicación'],
            ['recycle_bin_parse', '$Recycle.Bin/', 'Archivos eliminados + rutas originales'],
            ['bulk_extract', 'Imagen/volcado', 'IPs, emails, URLs, hashes carveados'],
            ['pcap_analyze', '*.pcap', 'Conversaciones, DNS, HTTP hosts, IPs externas'],
            ['strings_extract', 'Binario/ejecutable', 'Strings clasificados por categoría forense'],
            ['file_hash', 'Cualquier archivo', 'MD5, SHA1, SHA256, SHA512, ssdeep'],
            ['yara_scan', 'Archivo/directorio + reglas', 'Matches con nombre de regla y tags'],
            ['log2timeline_run', 'Artefacto/imagen', 'Supertimeline CSV (plaso)'],
        ]
    )

    doc.add_page_break()

    # ── 15. Troubleshooting ───────────────────────────────────────────────────
    add_heading(doc, '15. Solución de problemas', level=1)
    problemas = [
        ('No module named "fastmcp"',
         'pip3 install fastmcp>=3.4.0 --break-system-packages'),
        ('No module named "vanna"',
         'pip3 install "vanna[chromadb]" --break-system-packages'),
        ('"claude: command not found"',
         'Claude Code no está en PATH. Ver https://claude.ai/code para instalación.'),
        ('El MCP no conecta con Claude Code',
         'Verificar que el path en settings.json es absoluto y correcto:\ncat ~/.claude/settings.json | python3 -m json.tool'),
        ('Ollama no responde',
         'ollama serve    # iniciar el servidor\nollama list      # verificar modelos\nollama pull mistral:7b  # descargar modelo'),
        ('timeout en analyze_ioc',
         'Las APIs externas (ipinfo.io, DNS) no están disponibles en air-gap.\nEl agente continuará y marcará el IOC como "unverified".'),
        ('EvtxECmd not found',
         'El sistema usará python-evtx automáticamente como fallback.\nPara EvtxECmd: dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll --help'),
    ]
    for prob, sol in problemas:
        add_para(doc, f'Problema: {prob}', bold=True)
        add_code(doc, f'Solución:\n{sol}')
        doc.add_paragraph()

    doc.add_page_break()

    # ── 16. Seguridad ─────────────────────────────────────────────────────────
    add_heading(doc, '16. Seguridad y cadena de custodia', level=1)
    add_heading(doc, '16.1 Guardrails arquitectónicos (código, no prompts)', level=2)
    add_table(doc,
        ['Protección', 'Cómo funciona'],
        [
            ['Read-only enforcement', 'guardrails.py bloquea rm, dd, shred, wget, curl, ssh antes de subprocess.run()'],
            ['Path boundaries', 'check_path() valida que cada archivo esté en EVIDENCE_ROOT, /tmp, /home o /var/log'],
            ['Audit trail JSONL', 'Cada tool call registrado: timestamp UTC, herramienta, args, resultado'],
            ['Sin escritura a evidencia', 'Outputs van a ./analysis/, ./reports/ o /tmp/ — nunca a /cases/'],
        ]
    )
    doc.add_paragraph()
    add_heading(doc, '16.2 Qué ve el LLM vs. qué no ve', level=2)
    add_para(doc, 'El LLM NUNCA ve:', bold=True)
    for item in ['El archivo .evtx crudo', 'El volcado de memoria completo',
                 'Las colmenas de registro en binario', 'Imágenes de disco']:
        add_bullet(doc, item)
    doc.add_paragraph()
    add_para(doc, 'El LLM SÍ ve (solo resultados estructurados):', bold=True)
    for item in ['Máximo 50 filas de resultado de una query SQL',
                 'Texto de salida de Volatility truncado a 8,000 caracteres',
                 'JSON con los hallazgos del agente IOC']:
        add_bullet(doc, item)
    doc.add_paragraph()
    add_para(doc,
        'Esta distinción es clave para la cadena de custodia: '
        'la evidencia primaria nunca sale del SIFT Workstation.',
        italic=True)

    doc.add_page_break()

    # ── 17. FAQ ───────────────────────────────────────────────────────────────
    add_heading(doc, '17. Preguntas frecuentes', level=1)
    faq = [
        ('¿Puedo usar esto en un caso real bajo NDA?',
         'Sí, con LLM_BACKEND=ollama. Con Ollama, cero datos salen de tu máquina. '
         'Con LLM_BACKEND=claude, los resultados de las herramientas (no la evidencia cruda) '
         'pasan por la API de Anthropic.'),
        ('¿Funciona con EVTX muy grandes (millones de eventos)?',
         'Sí. NL→SQL opera sobre el SQLite completo independientemente del tamaño. '
         'La única limitación es el espacio en disco para la SQLite.'),
        ('¿El hallucination_score de 0% significa que no hay errores?',
         'Significa que todos los hallazgos citados pudieron verificarse contra la evidencia. '
         'No garantiza que no haya hallazgos no citados. Siempre revisar el reporte con criterio forense.'),
        ('¿Puedo agregar mis propias reglas YARA?',
         'Sí: yara_scan_tool(target_path="/cases/malware/", rules_path="/mis_reglas/custom.yar")'),
        ('¿Puedo entrenar el NL→SQL con mis propios ejemplos?',
         'Sí, editando tools/nlsql.py::DFIR_CONTEXT y EJEMPLOS. También puedes usar '
         'el motor Vanna (tools/evtx_tools.py) que aprende de pares pregunta-SQL entre casos.'),
        ('¿Qué modelo de Ollama recomiendan?',
         'mistral:7b para la mayoría de tareas (4 GB RAM, buena velocidad). '
         'qwen2.5:14b para mejor calidad si tienes 16 GB+ RAM.'),
    ]
    for pregunta, respuesta in faq:
        add_para(doc, f'P: {pregunta}', bold=True)
        add_para(doc, f'R: {respuesta}')
        doc.add_paragraph()

    # ── Pie de página ─────────────────────────────────────────────────────────
    doc.add_page_break()
    footer_p = doc.add_paragraph()
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = footer_p.add_run(
        'DFIRLlama-SIFT v1.0  |  SANS FIND EVIL! Hackathon 2026\n'
        'DFIRLlama Research\n'
        'MIT License — TLP:CLEAR\n'
        'Dataset: Synthetic RDP compromise + sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0)'
    )
    r.font.size = Pt(10)
    r.font.color.rgb = RGBColor(0x8b, 0x94, 0x9e)

    # Guardar
    out_path = '/home/sansforensics/dfirllama-sift/DFIRLlama-SIFT_Manual_Usuario.docx'
    doc.save(out_path)
    print(f'✓ DOCX guardado: {out_path}')
    return out_path


if __name__ == '__main__':
    build()
