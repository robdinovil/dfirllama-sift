#!/bin/bash
# DFIRLlama-SIFT — Script de instalación automática
# SANS FIND EVIL! Hackathon 2026
# Uso: bash setup.sh

set -e

CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${CYAN}${BOLD}DFIRLlama-SIFT — Instalación automática${RESET}"
echo -e "${CYAN}Directorio: ${REPO_DIR}${RESET}\n"

# ── 1. Verificar Python ────────────────────────────────────────────────────────
echo -e "${BOLD}[1/6] Verificando Python 3.10+...${RESET}"
python3 --version || { echo -e "${RED}Python 3 no encontrado${RESET}"; exit 1; }
PYTHON_VERSION=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_VERSION" -lt 10 ]; then
    echo -e "${RED}Se requiere Python 3.10+. Versión actual: 3.${PYTHON_VERSION}${RESET}"
    exit 1
fi
echo -e "${GREEN}✓ Python OK${RESET}"

# ── 2. Instalar dependencias Python ───────────────────────────────────────────
echo -e "\n${BOLD}[2/6] Instalando dependencias Python...${RESET}"
pip3 install -r "${REPO_DIR}/requirements.txt" --break-system-packages -q \
    || pip3 install -r "${REPO_DIR}/requirements.txt" -q \
    || { echo -e "${RED}pip install falló. Intenta manualmente: pip3 install -r requirements.txt${RESET}"; exit 1; }
echo -e "${GREEN}✓ Dependencias instaladas${RESET}"

# ── 3. Configurar .env ────────────────────────────────────────────────────────
echo -e "\n${BOLD}[3/6] Configurando entorno...${RESET}"
if [ ! -f "${REPO_DIR}/.env" ]; then
    cp "${REPO_DIR}/.env.example" "${REPO_DIR}/.env"
    echo -e "${YELLOW}  → .env creado desde .env.example${RESET}"
    echo -e "${YELLOW}  → Edita ${REPO_DIR}/.env para configurar LLM_BACKEND${RESET}"
else
    echo -e "${GREEN}  → .env ya existe, no se sobreescribe${RESET}"
fi

# ── 4. Instalar EIL skill en Claude Code ──────────────────────────────────────
echo -e "\n${BOLD}[4/6] Instalando skill EIL en Claude Code...${RESET}"
SKILLS_DIR="${HOME}/.claude/skills/dfirllama-eil"
mkdir -p "${SKILLS_DIR}"
cp "${REPO_DIR}/skills/dfirllama-eil/SKILL.md" "${SKILLS_DIR}/SKILL.md"
echo -e "${GREEN}✓ EIL SKILL.md instalado en ${SKILLS_DIR}${RESET}"

# ── 5. Registrar MCP en settings.json ─────────────────────────────────────────
echo -e "\n${BOLD}[5/6] Registrando servidor MCP en Claude Code...${RESET}"
SETTINGS="${HOME}/.claude/settings.json"
SERVER_PATH="${REPO_DIR}/server.py"

if [ ! -f "${SETTINGS}" ]; then
    # Crear settings.json desde cero
    cat > "${SETTINGS}" << EOF
{
  "mcpServers": {
    "dfirllama-sift": {
      "command": "python3",
      "args": ["${SERVER_PATH}"],
      "env": {
        "LLM_BACKEND": "auto",
        "EVIDENCE_ROOT": "/cases",
        "AUDIT_LOG": "/tmp/dfirllama_audit.log"
      }
    }
  }
}
EOF
    echo -e "${GREEN}✓ settings.json creado con MCP registrado${RESET}"
else
    # Verificar si ya está registrado
    if grep -q "dfirllama-sift" "${SETTINGS}" 2>/dev/null; then
        echo -e "${GREEN}✓ MCP dfirllama-sift ya registrado en settings.json${RESET}"
    else
        echo -e "${YELLOW}  → settings.json existe pero no tiene dfirllama-sift${RESET}"
        echo -e "${YELLOW}  → Agrega manualmente esta sección a ${SETTINGS}:${RESET}"
        echo -e ""
        cat << EOF
  "mcpServers": {
    "dfirllama-sift": {
      "command": "python3",
      "args": ["${SERVER_PATH}"],
      "env": {
        "LLM_BACKEND": "auto",
        "EVIDENCE_ROOT": "/cases",
        "AUDIT_LOG": "/tmp/dfirllama_audit.log"
      }
    }
  }
EOF
    fi
fi

# ── 6. Verificar instalación ──────────────────────────────────────────────────
echo -e "\n${BOLD}[6/6] Verificando instalación...${RESET}"
cd "${REPO_DIR}"

python3 -c "
import sys
sys.path.insert(0, '.')
errors = []
for mod in ['server','agent','webui','guardrails',
            'tools.nlsql','tools.validator','tools.ioc_tools',
            'llm.client','benchmark.ground_truth']:
    try:
        __import__(mod)
        print(f'  ✓ {mod}')
    except Exception as e:
        errors.append(f'  ✗ {mod}: {e}')
        print(f'  ✗ {mod}: {e}')
if errors:
    print(f'\n{len(errors)} errores de importación')
    sys.exit(1)
else:
    print(f'\n  Todos los módulos OK')
"

# Benchmark de verificación
echo -e "\n${BOLD}Corriendo benchmark de verificación...${RESET}"
python3 benchmark/run_benchmark.py --dry-run --db demo/data/tslsm_demo.db 2>&1 | \
    grep -E "Correctas|F1|Alucinaciones|ERROR" | head -5

echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   DFIRLlama-SIFT instalado correctamente ✓      ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo -e ""
echo -e "${BOLD}Uso rápido:${RESET}"
echo -e "  ${CYAN}Modo 1 (Claude Code):${RESET}  cd /cases/MI-CASO && claude"
echo -e "  ${CYAN}Modo 2 (Standalone):${RESET}   python3 ${REPO_DIR}/agent.py /cases/MI-CASO"
echo -e "  ${CYAN}Modo 3 (Web UI):${RESET}        python3 ${REPO_DIR}/webui.py"
echo -e "  ${CYAN}Demo inmediata:${RESET}         python3 ${REPO_DIR}/agent.py demo/data --demo"
echo -e ""
echo -e "${YELLOW}Recuerda editar ${REPO_DIR}/.env para configurar tu backend LLM${RESET}\n"
