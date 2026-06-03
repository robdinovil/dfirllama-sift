#!/usr/bin/env python3
"""
DFIRLlama-SIFT — Pre-flight check script.
Verifies that all dependencies, tools, and configurations are in place
before running the system on SIFT Workstation.

Usage: python3 setup_check.py
"""
import sys, os, subprocess, importlib
from pathlib import Path

CYAN  = "\033[96m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
BOLD  = "\033[1m"
RESET = "\033[0m"

REPO = Path(__file__).parent
PASS = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
WARN = f"{YELLOW}⚠{RESET}"

errors = []
warnings = []


def check(label, fn):
    try:
        result = fn()
        if result is True or result is None:
            print(f"  {PASS} {label}")
        elif result is False:
            print(f"  {FAIL} {label}")
            errors.append(label)
        else:
            print(f"  {WARN} {label}: {result}")
            warnings.append(label)
    except Exception as e:
        print(f"  {FAIL} {label}: {e}")
        errors.append(label)


# ── Python ──────────────────────────────────────────────────────────────────
print(f"\n{BOLD}[1] Python version{RESET}")
check("Python 3.10+", lambda: sys.version_info >= (3, 10))

# ── Python packages ──────────────────────────────────────────────────────────
print(f"\n{BOLD}[2] Python packages{RESET}")
REQUIRED_PACKAGES = [
    ("fastmcp", "fastmcp"),
    ("mcp", "mcp"),
    ("anthropic", "anthropic"),
    ("openai", "openai"),
    ("pandas", "pandas"),
    ("requests", "requests"),
    ("flask", "flask"),
]
for label, mod in REQUIRED_PACKAGES:
    check(label, lambda m=mod: importlib.import_module(m) and True)

# Optional
OPTIONAL_PACKAGES = [("vanna", "vanna"), ("yara", "yara"), ("whois", "whois")]
for label, mod in OPTIONAL_PACKAGES:
    try:
        importlib.import_module(mod)
        print(f"  {PASS} {label} (optional)")
    except ImportError:
        print(f"  {WARN} {label} (optional — not installed)")
        warnings.append(f"{label} optional")

# ── SIFT tools ───────────────────────────────────────────────────────────────
print(f"\n{BOLD}[3] SIFT tools{RESET}")

def cmd_exists(cmd):
    r = subprocess.run(["which", cmd], capture_output=True)
    return r.returncode == 0

check("fls (Sleuth Kit)",        lambda: cmd_exists("fls"))
check("log2timeline.py (Plaso)", lambda: cmd_exists("log2timeline.py"))
check("Volatility 3",            lambda: Path("/opt/volatility3/bin/vol").exists() or Path("/opt/volatility3-2.20.0/vol.py").exists())
check("EvtxECmd (Zimmerman)",    lambda: Path("/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll").exists())
def _check_yara():
    if cmd_exists("yara"):
        return True
    try:
        import yara
        return True
    except ImportError:
        return False
check("YARA",                    _check_yara)
check("bulk_extractor",          lambda: cmd_exists("bulk_extractor"))
check("dotnet runtime",          lambda: cmd_exists("dotnet"))

# ── LLM backend ──────────────────────────────────────────────────────────────
print(f"\n{BOLD}[4] LLM backend{RESET}")

def check_claude_cli():
    r = subprocess.run(["claude", "-p", "ok"], capture_output=True, text=True, timeout=15)
    return r.returncode == 0

def check_ollama():
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
        return True
    except Exception:
        return False

claude_ok = False
try:
    claude_ok = check_claude_cli()
    check("claude-cli (Claude Code)", lambda: claude_ok)
except Exception:
    print(f"  {WARN} claude-cli not responding")
    warnings.append("claude-cli")

ollama_ok = check_ollama()
if ollama_ok:
    print(f"  {PASS} ollama (localhost:11434)")
else:
    print(f"  {WARN} ollama not running (optional if claude-cli works)")

if not claude_ok and not ollama_ok:
    print(f"  {FAIL} No LLM backend available — set LLM_BACKEND and configure credentials")
    errors.append("No LLM backend")

# ── Project files ─────────────────────────────────────────────────────────────
print(f"\n{BOLD}[5] Project files{RESET}")
REQUIRED_FILES = [
    "server.py", "agent.py", "guardrails.py", "llm/client.py",
    "tools/nlsql.py", "tools/validator.py", "tools/ioc_tools.py",
    "benchmark/ground_truth.py", "benchmark/run_benchmark.py",
    "demo/data/tslsm_demo.db", "skills/dfirllama-eil/SKILL.md",
]
for f in REQUIRED_FILES:
    check(f, lambda fp=f: (REPO / fp).exists())

REAL_DATA = "demo/real_data/real_attack.db"
if (REPO / REAL_DATA).exists():
    print(f"  {PASS} {REAL_DATA} (real attack dataset)")
else:
    print(f"  {WARN} {REAL_DATA} missing — run: python3 demo/generate_demo_data.py --real")
    warnings.append("real_attack.db missing")

# ── MCP registration ──────────────────────────────────────────────────────────
print(f"\n{BOLD}[6] MCP registration{RESET}")
settings = Path.home() / ".claude" / "settings.json"
if settings.exists():
    import json
    s = json.loads(settings.read_text())
    registered = "dfirllama-sift" in s.get("mcpServers", {})
    check("dfirllama-sift in ~/.claude/settings.json", lambda: registered)
else:
    print(f"  {WARN} ~/.claude/settings.json not found — run setup.sh")
    warnings.append("settings.json")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'='*50}")
if errors:
    print(f"{RED}{BOLD}FAILED: {len(errors)} error(s){RESET}")
    for e in errors:
        print(f"  {FAIL} {e}")
    sys.exit(1)
elif warnings:
    print(f"{YELLOW}{BOLD}READY WITH WARNINGS: {len(warnings)} warning(s){RESET}")
    for w in warnings:
        print(f"  {WARN} {w}")
    print(f"\n{GREEN}System is functional. Warnings are non-blocking.{RESET}")
else:
    print(f"{GREEN}{BOLD}ALL CHECKS PASSED — DFIRLlama-SIFT ready to run{RESET}")
