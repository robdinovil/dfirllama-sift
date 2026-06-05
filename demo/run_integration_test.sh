#!/bin/bash
# DFIRLlama-SIFT — Integration test
# Validates the full stack from a fresh clone perspective.
# Run from the repo root: bash demo/run_integration_test.sh

set -e

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

GREEN='\033[92m'; RED='\033[91m'; YELLOW='\033[93m'; BOLD='\033[1m'; RESET='\033[0m'

pass() { echo -e "${GREEN}${BOLD}[PASS]${RESET} $1"; }
fail() { echo -e "${RED}${BOLD}[FAIL]${RESET} $1"; exit 1; }
info() { echo -e "${YELLOW}$1${RESET}"; }

echo -e "${BOLD}DFIRLlama-SIFT — Integration Test${RESET}"
echo "Repo: $REPO"
echo "Date: $(date -u)"
echo "────────────────────────────────────────────────────"

# 1. Module imports
info "[1/7] Module imports..."
python3 -c "
import server, agent, webui, guardrails
from tools import nlsql, evtx_tools, ioc_tools, validator, zimmerman_tools, sift_tools, forensic_tools
from llm import client
print('ok')
" && pass "All modules import cleanly" || fail "Module import failed"

# 2. Guardrails tests
info "[2/7] Guardrails tests..."
python3 -m pytest tests/test_guardrails.py -q 2>&1 | tail -3
python3 -m pytest tests/test_guardrails.py -q --tb=no 2>&1 | grep -q "18 passed" && pass "18/18 guardrails tests pass" || fail "Guardrails tests failed"

# 3. Benchmark dry-run
info "[3/7] NL→SQL benchmark (dry-run)..."
result=$(python3 benchmark/run_benchmark.py --dry-run --db demo/data/tslsm_demo.db 2>&1)
echo "$result" | grep -q "20 (100" && pass "Benchmark 20/20 correct (F1=1.000)" || fail "Benchmark failed: $result"

# 4. NL→SQL live query
info "[4/7] NL→SQL live query on demo DB..."
python3 -c "
from tools.nlsql import query_nl
r = query_nl('demo/data/tslsm_demo.db', 'How many logon events from external IPs?')
assert r.get('ok'), f'query failed: {r}'
assert r.get('row_count',0) > 0, 'expected results, got 0 rows'
print(f'SQL: {r[\"sql\"][:80]}')
print(f'Rows: {r[\"row_count\"]}')
" && pass "NL→SQL live query returns results" || fail "NL→SQL live query failed"

# 5. IOC extraction
info "[5/7] IOC extraction with structured output..."
python3 -c "
from tools.ioc_tools import extract_iocs
r = extract_iocs('Malicious IP: 185.220.101.47. C2 domain: evil.example.com. Hash: a3f8b2c19d4e5f67890ab12cd34ef5678901234567890abcdef1234567890ab')
iocs = r.get('iocs', [])
types = {i['ioc_type'] for i in iocs}
assert 'ip' in types, f'Missing ip in {types}'
assert 'domain' in types, f'Missing domain in {types}'
assert 'hash_sha256' in types, f'Missing hash in {types}'
print(f'IOCs extracted: {len(iocs)} ({types})')
" && pass "IOC extraction returns ip, domain, hash" || fail "IOC extraction failed"

# 6. validate_findings with injected hallucination
info "[6/7] validate_findings (hallucination detection)..."
python3 -c "
from tools.validator import validate_findings
findings = [
    {'description': 'Real finding', 'ioc_type': 'ip', 'ioc_value': '53.58.75.69',
     'confidence': 'high', 'evidence_citation': 'EventId=21 RemoteHost=53.58.75.69'},
    {'description': 'Hallucinated finding', 'ioc_type': 'ip', 'ioc_value': '999.999.999.999',
     'confidence': 'high', 'evidence_citation': 'EventId=21 RemoteHost=999.999.999.999'},
]
r = validate_findings(findings, evidence_db='demo/data/tslsm_demo.db')
assert r.get('needs_correction') == True, 'expected needs_correction=True'
assert r.get('hallucination_score', 0) > 0, 'expected hallucination detected'
triggers = r.get('self_correction_triggers', [])
assert len(triggers) > 0, 'expected self_correction_trigger'
print(f'hallucination_score={r[\"hallucination_score\"]:.2f} triggers={len(triggers)}')
" && pass "Hallucination detected, needs_correction=True, trigger generated" || fail "validate_findings failed"

# 7. Agent demo run + output verification
info "[7/7] Agent end-to-end demo run (Phase 1-3 minimum)..."
OUTPUT_DIR="/tmp/dfirllama_integration_$(date +%s)"
timeout 180 python3 agent.py demo/data --demo --output "$OUTPUT_DIR" 2>/dev/null || true

MISSING=""
for f in evidence_manifest.json orient_results.json interrogate_findings.json; do
    if [ ! -f "$OUTPUT_DIR/$f" ]; then
        MISSING="$MISSING $f"
    fi
done

if [ -n "$MISSING" ]; then
    fail "Missing output files:$MISSING (check agent.py demo mode)"
fi

FINDINGS=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/interrogate_findings.json')); print(len(d))" 2>/dev/null || echo 0)
EVENTS=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/orient_results.json')); v=list(d.values()); print(v[0]['total_events'] if v else 0)" 2>/dev/null || echo 0)

pass "Output files generated: evidence_manifest.json, orient_results.json, interrogate_findings.json"
echo "      Events detected: $EVENTS | Findings: $FINDINGS"

echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ALL INTEGRATION TESTS PASSED${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo ""
echo "Output dir: $OUTPUT_DIR"
echo "Audit log:  /tmp/dfirllama_audit.log"
ls -lh "$OUTPUT_DIR/" 2>/dev/null
