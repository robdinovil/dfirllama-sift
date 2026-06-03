# Execution Log Schema

DFIRLlama-SIFT logs every tool invocation to a structured JSONL file at `$AUDIT_LOG` (default: `/tmp/dfirllama_audit.log`).

## Schema

```json
{
  "ts_utc":        "2026-06-03T08:15:22.134Z",
  "phase":         "INTERROGATE",
  "tool":          "query_forensic_db",
  "status":        "ok",
  "args_redacted": {
    "db_path":  "analysis/case.sqlite",
    "question": "Were there failed logons followed by a successful logon?"
  },
  "duration_ms":   1280,
  "token_usage":   {
    "input_tokens":  1234,
    "output_tokens": 321
  },
  "output_summary": "12 rows returned: EID 4625 at 03:17:41 → EID 4624 at 03:18:02",
  "output_hash":    "sha256:a3f8b2c19d4e",
  "finding_ids":    ["F-001", "F-002"]
}
```

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `ts_utc` | ISO 8601 string | UTC timestamp of tool execution |
| `phase` | string | EIL phase: `SCOPE`, `INTERROGATE`, `CORRELATE`, `VALIDATE`, `SELF_CORRECT`, `REPORT`, or `TOOL` |
| `tool` | string | MCP tool name as registered in `server.py` |
| `status` | string | `ok` or `error` |
| `args_redacted` | object | Tool arguments truncated to 200 chars each (no raw evidence paths) |
| `duration_ms` | int | Execution time in milliseconds |
| `token_usage` | object | `input_tokens` and `output_tokens` consumed (0 if not applicable) |
| `output_summary` | string | First 300 chars of tool output |
| `output_hash` | string | SHA-256 prefix of full output for integrity tracing |
| `finding_ids` | array | Finding IDs created or updated by this tool call |

## Traceability

Every finding in the IR report has a `finding_id` (e.g., `F-001`). The audit log allows tracing any finding back to the specific tool call that produced it via `finding_ids`.

## Example: Reading the Log

```bash
# Show all VALIDATE phase calls
cat /tmp/dfirllama_audit.log | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e.get('phase') == 'VALIDATE':
        print(e['ts_utc'], e['tool'], e['status'])
"

# Show all self-correction triggers
cat /tmp/dfirllama_audit.log | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e.get('phase') == 'SELF_CORRECT':
        print(json.dumps(e, indent=2))
"
```
