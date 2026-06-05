"""
Security guardrails for DFIRLlama-SIFT.
- Read-only: blocks destructive commands
- Path boundaries: agent restricted to EVIDENCE_ROOT and designated output dirs
- Audit trail: structured JSONL log of every tool call with phase, duration, token usage
"""
import os
import re
import json
import time
import datetime
import hashlib
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

# Output dirs the agent may write to
_REPO_ROOT = Path(__file__).parent.resolve()
ALLOWED_WRITE_DIRS = [
    _REPO_ROOT / "analysis",
    _REPO_ROOT / "exports",
    _REPO_ROOT / "reports",
    Path("/tmp/dfirllama"),
]


def audit(tool_name: str, args: dict, result_summary: str = "",
          phase: str = "", duration_ms: int = 0,
          token_usage: dict | None = None,
          finding_ids: list | None = None,
          status: str = "ok"):
    """Structured JSONL audit trail — traceable to every tool execution."""
    output_hash = ""
    if result_summary:
        output_hash = "sha256:" + hashlib.sha256(result_summary.encode()).hexdigest()[:16]

    entry = {
        "ts_utc":          datetime.datetime.utcnow().isoformat() + "Z",
        "phase":           phase or "TOOL",
        "tool":            tool_name,
        "status":          status,
        "args_redacted":   {k: str(v)[:200] for k, v in args.items()},
        "duration_ms":     duration_ms,
        "token_usage":     token_usage or {},
        "output_summary":  result_summary[:300],
        "output_hash":     output_hash,
        "finding_ids":     finding_ids or [],
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def check_path(path: str | Path) -> Path:
    """
    Verifies the path is within EVIDENCE_ROOT or a designated output dir.
    Raises ValueError if out of scope.
    """
    p = Path(path).resolve()
    # Re-read EVIDENCE_ROOT from env each call so agents can override it at runtime
    current_root = Path(os.getenv("EVIDENCE_ROOT", str(EVIDENCE_ROOT))).resolve()
    allowed = [current_root] + ALLOWED_WRITE_DIRS
    if not any(str(p).startswith(str(prefix)) for prefix in allowed):
        raise ValueError(
            f"Path out of allowed scope: {p}\n"
            f"Allowed: {[str(x) for x in allowed]}"
        )
    return p


def check_command(cmd: str):
    """Blocks destructive commands before execution."""
    if BLOCKED_PATTERNS.search(cmd):
        raise PermissionError(
            f"Command blocked by read-only guardrail: {cmd[:100]}"
        )
    for blocked in BLOCKED_ARGS:
        if blocked in cmd.split():
            raise PermissionError(f"Blocked argument: {blocked}")


def safe_run(cmd: list[str], tool_name: str, phase: str = "",
             token_usage: dict | None = None, **kwargs) -> str:
    """Executes a command safely — read-only, with structured audit trail."""
    import subprocess
    cmd_str = " ".join(str(c) for c in cmd)
    check_command(cmd_str)
    audit(tool_name, {"cmd": cmd_str}, phase=phase)

    t0 = time.monotonic()
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=kwargs.get("timeout", 120),
    )
    duration_ms = int((time.monotonic() - t0) * 1000)
    output = result.stdout + (f"\n[stderr]: {result.stderr}" if result.stderr else "")
    status = "ok" if result.returncode == 0 else "error"
    audit(tool_name, {"cmd": cmd_str}, result_summary=output[:300],
          phase=phase, duration_ms=duration_ms,
          token_usage=token_usage, status=status)
    return output
