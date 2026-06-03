"""
LLM client unificado — tres backends, mismo interface.

Prioridad automática:
  1. claude-cli  — claude -p (usa credenciales de Claude Code, sin API key extra)
  2. claude-api  — Anthropic SDK (si ANTHROPIC_API_KEY está en el entorno)
  3. ollama      — Ollama local (si OLLAMA_BASE_URL responde)

Controlado por LLM_BACKEND=auto|claude-cli|claude-api|ollama
"""

import json
import os
import re
import subprocess
from openai import OpenAI

LLM_BACKEND   = os.getenv("LLM_BACKEND", "auto")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_URL    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL",    "mistral:7b")
CLAUDE_MODEL  = os.getenv("CLAUDE_MODEL",    "claude-haiku-4-5-20251001")
CLAUDE_CLI    = os.getenv("CLAUDE_CLI_PATH", "claude")


def _detect_backend() -> str:
    """Detecta el mejor backend disponible automáticamente."""
    if LLM_BACKEND != "auto":
        return LLM_BACKEND

    # 1. Claude CLI — siempre disponible si Claude Code está instalado
    try:
        result = subprocess.run(
            [CLAUDE_CLI, "-p", "ok"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            return "claude-cli"
    except Exception:
        pass

    # 2. Anthropic SDK con API key explícita
    if ANTHROPIC_KEY:
        return "claude-api"

    # 3. Ollama
    return "ollama"


_BACKEND = None


def _get_backend() -> str:
    global _BACKEND
    if _BACKEND is None:
        _BACKEND = _detect_backend()
    return _BACKEND


def get_model_name() -> str:
    b = _get_backend()
    if b in ("claude-cli", "claude-api"):
        return CLAUDE_MODEL
    return OLLAMA_MODEL


def chat_completion(messages: list[dict], temperature: float = 0.1,
                    response_json: bool = False, max_tokens: int = 4096) -> str:
    """
    Llamada de chat unificada. Retorna el string de texto de la respuesta.
    Detecta automáticamente el mejor backend disponible.
    """
    backend = _get_backend()

    if backend == "claude-cli":
        return _chat_claude_cli(messages, response_json)
    elif backend == "claude-api":
        return _chat_claude_api(messages, temperature, response_json, max_tokens)
    else:
        return _chat_ollama(messages, temperature, response_json, max_tokens)


# ── Claude CLI backend ────────────────────────────────────────────────────────

def _chat_claude_cli(messages: list[dict], response_json: bool = False) -> str:
    """Usa `claude -p` para hacer llamadas LLM sin API key adicional."""
    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    user_parts   = [m["content"] for m in messages if m["role"] == "user"]

    system_text = "\n\n".join(system_parts) if system_parts else None
    user_text   = "\n\n".join(user_parts)   if user_parts  else ""

    if response_json:
        json_instruction = "\n\nResponde ÚNICAMENTE con JSON válido, sin texto adicional, sin markdown, sin ```json."
        if system_text:
            system_text += json_instruction
        else:
            system_text = "Eres un asistente de análisis forense." + json_instruction

    cmd = [CLAUDE_CLI, "-p", user_text]
    if system_text:
        cmd += ["--system-prompt", system_text]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout.strip()

        if response_json:
            output = _extract_json(output)

        return output

    except subprocess.TimeoutExpired:
        return '{"error": "claude-cli timeout"}'
    except Exception as e:
        return f'{{"error": "claude-cli error: {str(e)[:100]}"}}'


def _extract_json(text: str) -> str:
    """Extrae JSON de una respuesta que puede tener markdown o texto extra."""
    # Quitar bloques de código markdown
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*",     "", text)
    text = text.strip()

    # Intentar parsear directamente
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass

    # Buscar el primer { ... } o [ ... ] del texto
    for start_char, end_char in [('{', '}'), ('[', ']')]:
        start = text.find(start_char)
        if start != -1:
            # Encontrar el cierre correspondiente
            depth = 0
            for i, ch in enumerate(text[start:], start):
                if ch == start_char:
                    depth += 1
                elif ch == end_char:
                    depth -= 1
                    if depth == 0:
                        candidate = text[start:i+1]
                        try:
                            json.loads(candidate)
                            return candidate
                        except json.JSONDecodeError:
                            break

    return text  # devolver tal cual si no se puede limpiar


# ── Claude API backend ────────────────────────────────────────────────────────

def _chat_claude_api(messages: list[dict], temperature: float,
                     response_json: bool, max_tokens: int) -> str:
    """Usa el Anthropic SDK con API key explícita."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

        system_msgs = [m["content"] for m in messages if m["role"] == "system"]
        user_msgs   = [m for m in messages if m["role"] != "system"]
        system_text = "\n\n".join(system_msgs) if system_msgs else None

        if response_json:
            suffix = "\n\nResponde ÚNICAMENTE con JSON válido."
            system_text = (system_text or "") + suffix

        kwargs: dict = dict(
            model=CLAUDE_MODEL, max_tokens=max_tokens,
            messages=user_msgs, temperature=temperature,
        )
        if system_text:
            kwargs["system"] = system_text

        resp = client.messages.create(**kwargs)
        return resp.content[0].text

    except Exception as e:
        return f'{{"error": "claude-api: {str(e)[:100]}"}}'


# ── Ollama backend ────────────────────────────────────────────────────────────

def _chat_ollama(messages: list[dict], temperature: float,
                 response_json: bool, max_tokens: int) -> str:
    """Usa Ollama via cliente OpenAI-compatible."""
    try:
        client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")
        kwargs: dict = dict(
            model=OLLAMA_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if response_json:
            kwargs["response_format"] = {"type": "json_object"}

        resp = client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""

    except Exception as e:
        return f'{{"error": "ollama: {str(e)[:100]}"}}'
