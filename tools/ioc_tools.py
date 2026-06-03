"""
IOC tools — análisis de indicadores de compromiso.

analyze_ioc:   ReAct agent — investiga una IP, dominio, hash o URL
extract_iocs:  structured output — extrae IOCs de texto libre
"""
import base64
import json
import os
import requests
from guardrails import audit
from llm.client import chat_completion

IPSUM_FILE = os.getenv("IPSUM_FILE", "/tmp/ipsum.txt")


# ── Herramientas del agente ───────────────────────────────────────────────────

def _decode_base64(b64: str) -> str:
    try:
        return base64.b64decode(b64.strip("'\"")).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"


def _domain_whois(domain: str) -> dict:
    try:
        import whois as w
        d = w.whois(domain)
        return {
            "registrar": str(d.registrar),
            "creation_date": str(d.creation_date),
            "expiration_date": str(d.expiration_date),
            "name_servers": str(d.name_servers),
        }
    except Exception as e:
        return {"error": str(e)}


def _dns_resolve(domain: str) -> list[str]:
    try:
        if "://" in domain:
            domain = domain.split("://")[1].split("/")[0]
        domain = domain.strip("/").split("/")[0]
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=10)
        return [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []


def _geoip(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        d = r.json()
        return {"country": d.get("country"), "org": d.get("org"), "city": d.get("city")}
    except Exception as e:
        return {"error": str(e)}


def _threat_check(ip: str) -> dict:
    try:
        with open(IPSUM_FILE) as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == ip:
                        return {"in_blocklist": True, "score": int(parts[1])}
        return {"in_blocklist": False, "score": 0}
    except FileNotFoundError:
        return {"in_blocklist": False, "score": 0, "note": "ipsum.txt not found"}


TOOLS_MAP = {
    "decode_base64":     lambda args: _decode_base64(args.get("b64_string", "")),
    "domain_whois":      lambda args: json.dumps(_domain_whois(args.get("domain", ""))),
    "dns_resolve":       lambda args: json.dumps({"ips": _dns_resolve(args.get("domain", ""))}),
    "geoip_lookup":      lambda args: json.dumps(_geoip(args.get("ip", ""))),
    "threat_list_check": lambda args: json.dumps(_threat_check(args.get("ip", ""))),
}

TOOLS_SCHEMA = [
    {"type": "function", "function": {
        "name": "decode_base64",
        "description": "Decode a Base64-encoded string. Use when you see base64 in commands or traffic.",
        "parameters": {"type": "object", "properties": {"b64_string": {"type": "string"}}, "required": ["b64_string"]},
    }},
    {"type": "function", "function": {
        "name": "domain_whois",
        "description": "WHOIS lookup for a domain — registrar, creation date, name servers.",
        "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
    }},
    {"type": "function", "function": {
        "name": "dns_resolve",
        "description": "Resolve a domain to IP addresses via Google DNS-over-HTTPS.",
        "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
    }},
    {"type": "function", "function": {
        "name": "geoip_lookup",
        "description": "Get country, city, and ASN for an IP address.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
    }},
    {"type": "function", "function": {
        "name": "threat_list_check",
        "description": "Check if an IP is in the IPSum threat intelligence blocklist (30+ sources).",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
    }},
]


# ── Tool 1: analyze_ioc ───────────────────────────────────────────────────────

def analyze_ioc(ioc_value: str, ioc_type: str = "auto") -> dict:
    """
    Analiza un IOC (IP, dominio, URL, hash, PowerShell) usando un agente ReAct.
    El agente decide autónomamente qué herramientas usar y en qué orden.
    Usa el backend LLM configurado (claude-cli, claude-api, u ollama).

    Args:
        ioc_value: El valor a analizar (IP, dominio, URL, comando PowerShell, hash SHA256)
        ioc_type:  Tipo de IOC: "ip", "domain", "url", "hash", "powershell", "auto"
    """
    audit("analyze_ioc", {"ioc_value": ioc_value[:100], "ioc_type": ioc_type})

    from llm.client import _get_backend, OLLAMA_URL, OLLAMA_MODEL, ANTHROPIC_KEY, CLAUDE_MODEL

    backend = _get_backend()

    # Function calling nativo requiere API OpenAI-compatible.
    # claude-cli no lo soporta → usamos loop manual con chat_completion.
    if backend == "claude-cli":
        return _analyze_ioc_manual(ioc_value, ioc_type)

    # claude-api u ollama → function calling nativo
    from openai import OpenAI
    if backend == "claude-api":
        # Anthropic SDK vía endpoint OpenAI-compatible no soporta tools de igual forma;
        # usamos loop manual para consistencia
        return _analyze_ioc_manual(ioc_value, ioc_type)

    # Ollama — function calling nativo
    client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")
    model  = OLLAMA_MODEL

    messages = [
        {"role": "system", "content": (
            "You are a senior DFIR analyst. Analyze the given IOC using your tools. "
            "Decode base64 first if present, then investigate domains/IPs. "
            "Provide a final verdict: classification (malicious/suspicious/benign), "
            "confidence (high/medium/low), key findings, recommended actions."
        )},
        {"role": "user", "content": f"Analyze this IOC:\n\n{ioc_value}"},
    ]

    iterations, tool_calls_log = 0, []

    while iterations < 8:
        iterations += 1
        resp   = client.chat.completions.create(
            model=model, messages=messages,
            tools=TOOLS_SCHEMA, tool_choice="auto", temperature=0.1,
        )
        msg    = resp.choices[0].message
        reason = resp.choices[0].finish_reason

        if msg.content:
            messages.append({"role": "assistant", "content": msg.content,
                              "tool_calls": msg.tool_calls})

        if reason == "tool_calls" and msg.tool_calls:
            for tc in msg.tool_calls:
                args   = json.loads(tc.function.arguments)
                result = TOOLS_MAP.get(tc.function.name,
                                       lambda _: '{"error":"unknown tool"}')(args)
                tool_calls_log.append({"tool": tc.function.name, "args": args,
                                       "result": str(result)[:300]})
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                  "content": str(result)})
        elif reason == "stop":
            return {"ok": True, "ioc": ioc_value[:200], "verdict": msg.content,
                    "tool_calls": tool_calls_log, "iterations": iterations}

    return {"ok": False, "error": "Max iterations reached", "tool_calls": tool_calls_log}


def _analyze_ioc_manual(ioc_value: str, ioc_type: str) -> dict:
    """
    ReAct loop manual para backends que no soportan function calling nativo
    (claude-cli, claude-api). El LLM razona en texto y nosotros parseamos
    la acción — más transparente para demos.
    """
    from llm.client import chat_completion

    system = (
        "You are a senior DFIR analyst investigating an IOC. "
        "Reason step by step using this format EXACTLY:\n\n"
        "Thought: <your reasoning>\n"
        "Action: <tool_name>\n"
        "Action Input: <JSON args>\n\n"
        "Available tools:\n"
        "- decode_base64({\"b64_string\": \"...\"})\n"
        "- domain_whois({\"domain\": \"...\"})\n"
        "- dns_resolve({\"domain\": \"...\"})\n"
        "- geoip_lookup({\"ip\": \"...\"})\n"
        "- threat_list_check({\"ip\": \"...\"})\n\n"
        "When done, write:\n"
        "Final Answer: <verdict with classification, confidence, findings, actions>"
    )

    messages = [
        {"role": "system", "content": system},
        {"role": "user",   "content": f"Investigate this IOC: {ioc_value}"},
    ]

    iterations, tool_calls_log = 0, []

    while iterations < 8:
        iterations += 1
        response = chat_completion(messages, temperature=0.1)
        messages.append({"role": "assistant", "content": response})

        if "Final Answer:" in response:
            verdict = response.split("Final Answer:")[-1].strip()
            return {"ok": True, "ioc": ioc_value[:200], "verdict": verdict,
                    "tool_calls": tool_calls_log, "iterations": iterations,
                    "mode": "manual_react"}

        # Parsear Action / Action Input
        action = _parse_action(response)
        if action:
            tool_name, args = action
            result = TOOLS_MAP.get(tool_name, lambda _: '{"error":"unknown tool"}')(args)
            tool_calls_log.append({"tool": tool_name, "args": args,
                                   "result": str(result)[:300]})
            messages.append({"role": "user",
                              "content": f"Observation: {result}\n\nContinue your analysis."})

    return {"ok": False, "error": "Max iterations", "tool_calls": tool_calls_log}


def _parse_action(text: str) -> tuple[str, dict] | None:
    """Extrae Action y Action Input del texto ReAct."""
    import re
    action_match = re.search(r"Action:\s*(\w+)", text)
    input_match  = re.search(r"Action Input:\s*(\{.*?\})", text, re.DOTALL)
    if not action_match:
        return None
    tool_name = action_match.group(1).strip()
    try:
        args = json.loads(input_match.group(1)) if input_match else {}
    except json.JSONDecodeError:
        args = {}
    return tool_name, args


# ── Tool 2: extract_iocs ─────────────────────────────────────────────────────

IOC_SCHEMA = {
    "type": "object",
    "properties": {
        "iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ioc_type":       {"type": "string", "enum": ["ip","domain","url","hash_sha256","hash_md5","email","registry_key","filename"]},
                    "ioc_value":      {"type": "string"},
                    "malware_family": {"type": "string"},
                    "confidence":     {"type": "string", "enum": ["high","medium","low"]},
                    "notes":          {"type": "string"},
                },
                "required": ["ioc_type", "ioc_value", "confidence"],
            }
        }
    },
    "required": ["iocs"],
}


def extract_iocs(text: str) -> dict:
    """
    Extrae todos los IOCs (IPs, dominios, URLs, hashes, claves de registro) de un texto.
    Usa structured output JSON para eliminar alucinaciones en campos clave.
    El output es importable directamente a MISP, TheHive, o Elastic SIEM.

    Args:
        text: Texto de un reporte de threat intelligence, alerta de EDR, o notas de triage.
    """
    audit("extract_iocs", {"text_len": len(text)})

    result_text = chat_completion(
        messages=[
            {"role": "system", "content": (
                "You are a threat intelligence analyst. Extract ALL indicators of compromise "
                "from the given text. Be exhaustive: IPs, domains, URLs, hashes, registry keys, "
                "filenames. Reply ONLY with valid JSON matching the schema provided."
            )},
            {"role": "user", "content": (
                f"Extract all IOCs from this text:\n\n{text}\n\n"
                f"Required JSON schema:\n{json.dumps(IOC_SCHEMA, indent=2)}"
            )},
        ],
        response_json=True,
        temperature=0.1,
    )

    try:
        result = json.loads(result_text)
        iocs   = result.get("iocs", [])
        return {"ok": True, "ioc_count": len(iocs), "iocs": iocs}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"JSON parse error: {e}", "raw": result_text[:500]}
