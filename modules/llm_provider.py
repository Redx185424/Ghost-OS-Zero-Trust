"""
Shared LLM Provider
----------------------
One place for the Groq/Claude calling logic, used by both the AI Risk
Analyst (modules/ai_analyst.py) and the Security & General Assistant
(modules/assistant.py). Avoids duplicating provider/fallback logic.

Provider priority:
  1. Groq — set GROQ_API_KEY (free tier, fast)
  2. Anthropic — set ANTHROPIC_API_KEY (optional)
  3. None available — caller decides the fallback (each feature has its
     own honest non-AI fallback; this module never fakes a response)
"""

import os
import json
import urllib.request
import urllib.error

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile moved to Groq's Enterprise-only tier and is no
# longer reachable with standard/free-tier keys (returns 404 model_not_found).
# openai/gpt-oss-20b is fast, cheap, and available on the free developer tier.
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")


class LLMUnavailable(Exception):
    """Raised when no provider is configured or all configured providers failed."""
    def __init__(self, message, attempted=None):
        super().__init__(message)
        self.attempted = attempted or []


def _call_groq(system: str, messages: list) -> str:
    api_key = os.environ["GROQ_API_KEY"]
    full_messages = ([{"role": "system", "content": system}] if system else []) + messages
    body = json.dumps({
        "model": GROQ_MODEL,
        "max_tokens": 700,
        "messages": full_messages,
    }).encode("utf-8")

    req = urllib.request.Request(
        GROQ_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            # Some providers front their API with a WAF (Cloudflare, etc.) that
            # blocks the default Python urllib User-Agent as bot traffic,
            # producing a bare 403 with no useful error body. A normal-looking
            # UA avoids that class of false-positive block.
            "User-Agent": "GhostOS-ZeroTrust/1.0",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        data = json.loads(resp.read().decode())
        choices = data.get("choices", [])
        if not choices:
            return "(empty response from model)"
        return choices[0]["message"]["content"]


def _call_claude(system: str, messages: list) -> str:
    api_key = os.environ["ANTHROPIC_API_KEY"]
    # Anthropic's API takes system as a top-level field, not a message
    body = json.dumps({
        "model": ANTHROPIC_MODEL,
        "max_tokens": 700,
        **({"system": system} if system else {}),
        "messages": messages,
    }).encode("utf-8")

    req = urllib.request.Request(
        ANTHROPIC_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "User-Agent": "GhostOS-ZeroTrust/1.0",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        data = json.loads(resp.read().decode())
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        return "\n".join(text_blocks) if text_blocks else "(empty response from model)"


def _describe_error(provider: str, e: Exception) -> str:
    """
    Turn an exception into a diagnostic string that includes the actual
    response body when available (HTTPError bodies usually contain the
    real reason — invalid key, model not found, WAF block page, etc.)
    instead of just the bare status code.
    """
    if isinstance(e, urllib.error.HTTPError):
        try:
            body = e.read().decode(errors="ignore")[:300]
        except Exception:
            body = "(could not read response body)"
        return f"{provider}: HTTP {e.code} {e.reason} — {body}"
    return f"{provider}: {e}"


def call_llm(system: str, messages: list) -> dict:
    """
    Returns {"source": "groq (...)" | "claude (...)", "text": "..."} on success.
    Raises LLMUnavailable if no provider is configured or every configured
    provider's call failed — the caller is responsible for the non-AI
    fallback and must not claim AI output when this raises.
    """
    attempted = []

    if os.environ.get("GROQ_API_KEY"):
        try:
            text = _call_groq(system, messages)
            return {"source": f"groq ({GROQ_MODEL})", "text": text}
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError, ValueError) as e:
            attempted.append(_describe_error("groq", e))

    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            text = _call_claude(system, messages)
            return {"source": f"claude ({ANTHROPIC_MODEL})", "text": text}
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError, ValueError) as e:
            attempted.append(_describe_error("claude", e))

    if not attempted:
        raise LLMUnavailable("No provider configured — set GROQ_API_KEY or ANTHROPIC_API_KEY", attempted)
    raise LLMUnavailable("All configured providers failed", attempted)
