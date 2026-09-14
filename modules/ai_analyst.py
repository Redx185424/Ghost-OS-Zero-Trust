"""
AI Risk Analyst
-----------------
Feeds recon/OSINT/score findings to an LLM for a plain-English risk
summary and prioritized recommendations. Uses modules/llm_provider.py
for the actual Groq/Claude call — this file just owns the prompt and
the honest rule-based fallback.

We never fake AI output. The response always includes a `source` field
so you know exactly which mode produced a given summary.
"""

from modules.llm_provider import call_llm, LLMUnavailable

SYSTEM_PROMPT = (
    "You are a security analyst producing a short risk summary from scan/OSINT "
    "findings. Write 3-5 plain-English sentences, then a prioritized bullet list "
    "of concrete fixes. Be concise and specific — no filler."
)


def _rule_based_summary(findings: dict) -> str:
    lines = []
    open_ports = findings.get("open_ports", [])
    unexpected = [p for p in open_ports if p not in (80, 443)]
    if unexpected:
        lines.append(f"- {len(unexpected)} non-standard port(s) open ({', '.join(map(str, unexpected))}). "
                      "Review whether these services need to be internet-facing.")
    headers = findings.get("headers_checked", {})
    missing = [h for h, v in headers.items() if v == "MISSING"]
    if missing:
        lines.append(f"- Missing {len(missing)} standard security header(s): {', '.join(missing)}. "
                      "These are low-effort, high-value fixes.")
    tls = findings.get("tls", {})
    if isinstance(tls, dict) and tls.get("error"):
        lines.append(f"- TLS handshake failed: {tls['error']}. Verify certificate validity and chain.")
    if not lines:
        lines.append("- No significant findings in the supplied data. Run recon and the header_analyzer "
                      "plugin against a target for a fuller picture.")
    return "Rule-based summary (no GROQ_API_KEY or ANTHROPIC_API_KEY configured):\n" + "\n".join(lines)


def generate_risk_summary(findings: dict) -> dict:
    import json
    try:
        result = call_llm(
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Findings:\n{json.dumps(findings, indent=2)}"}],
        )
        return {"source": result["source"], "summary": result["text"]}
    except LLMUnavailable as e:
        source = "rule-based (no provider configured)" if not e.attempted else f"rule-based (provider call failed: {e.attempted})"
        return {"source": source, "summary": _rule_based_summary(findings)}
