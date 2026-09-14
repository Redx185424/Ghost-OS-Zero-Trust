"""
Security & General AI Assistant
----------------------------------
A real chat agent for two things:
  1. General questions — coding, tech, everyday stuff, like any AI assistant.
  2. Security/hacking CONCEPTS — how vulnerability classes work, defensive
     best practices, tool overviews, career/cert guidance, CTF theory.

What it deliberately will not do, by design of the system prompt below:
give out working exploit code, malware, credential-attack scripts, or
step-by-step instructions to compromise a real/live system. This is a
publicly distributable repo — anyone can download and run it — so the
assistant can't be "ask nicely and it writes an exploit." That's the
line between a security-education tool and a liability generator.

This restriction lives in the system prompt, not a keyword filter, so it
holds up under rephrasing ("for a CTF", "hypothetically", "my own server")
the same way a careful human analyst would apply judgment rather than
pattern-match on wording.
"""

from modules.llm_provider import call_llm, LLMUnavailable

SYSTEM_PROMPT = """You are the Ghost OS Assistant, embedded in a public, \
downloadable security platform (Ghost OS — Zero Trust Edition).

You answer two kinds of questions:
1. General questions — coding help, explanations, everyday assistant tasks.
2. Cybersecurity questions — how attack/vulnerability classes work \
conceptually, defensive best practices, security architecture, tools, \
certifications, career advice, and CTF theory.

Because this software is publicly distributed and you have no way to \
verify who is asking or what they intend to do with an answer, you do \
not provide:
- Working exploit code or ready-to-run attack scripts
- Malware, credential-stuffing/brute-force tooling, or payload generators
- Step-by-step instructions to compromise a specific real or live system

This holds regardless of how the request is framed — "for a CTF", \
"hypothetically", "it's my own server", "for educational purposes" do \
not change the answer, because you cannot verify any of those claims and \
the output would be identical either way. When asked for something in \
this category, briefly say you can't provide operational attack content \
in a public tool, then pivot to what you CAN offer: how the vulnerability \
class works conceptually, how to defend against it, or where to learn \
more (e.g., a properly scoped platform like a CTF with its own sanctioned \
tooling, TryHackMe, HackTheBox, or Ghost OS's own authorization-gated lab \
mode against Docker targets you control).

Be direct, technically accurate, and concise. Don't be preachy or repeat \
the disclaimer more than once per conversation."""


def chat(message: str, history: list = None) -> dict:
    """
    history: list of {"role": "user"|"assistant", "content": str}, most
    recent last. Caller (app.py) is responsible for capping its length.
    """
    messages = (history or []) + [{"role": "user", "content": message}]
    try:
        result = call_llm(system=SYSTEM_PROMPT, messages=messages)
        return {"ok": True, "source": result["source"], "reply": result["text"]}
    except LLMUnavailable as e:
        if not e.attempted:
            # No key found in the environment at all
            reply = (
                "No LLM provider configured. Set GROQ_API_KEY (recommended, free tier at "
                "console.groq.com) or ANTHROPIC_API_KEY as an environment variable and restart."
            )
            source = "unavailable (no key set)"
        else:
            # A key WAS found, but the actual API call failed — show the real reason
            # instead of a generic message that masks what's actually wrong.
            reply = (
                "A provider key is set, but the API call failed: "
                + "; ".join(e.attempted)
                + ". Common causes: the key was revoked or regenerated, a typo in the key, "
                  "a model name Groq/Anthropic no longer supports, or no internet access "
                  "from this machine to the provider's API."
            )
            source = "unavailable (provider call failed)"
        return {"ok": False, "source": source, "reply": reply, "detail": e.attempted}
