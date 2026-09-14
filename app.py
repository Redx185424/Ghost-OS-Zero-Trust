"""
Ghost OS — Zero Trust Edition
----------------------------
A public-safe, authorization-gated security intelligence platform.

This edition intentionally does NOT include live exploit modules, payload
generation, or unrestricted target scanning. Every active action requires
explicit authorization and is restricted to the lab target allow-list.
See LEGAL.md for the acceptable-use policy.
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import uuid

# Load .env into the process environment before anything reads os.environ.
# Safe to call even if no .env file exists (it's a no-op in that case).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[ghost-os] python-dotenv not installed — .env file will be ignored. "
          "Run: pip install -r requirements.txt")

# Startup diagnostic — tells you immediately whether a key was actually
# picked up, instead of finding out three clicks later in the Assistant panel.
_groq_ok = bool(os.environ.get("GROQ_API_KEY"))
_anthropic_ok = bool(os.environ.get("ANTHROPIC_API_KEY"))
print(f"[ghost-os] GROQ_API_KEY loaded: {_groq_ok} | ANTHROPIC_API_KEY loaded: {_anthropic_ok}")
if not _groq_ok and not _anthropic_ok:
    print("[ghost-os] No LLM key found. Check that .env sits next to app.py and "
          "contains a line like: GROQ_API_KEY=gsk_...  (no quotes, no spaces around =)")

from modules.rbac import require_role, ROLES
from modules.audit import log_action, get_audit_log
from modules.auth_gate import (
    is_target_authorized,
    record_consent,
    has_active_consent,
    ALLOWLIST,
)
from modules.recon import run_recon
from modules.osint import run_osint
from modules.report import generate_report
from modules.plugin_loader import load_plugins
from modules.scoring import compute_score
from modules.ai_analyst import generate_risk_summary
from modules.defend import stream_events, inject_simulated_event
from modules.attack_surface import build_attack_surface
from modules.assistant import chat as assistant_chat

app = Flask(__name__)
app.secret_key = os.environ.get("GHOST_OS_SECRET", "dev-only-change-me")

PLUGINS = load_plugins()


# ---------------------------------------------------------------------------
# Session / role bootstrap (simple demo auth — swap for real auth in prod)
# ---------------------------------------------------------------------------
@app.before_request
def bootstrap_session():
    if "user_id" not in session:
        session["user_id"] = str(uuid.uuid4())[:8]
        session["role"] = "analyst"  # default role: analyst < lead < admin


# ---------------------------------------------------------------------------
# Core pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", role=session.get("role"), user=session.get("user_id"))


@app.route("/dashboard")
def dashboard():
    return render_template(
        "dashboard.html",
        role=session.get("role"),
        allowlist=ALLOWLIST,
        plugins=[p["name"] for p in PLUGINS],
    )


@app.route("/legal")
def legal():
    with open("LEGAL.md") as f:
        content = f.read()
    return render_template("legal.html", content=content)


# ---------------------------------------------------------------------------
# Authorization gate — MUST pass before any active module runs
# ---------------------------------------------------------------------------
@app.route("/api/consent", methods=["POST"])
def api_consent():
    data = request.json or {}
    target = data.get("target", "").strip()
    consent_text = data.get("consent_text", "").strip()

    if not is_target_authorized(target):
        log_action(session["user_id"], "consent_denied", target, "target not in allow-list")
        return jsonify({
            "ok": False,
            "reason": "Target is not on the lab allow-list. Ghost OS (Zero Trust "
                      "Edition) only operates against pre-approved lab/demo targets. See /legal."
        }), 403

    required_phrase = f"I AM AUTHORIZED TO TEST {target}"
    if consent_text.strip().upper() != required_phrase.upper():
        return jsonify({"ok": False, "reason": f'Type exactly: "{required_phrase}"'}), 400

    record_consent(session["user_id"], target)
    log_action(session["user_id"], "consent_granted", target, "explicit consent recorded")
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Passive OSINT — read-only, safe against any public domain
# ---------------------------------------------------------------------------
@app.route("/api/osint", methods=["POST"])
def api_osint():
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"ok": False, "reason": "target required"}), 400

    result = run_osint(target)
    log_action(session["user_id"], "osint_scan", target, "passive OSINT executed")
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------------------
# Active recon — requires prior consent + allow-listed target
# ---------------------------------------------------------------------------
@app.route("/api/recon", methods=["POST"])
def api_recon():
    data = request.json or {}
    target = data.get("target", "").strip()

    if not is_target_authorized(target):
        return jsonify({"ok": False, "reason": "target not on allow-list"}), 403
    if not has_active_consent(session["user_id"], target):
        return jsonify({"ok": False, "reason": "no active consent — POST /api/consent first"}), 403

    result = run_recon(target)
    log_action(session["user_id"], "active_recon", target, "recon module executed against lab target")
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------------------
# Plugins — auto-discovered, sandboxed, benign by contract (see plugins/README.md)
# ---------------------------------------------------------------------------
@app.route("/api/plugins")
def api_plugins():
    return jsonify({"plugins": [{"name": p["name"], "description": p["description"]} for p in PLUGINS]})


@app.route("/api/plugins/<name>/run", methods=["POST"])
def api_run_plugin(name):
    data = request.json or {}
    target = data.get("target", "").strip()
    plugin = next((p for p in PLUGINS if p["name"] == name), None)
    if not plugin:
        return jsonify({"ok": False, "reason": "plugin not found"}), 404

    if plugin.get("requires_target_auth") and not is_target_authorized(target):
        return jsonify({"ok": False, "reason": "target not on allow-list"}), 403

    result = plugin["run"](target)
    log_action(session["user_id"], f"plugin:{name}", target, "plugin executed")
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------------------
# Reporting — turns session activity into a client-style PDF/HTML report
# ---------------------------------------------------------------------------
@app.route("/api/report", methods=["POST"])
@require_role("lead")
def api_report():
    data = request.json or {}
    target = data.get("target", "").strip()
    findings = data.get("findings", {})
    path = generate_report(target, findings, analyst=session["user_id"])
    log_action(session["user_id"], "report_generated", target, path)
    return jsonify({"ok": True, "report_path": path})


# ---------------------------------------------------------------------------
# Audit trail — surfaced as a first-class feature, not an afterthought
# ---------------------------------------------------------------------------
@app.route("/api/audit")
@require_role("lead")
def api_audit():
    return jsonify({"log": get_audit_log()})


# ---------------------------------------------------------------------------
# RBAC demo endpoint — lets you flip role in the UI for the showcase
# ---------------------------------------------------------------------------
@app.route("/api/role", methods=["POST"])
def api_set_role():
    role = (request.json or {}).get("role", "analyst")
    if role not in ROLES:
        return jsonify({"ok": False, "reason": f"role must be one of {ROLES}"}), 400
    session["role"] = role
    return jsonify({"ok": True, "role": role})


# ---------------------------------------------------------------------------
# Zero Trust Score — grades findings A-F
# ---------------------------------------------------------------------------
@app.route("/api/score", methods=["POST"])
def api_score():
    findings = (request.json or {}).get("findings", {})
    result = compute_score(findings)
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------------------
# AI Risk Analyst — real Claude call if ANTHROPIC_API_KEY is set, else
# an honest rule-based summary (never fakes AI output)
# ---------------------------------------------------------------------------
@app.route("/api/ai-analysis", methods=["POST"])
def api_ai_analysis():
    findings = (request.json or {}).get("findings", {})
    result = generate_risk_summary(findings)
    log_action(session["user_id"], "ai_analysis", findings.get("target", "unknown"), f"source={result['source']}")
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------------------
# Attack Surface Map — OSINT + (if consented) recon, as a node/edge graph
# ---------------------------------------------------------------------------
@app.route("/api/attack-surface", methods=["POST"])
def api_attack_surface():
    target = (request.json or {}).get("target", "").strip()
    if not target:
        return jsonify({"ok": False, "reason": "target required"}), 400
    result = build_attack_surface(target, session["user_id"], run_recon)
    log_action(session["user_id"], "attack_surface_map", target,
               f"active_recon_included={result['active_recon_included']}")
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------------------
# Live Defend Feed — SSE stream of real audit events + labeled simulated
# ---------------------------------------------------------------------------
@app.route("/api/defend/stream")
def api_defend_stream():
    return app.response_class(stream_events(), mimetype="text/event-stream")


@app.route("/api/defend/simulate", methods=["POST"])
def api_defend_simulate():
    event = inject_simulated_event()
    return jsonify({"ok": True, "event": event})


# ---------------------------------------------------------------------------
# Security & General Assistant — Groq/Claude-backed, scope-limited by
# system prompt (see modules/assistant.py for why)
# ---------------------------------------------------------------------------
MAX_HISTORY_TURNS = 8  # cap context sent per request

@app.route("/api/assistant/chat", methods=["POST"])
def api_assistant_chat():
    data = request.json or {}
    message = data.get("message", "").strip()
    history = data.get("history", [])[-MAX_HISTORY_TURNS * 2:]  # user+assistant pairs

    if not message:
        return jsonify({"ok": False, "reason": "message required"}), 400

    result = assistant_chat(message, history)
    log_action(session["user_id"], "assistant_chat", "n/a", f"source={result['source']}")
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
