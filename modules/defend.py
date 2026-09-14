"""
Live Defend Feed
------------------
Streams two kinds of events, clearly distinguished:

1. REAL events — derived from the actual audit log. Every consent grant,
   recon run, or plugin execution taken through Ghost OS shows up here as
   a live "detection", because the platform genuinely is observing its
   own action stream. This is not fake.

2. SIMULATED events — synthetic ambient traffic (fake login attempts,
   probes from random IPs) injected on demand via /api/defend/simulate,
   for demo purposes. These are ALWAYS tagged "[SIMULATED]" in the output
   — Ghost OS does not misrepresent synthetic data as real detections.

Uses Server-Sent Events (SSE) — no extra dependency needed.
"""

import json
import time
import random
import queue

from modules.audit import get_audit_log_chronological

_simulated_queue = queue.Queue()

_SIMULATED_TEMPLATES = [
    ("HIGH", "Repeated failed SSH login from {ip} — auto-blocked after 5 attempts"),
    ("MEDIUM", "Port sweep detected from {ip} across 20 ports in 3s"),
    ("LOW", "Unusual User-Agent string flagged from {ip}"),
    ("HIGH", "SQL injection pattern detected in request from {ip} — blocked by WAF rule"),
    ("MEDIUM", "New device fingerprint seen from {ip}, flagged for review"),
]


def _random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def inject_simulated_event():
    """Called by POST /api/defend/simulate — pushes one labeled synthetic event."""
    severity, template = random.choice(_SIMULATED_TEMPLATES)
    event = {
        "kind": "SIMULATED",
        "severity": severity,
        "message": f"[SIMULATED] {template.format(ip=_random_ip())}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }
    _simulated_queue.put(event)
    return event


_AUDIT_ACTION_STYLE = {
    "consent_granted": ("LOW", "AUTH"),
    "consent_denied": ("MEDIUM", "AUTH"),
    "active_recon": ("HIGH", "RECON"),
    "osint_scan": ("LOW", "OSINT"),
    "report_generated": ("LOW", "REPORT"),
}


def _format_audit_event(entry):
    severity, tag = _AUDIT_ACTION_STYLE.get(entry["action"], ("LOW", entry["action"].upper()))
    prefix = tag
    if entry["action"].startswith("plugin:"):
        prefix = "PLUGIN"
    return {
        "kind": "REAL",
        "severity": severity,
        "message": f"[{prefix}] {entry['action']} on '{entry['target']}' by user {entry['user_id']} — {entry['detail']}",
        "timestamp": entry["timestamp"],
    }


def stream_events(max_iterations=None, sleep_seconds=1.0):
    """
    Generator yielding SSE-formatted strings. Merges real audit events
    (polled from the log file) with any queued simulated events.

    max_iterations: for testing only — caps the loop so it terminates.
    sleep_seconds: poll interval; pass 0 in tests to avoid real delay.
    """
    seen_count = len(get_audit_log_chronological())
    iterations = 0

    # Emit a banner event so the client knows what it's looking at
    yield f"data: {json.dumps({'kind': 'INFO', 'severity': 'LOW', 'message': 'Defend feed connected — REAL events from the audit log, [SIMULATED] events are labeled synthetic demo traffic.', 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())})}\n\n"

    while max_iterations is None or iterations < max_iterations:
        current_log = get_audit_log_chronological()
        if len(current_log) > seen_count:
            for entry in current_log[seen_count:]:
                yield f"data: {json.dumps(_format_audit_event(entry))}\n\n"
            seen_count = len(current_log)

        while not _simulated_queue.empty():
            event = _simulated_queue.get_nowait()
            yield f"data: {json.dumps(event)}\n\n"

        iterations += 1
        if sleep_seconds:
            time.sleep(sleep_seconds)
