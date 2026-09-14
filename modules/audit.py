"""
Audit Trail
-----------
Every action — consent, scan, plugin run, report generation — is logged
here. This is a headline feature, not a footnote: it's what makes the
platform defensible as "authorized testing tooling" rather than a black box.
"""

import json
import os
import time

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
AUDIT_LOG_PATH = os.path.join(DATA_DIR, "audit_log.json")


def _read_log():
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    with open(AUDIT_LOG_PATH) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def _write_log(entries):
    with open(AUDIT_LOG_PATH, "w") as f:
        json.dump(entries, f, indent=2)


def log_action(user_id: str, action: str, target: str, detail: str = ""):
    entries = _read_log()
    entries.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "user_id": user_id,
        "action": action,
        "target": target,
        "detail": detail,
    })
    _write_log(entries)


def get_audit_log():
    return list(reversed(_read_log()))  # most recent first


def get_audit_log_chronological():
    return _read_log()  # oldest first — used by the defend feed for correct ordering
