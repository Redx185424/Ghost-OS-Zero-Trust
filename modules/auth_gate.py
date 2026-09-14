"""
Authorization Gate
-------------------
This is the feature that turns Ghost OS from "a hacking tool" into
"an authorized security testing platform." Nothing active runs without:
  1. The target being on the lab allow-list
  2. The user typing an explicit consent phrase (logged + timestamped)

Consent expires after CONSENT_TTL_SECONDS so stale sessions can't be reused.
"""

import time
import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
ALLOWLIST_PATH = os.path.join(DATA_DIR, "allowlist.json")
CONSENT_TTL_SECONDS = 60 * 30  # 30 minutes

_consent_store = {}  # {(user_id, target): timestamp}


def _load_allowlist():
    with open(ALLOWLIST_PATH) as f:
        return json.load(f)


ALLOWLIST = _load_allowlist()


def is_target_authorized(target: str) -> bool:
    """Target must be an exact match on the lab allow-list."""
    if not target:
        return False
    return any(entry["host"] == target for entry in ALLOWLIST)


def record_consent(user_id: str, target: str):
    _consent_store[(user_id, target)] = time.time()


def has_active_consent(user_id: str, target: str) -> bool:
    ts = _consent_store.get((user_id, target))
    if ts is None:
        return False
    return (time.time() - ts) < CONSENT_TTL_SECONDS


def reload_allowlist():
    """Call after editing data/allowlist.json without restarting the server."""
    global ALLOWLIST
    ALLOWLIST = _load_allowlist()
    return ALLOWLIST
