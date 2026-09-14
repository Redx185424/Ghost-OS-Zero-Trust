"""
RBAC — Role Based Access Control
---------------------------------
Three roles, escalating privilege. Swap the session-based role check for a
real identity provider (OAuth/SSO) in production — this is a showcase-grade
implementation to demonstrate the pattern.
"""

from functools import wraps
from flask import session, jsonify

ROLES = ["analyst", "lead", "admin"]
ROLE_RANK = {role: i for i, role in enumerate(ROLES)}


def require_role(min_role: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current = session.get("role", "analyst")
            if ROLE_RANK.get(current, 0) < ROLE_RANK.get(min_role, 0):
                return jsonify({
                    "ok": False,
                    "reason": f"requires role '{min_role}' or higher (you are '{current}')"
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
