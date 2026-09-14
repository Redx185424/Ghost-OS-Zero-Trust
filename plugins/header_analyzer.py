"""
Example Plugin: HTTP Security Header Analyzer
------------------------------------------------
Fetches HTTP response headers from a target and checks for the presence
of standard security headers (CSP, HSTS, X-Frame-Options, etc). Entirely
passive/read-only — same as loading the page in a browser and checking
dev tools. Safe against any public domain.

Use this file as the template for writing your own plugins.
"""

import urllib.request

NAME = "header_analyzer"
DESCRIPTION = "Checks a target's HTTP response for standard security headers"
REQUIRES_TARGET_AUTH = False  # passive — no allow-list required

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def run(target: str) -> dict:
    url = target if target.startswith("http") else f"https://{target}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GhostOS-ZeroTrust/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            headers = dict(resp.getheaders())
    except Exception as e:
        return {"error": str(e)}

    findings = {h: headers.get(h, "MISSING") for h in SECURITY_HEADERS}
    missing = [h for h, v in findings.items() if v == "MISSING"]

    return {
        "target": url,
        "headers_checked": findings,
        "missing_count": len(missing),
        "grade": "A" if len(missing) == 0 else "B" if len(missing) <= 2 else "C" if len(missing) <= 4 else "D",
    }
