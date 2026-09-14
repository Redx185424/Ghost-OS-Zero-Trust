"""
Zero Trust Score
-----------------
Turns raw findings (open ports, missing security headers, TLS issues) into
a single graded score, same pattern as SSL Labs / Mozilla Observatory.
Pure function, no side effects — takes whatever findings dict you give it
and scores what's present. Missing categories are simply not scored.
"""

EXPECTED_PORTS = {80, 443}
PORT_PENALTY = 8
HEADER_PENALTY = 5
TLS_ERROR_PENALTY = 15
STALE_CERT_PENALTY = 10


def compute_score(findings: dict) -> dict:
    score = 100
    deductions = []

    open_ports = findings.get("open_ports", [])
    for p in open_ports:
        if p not in EXPECTED_PORTS:
            score -= PORT_PENALTY
            deductions.append(f"Unexpected open port {p} (-{PORT_PENALTY})")

    headers = findings.get("headers_checked", {})
    for header, value in headers.items():
        if value == "MISSING":
            score -= HEADER_PENALTY
            deductions.append(f"Missing security header: {header} (-{HEADER_PENALTY})")

    tls = findings.get("tls", {})
    if isinstance(tls, dict):
        if tls.get("error"):
            score -= TLS_ERROR_PENALTY
            deductions.append(f"TLS handshake issue: {tls['error']} (-{TLS_ERROR_PENALTY})")
        elif tls.get("not_after"):
            deductions.append("TLS certificate present and readable (no penalty)")

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    if not deductions:
        deductions.append("No findings supplied yet — run recon and/or the header_analyzer plugin first.")

    return {"score": score, "grade": grade, "deductions": deductions}
