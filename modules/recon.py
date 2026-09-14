"""
Active Recon Module
--------------------
Unlike osint.py, this module makes active connections to the target
(port probes, banner grabs, TLS handshake). It is ONLY reachable via
/api/recon in app.py, which already enforces:
  1. target is on the lab allow-list (data/allowlist.json)
  2. the user has active, logged consent for that target

This module intentionally does NOT include exploitation, payload delivery,
or credential brute-forcing. It reports what's open and what's running —
nothing more. That's the line between "recon" and "attack."
"""

import socket
import ssl
import time

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]


def _probe_port(host, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except socket.gaierror:
        return False


def _grab_banner(host, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            try:
                s.sendall(b"\r\n")
            except OSError:
                pass
            banner = s.recv(256)
            return banner.decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _tls_info(host, port=443, timeout=3.0):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "tls_version": ssock.version(),
                }
    except Exception as e:
        return {"error": str(e)}


def run_recon(target: str) -> dict:
    started = time.time()
    open_ports = [p for p in COMMON_PORTS if _probe_port(target, p)]
    banners = {p: _grab_banner(target, p) for p in open_ports}

    result = {
        "target": target,
        "open_ports": open_ports,
        "banners": {p: b for p, b in banners.items() if b},
        "duration_seconds": round(time.time() - started, 2),
    }

    if 443 in open_ports:
        result["tls"] = _tls_info(target)

    return result
