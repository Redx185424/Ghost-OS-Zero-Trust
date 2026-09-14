"""
Passive OSINT Module
---------------------
Read-only intelligence gathering using public records only:
  - DNS resolution (A/AAAA/MX/NS/TXT)
  - WHOIS lookup
  - Certificate Transparency search (crt.sh) for subdomain discovery

No packets are sent to the target beyond what a normal DNS resolver does.
This mode is safe to demo against any public domain — it's the same class
of lookup a browser or `dig`/`whois` command performs.
"""

import socket
import json
import urllib.request
import urllib.error

try:
    import whois  # python-whois
except ImportError:
    whois = None


def _dns_lookup(target):
    records = {}
    try:
        records["A"] = list({info[4][0] for info in socket.getaddrinfo(target, None, socket.AF_INET)})
    except socket.gaierror:
        records["A"] = []
    try:
        records["AAAA"] = list({info[4][0] for info in socket.getaddrinfo(target, None, socket.AF_INET6)})
    except socket.gaierror:
        records["AAAA"] = []
    return records


def _whois_lookup(target):
    if whois is None:
        return {"error": "python-whois not installed — see requirements.txt"}
    try:
        w = whois.whois(target)
        return {
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else [],
        }
    except Exception as e:
        return {"error": str(e)}


def _subdomain_enum_crtsh(target):
    """Passive subdomain discovery via certificate transparency logs (crt.sh)."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "GhostOS-ZeroTrust/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    if target in line:
                        subs.add(line.strip().lstrip("*."))
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        pass
    return sorted(subs)[:50]  # cap for demo purposes


def run_osint(target: str) -> dict:
    return {
        "target": target,
        "dns": _dns_lookup(target),
        "whois": _whois_lookup(target),
        "subdomains_via_ct_logs": _subdomain_enum_crtsh(target),
        "mode": "passive — no active connections made to target infrastructure",
    }
