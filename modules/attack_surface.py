"""
Attack Surface Map
--------------------
Combines passive OSINT (subdomains) and, if authorized, active recon
(open ports) into a node/edge graph the frontend renders as an SVG map.
Pure data-shaping — no new scanning logic, reuses osint.py / recon.py.
"""

from modules.osint import run_osint
from modules.auth_gate import is_target_authorized, has_active_consent


def build_attack_surface(target: str, user_id: str, recon_fn) -> dict:
    """
    recon_fn is passed in (rather than imported) so the caller controls
    whether active recon is allowed to run at all for this request.
    """
    osint_result = run_osint(target)
    subdomains = osint_result.get("subdomains_via_ct_logs", [])[:12]  # cap for a readable map

    nodes = [{"id": target, "label": target, "type": "root"}]
    edges = []

    for sub in subdomains:
        nodes.append({"id": sub, "label": sub, "type": "subdomain"})
        edges.append({"from": target, "to": sub})

    active_recon_ran = False
    if is_target_authorized(target) and has_active_consent(user_id, target):
        recon_result = recon_fn(target)
        active_recon_ran = True
        for port in recon_result.get("open_ports", []):
            node_id = f"port-{port}"
            nodes.append({"id": node_id, "label": f":{port}", "type": "port"})
            edges.append({"from": target, "to": node_id})

    return {
        "target": target,
        "nodes": nodes,
        "edges": edges,
        "active_recon_included": active_recon_ran,
        "note": None if active_recon_ran else "Passive data only — grant consent for this target to include open-port nodes.",
    }
