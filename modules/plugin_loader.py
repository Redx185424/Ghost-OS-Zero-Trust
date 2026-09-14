"""
Plugin Loader — Zero-Configuration Auto-Discovery
---------------------------------------------------
Drop any .py file into /plugins that defines:

    NAME = "my_plugin"
    DESCRIPTION = "what it does"
    REQUIRES_TARGET_AUTH = False   # True if it makes active connections
    def run(target: str) -> dict: ...

...and Ghost OS finds it automatically on startup. No registration,
no config file editing. This is the same pattern used by the private
Ghost OS Core plugin system, minus the ability to load compiled/
obfuscated modules — showcase plugins must be plain, readable Python.
"""

import os
import importlib.util

PLUGIN_DIR = os.path.join(os.path.dirname(__file__), "..", "plugins")


def load_plugins():
    plugins = []
    if not os.path.isdir(PLUGIN_DIR):
        return plugins

    for fname in sorted(os.listdir(PLUGIN_DIR)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(PLUGIN_DIR, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            print(f"[plugin_loader] failed to load {fname}: {e}")
            continue

        if hasattr(module, "NAME") and hasattr(module, "run"):
            plugins.append({
                "name": module.NAME,
                "description": getattr(module, "DESCRIPTION", ""),
                "requires_target_auth": getattr(module, "REQUIRES_TARGET_AUTH", False),
                "run": module.run,
            })
    return plugins
