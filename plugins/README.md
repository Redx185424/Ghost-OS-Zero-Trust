# Writing Ghost OS Plugins

Drop a `.py` file in this folder. It's auto-discovered on startup — no
registration, no config editing.

## Contract

```python
NAME = "my_plugin"                 # unique identifier
DESCRIPTION = "one-line summary"   # shown in the UI
REQUIRES_TARGET_AUTH = False       # True = must be on lab allow-list

def run(target: str) -> dict:
    ...
    return {"some": "result"}
```

## Rules for showcase plugins

- **Passive by default.** If your plugin only reads public data (HTTP
  headers, DNS, WHOIS, certificate transparency logs), set
  `REQUIRES_TARGET_AUTH = False`.
- **Active plugins require the gate.** If your plugin makes repeated
  connections, probes ports, or does anything beyond a single normal
  request, set `REQUIRES_TARGET_AUTH = True` — the app will enforce the
  allow-list + consent check before calling `run()`.
- **No exploitation.** This showcase repo does not carry payload
  generation, credential brute-forcing, or exploitation modules. That
  logic lives in Ghost OS Core (private) and is out of scope here.
- **Plain, readable Python only.** No obfuscation, no compiled
  extensions, no dynamic code fetched from a remote URL.

See `header_analyzer.py` for a working example.
