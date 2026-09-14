<div align="center">

# 👻 GHOST OS
### `ZERO TRUST EDITION`

**An authorization-gated security intelligence platform.**
*Judged by whether every action can be traced back to a name — not by what it can break.*

[![License: MIT](https://img.shields.io/badge/License-MIT-2dd4bf.svg?style=for-the-badge)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-2dd4bf.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Status: Active](https://img.shields.io/badge/Status-Active-2dd4bf.svg?style=for-the-badge)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-f6c343.svg?style=for-the-badge)]()

[![Groq](https://img.shields.io/badge/AI-Groq-f87171.svg?style=flat-square)]()
[![Claude](https://img.shields.io/badge/AI-Claude%20(optional)-f6c343.svg?style=flat-square)]()
[![Docker](https://img.shields.io/badge/Lab-Docker-2496ED.svg?style=flat-square&logo=docker&logoColor=white)]()
[![Zero Trust](https://img.shields.io/badge/Architecture-Zero%20Trust-2dd4bf.svg?style=flat-square)]()

Part of the **Redx Tech Universe**

</div>

---

> Most security tools are judged by what they can break.
> This one is judged by whether every action can be traced back to a name.

An authorization-gated security intelligence platform — RBAC, full audit
trails, consent-enforced active recon, auto-generated client reports, and
a zero-config plugin architecture. Built to demonstrate the part of
offensive security tooling that most student projects skip entirely: the
accountability layer.

> 🔒 The private **Ghost OS Core** (full recon/exploit engine, Dead Man's Key
> security layer) is a separate, non-public repo. This edition exists to
> demonstrate the platform architecture publicly and safely.

📖 **For architecture details, the full API reference, and troubleshooting,
see [`DOCUMENTATION.md`](DOCUMENTATION.md).**

---

## 📑 Table of Contents

- [Why "Zero Trust"](#-why-zero-trust)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Quickstart](#-quickstart)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Writing a Plugin](#-writing-a-plugin)
- [Roadmap](#-roadmap)
- [Legal & Acceptable Use](#-legal--acceptable-use)
- [License](#-license)

---

## 🎯 Why "Zero Trust"

Nothing in this system is trusted by default — not the user, not the
target, not the action. Every active operation has to earn its execution:

| Trust Assumption | How it's enforced |
|---|---|
| 🚫 **Zero trust in the target** | Must be explicitly on the allow-list |
| 🚫 **Zero trust in the user** | Must type a signed consent phrase, logged and timestamped |
| 🚫 **Zero trust in the role** | RBAC gates reports and audit access behind `lead`+ |
| 🚫 **Zero trust in silence** | Every action writes to an append-only audit log, full stop |

Security tools that scan arbitrary targets with no authorization layer
are a portfolio liability, not a portfolio piece. This edition flips
that: the authorization gate, audit trail, and reporting pipeline **are**
the feature set, backed by real (but scoped) recon and OSINT modules.

---

## ✨ Features

| Module | What it does | Restriction |
|---|---|---|
| 🔐 **Authorization Gate** | Requires typed consent before any active scan | Target must be on the allow-list |
| 🛰️ **Passive OSINT** | DNS, WHOIS, cert-transparency subdomain search | None — public-record data only |
| 🎯 **Active Recon** | Port probing, banner grabs, TLS cert inspection | Lab allow-list + logged consent only |
| 🕸️ **Attack Surface Map** | Live node/edge graph of subdomains + open ports | Active nodes require consent |
| 🏆 **Zero Trust Score** | A–F grade from open ports, missing headers, TLS issues | Pure scoring function, no side effects |
| 🧠 **AI Risk Analyst** | Plain-English risk summary + prioritized fixes | Real Groq/Claude call if a key is set, honest rule-based fallback otherwise |
| 💬 **Ghost OS Assistant** | Chat: general Q&A + security concepts, tools, careers, CTF theory | No exploit code or live-attack instructions — public tool |
| 📡 **Live Defend Feed** | Real-time stream of real audit events + labeled demo traffic | `[SIMULATED]` events always tagged, never passed off as real |
| 👥 **RBAC** | analyst / lead / admin roles | Reports & audit log require `lead`+ |
| 📜 **Audit Trail** | Every action timestamped and logged | Surfaced in-app, not hidden |
| 📄 **Report Generator** | Findings → styled HTML/PDF client report | Requires `lead`+ |
| ⏱️ **Session Timeline** | Visual replay of the audit log | Requires `lead`+ |
| 🧩 **Plugin System** | Drop-in `.py` files, zero-config auto-discovery | Active plugins inherit the allow-list check |

---

## 📸 Screenshots

<div align="center">
<em>Add your own dashboard screenshots here before publishing —<br>
e.g. <code>docs/screenshot-dashboard.png</code>, <code>docs/screenshot-map.png</code></em>
</div>

```markdown
<!-- Example once you have real screenshots: -->
![Dashboard](docs/screenshot-dashboard.png)
![Attack Surface Map](docs/screenshot-map.png)
```

---

## 🚀 Quickstart

```bash
git clone <your-repo-url>
cd ghost-os-zero-trust
pip install -r requirements.txt
python app.py
```

Visit **`http://localhost:5000`**.

### Optional: enable the AI features

```bash
# .env file, next to app.py — free tier at console.groq.com
GROQ_API_KEY=gsk_...
```

Works fully without this too — the AI Risk Analyst and Assistant fall
back to honest, clearly-labeled non-AI responses if no key is set.

### Optional: spin up the vulnerable lab targets

```bash
docker compose -f docker/docker-compose.yml up -d
```

Gives you DVWA (`:8081`), OWASP Juice Shop (`:3000`), and Metasploitable2
(`:8080`) — pre-approved in `data/allowlist.json` — so you can demo
active recon against something real without touching anyone else's
infrastructure.

---

## 🛠️ Tech Stack

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-F55036?style=flat-square)

</div>

---

## 📂 Project Structure

```
ghost-os-zero-trust/
├── app.py                       # Flask routes — 18 endpoints
├── modules/
│   ├── auth_gate.py              # Allow-list + consent tracking
│   ├── rbac.py                    # Role decorator (analyst/lead/admin)
│   ├── audit.py                    # Append-only audit log
│   ├── osint.py                     # Passive recon (DNS/WHOIS/CT logs)
│   ├── recon.py                      # Active recon (gated)
│   ├── attack_surface.py              # OSINT + recon → graph data
│   ├── scoring.py                      # Findings → A-F grade
│   ├── report.py                        # HTML/PDF report generation
│   ├── defend.py                         # Audit log → live SSE feed
│   ├── ai_analyst.py                      # Findings → AI risk summary
│   ├── assistant.py                        # General + security chat
│   ├── llm_provider.py                      # Shared Groq/Claude caller
│   └── plugin_loader.py                      # Zero-config auto-discovery
├── plugins/
│   ├── header_analyzer.py        # Example plugin
│   └── README.md                  # Plugin authoring guide
├── data/
│   ├── allowlist.json             # The ONLY targets active modules can touch
│   └── audit_log.json              # Append-only log (gitignored)
├── docker/
│   └── docker-compose.yml         # DVWA / Juice Shop / Metasploitable lab
├── templates/ + static/            # Dashboard UI
├── DOCUMENTATION.md                  # Full architecture + API reference
├── LEGAL.md                           # Acceptable use policy
└── LICENSE                             # MIT + acceptable-use addendum
```

---

## ⚙️ Configuration

| Variable | Required? | Purpose |
|---|:---:|---|
| `GROQ_API_KEY` | optional | AI Risk Analyst + Assistant via Groq (free tier, recommended) |
| `ANTHROPIC_API_KEY` | optional | Fallback provider |
| `GROQ_MODEL` | optional | Override model (default: `openai/gpt-oss-20b`) |
| `GHOST_OS_SECRET` | optional | Flask session secret for non-localhost deployments |

Full reference, including every API endpoint and a troubleshooting guide
for common provider/environment issues, is in [`DOCUMENTATION.md`](DOCUMENTATION.md).

### Adding a target to the allow-list

Only add targets you own or have explicit written authorization to test:

```json
{ "host": "your-own-test-server.com", "description": "my staging box", "type": "owned" }
```

---

## 🧩 Writing a Plugin

Drop a `.py` file in `/plugins/` — zero registration, auto-discovered on restart:

```python
NAME = "my_plugin"
DESCRIPTION = "what it does"
REQUIRES_TARGET_AUTH = False   # True if it makes active connections

def run(target: str) -> dict:
    return {"result": "..."}
```

See [`plugins/README.md`](plugins/README.md) for the full contract.

---

## 🗺️ Roadmap

- [ ] Swap session-based auth for real OAuth/SSO
- [ ] Move audit log from JSON file to a proper DB (Postgres/SQLite)
- [ ] CI check that fails the build if a non-lab host is committed to `allowlist.json`
- [ ] WebSocket upgrade for the Defend Feed (currently SSE)
- [ ] Multi-user support with per-user allow-lists

---

## ⚖️ Legal & Acceptable Use

This is a public, downloadable tool. Active modules are hard-restricted
to the lab allow-list plus explicit logged consent — see
[`LEGAL.md`](LEGAL.md) for the full policy before adding any target you
don't own or control. This repo contains no exploit code, payload
generators, or credential-attack tooling by design.

---

## 📜 License

MIT with an acceptable-use addendum — see [`LICENSE`](LICENSE).

---

<div align="center">

**Part of the Redx Tech Universe**

*Built to show the accountability layer most security tools skip.*

</div>
