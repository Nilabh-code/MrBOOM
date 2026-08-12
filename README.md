# MrBOOM — Breach & Attack Platform

All-in-one infrastructure reconnaissance, breach assessment, and **active exploit** platform with a live dashboard UI, SSE event streaming, AI-powered chat, and a persistent scan history.

MrBOOM runs a full recon pipeline and then an **active attack battery** (BB22) that self-surfaces and probes GET/POST parameters for exploitable vulnerabilities — only breachable findings are reported.

## Quick Start

### Prerequisites
- **Python 3.10+**
- A local or remote OpenAI-compatible model endpoint (Ollama, LM Studio, vLLM, OpenAI, etc.) — optional but enables the AI breach-assessment stage and chat

### Setup

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn
python app.py
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate
pip install fastapi uvicorn
python app.py
```

### Alternative: Run with uvicorn directly
```bash
uvicorn app:app --host 0.0.0.0 --port 8090
```

## Usage

1. Open `http://localhost:8090` in your browser
2. Enter your API Base URL (e.g. `http://localhost:1234/v1` for LM Studio, `http://localhost:11434` for Ollama, `https://api.openai.com/v1` for OpenAI)
3. Click **Discover Models** and select one (or type the model name)
4. Enter a target domain and prompt, then click **RUN**
5. After the run completes, review findings under **Findings**, download the report (MD/HTML/PDF), or ask follow-up questions in the chat panel

## Recon Pipeline

- DNS enumeration (A / MX / NS)
- Subdomain discovery (subfinder + crt.sh fallback) + wordlist brute-force
- PD dnsx / asnmap / uncover for deeper surface mapping
- HTTP probing (httpx + internal probe), port scanning (naabu), TLS analysis (tlsx)
- WHOIS, WAF detection, security-headers audit, CSP / S3 analysis
- JS bundle analysis, client-side assessment (cookies / DOM-XSS / CSP), wayback history
- Katana crawler, origin-IP (CDN bypass) hunt, nuclei + CVE correlation, exploit-chain analysis

## Attack & Validation Battery

- **BB22 Active Attack Engine** — self-surfacing battery over the discovered surface:
  - Reflected XSS (GET + POST, unique-marker detection — no false positives)
  - SQL injection (error-based + time-based blind)
  - Server-Side Template Injection (SSTI)
  - OS command injection (marker + time-based blind)
  - Path traversal / arbitrary file read
  - SSRF (cloud-metadata + internal network)
  - SQLi authentication bypass + XSS on login forms
  - Per-phase probe budgets, live-URL-first prioritization, stealth throttling
- **BB22b Web Configuration Validations** (`webvalidations.py`) — configuration-level checks that complement exploit probing:
  - TLS protocol version + weak cipher suites (RC4/DES/3DES/CBC) via live handshake
  - TLS certificate expiry, self-signed certs, issuer disclosure
  - Dangerous HTTP methods (TRACE → XST, PUT upload, permissive OPTIONS)
  - Cookie flags audit (Secure / HttpOnly / SameSite)
  - Directory listing detection, admin/auth path exposure, unauthenticated API JSON exposure
  - Information disclosure (server banner, X-Powered-By, stack traces)
  - Login rate limiting, security.txt presence, CORS credential/reflect behavior
  - Host-header injection + cache-poisoning indicators, weak/missing CSP, clickjacking
  - CRLF header injection, open redirects
- **BB23 Pentest Task Tree (PTT) + Agentic Exploit Loop** (PentestGPT-style):
  - Live task tree of every stage and its resolution status
  - Autonomous loop: LLM proposes the next concrete probe **from the real recon surface** (OpenAPI paths, JS-discovered API endpoints, dirbust results, confirmed origin IPs), the harness executes it, and outcomes feed back. Auto-retries blocked-auth endpoints with a forged `alg=none` JWT to test authz bypass.
- Directory busting (wordlist, catch-all / SPA false-positive filtering)
- Subdomain takeover, CORS misconfiguration, open redirect, basic injection scan
- Hardcoded secret scanning, exposed debug/health endpoints, source-map extraction
- API discovery + auth requirements, wayback secret hunt, default credentials check
- JWT / API auth bypass checks, deep JS asset analysis
- WAF fingerprint + bypass probes, OpenAPI/Swagger/GraphQL discovery
- Direct origin re-test, **CloudFront origin hunt** (BB21) via historical DNS + crt.sh
- **Content fuzzing** — auto-detects `ffuf` / `gobuster` and fuzzes live hosts with the harness wordlist (falls back to seclists if present); `assetfinder` adds passive subdomains
- Client-side validation: cookie flags, CSP bypass indicators, clickjacking (missing headers), HTTP methods

## 0-Day Discovery Modules (BB24)

White-box hunting layer — fills the gap between "exploit known CVEs" and "find new bugs". Both modules run standalone (CLI), are exposed as MCP tools (`patchgap_scan`, `source_scan`), and are registered in the AI planner's tool catalog.

### `patchgap.py` — Patch-Gap Hunter (1-day → 0-day)
Turns known security fixes into NEW bug findings: scans a repo's git history for security-relevant commits, reverses the patch to reconstruct the vulnerable state, and asks the LLM whether the fix is **complete** — sibling sinks, bypass paths, suggested probes.

```bash
# deterministic mode (no model needed)
python patchgap.py --repo https://github.com/pallets/werkzeug --commits 200

# LLM mode (OpenAI-compatible endpoint)
python patchgap.py --repo /path/to/repo --base-url http://localhost:11434/v1 --model gemma-4-12b

# continuous monitoring (cron-friendly, one pass with --once)
python patchgap.py --watch https://github.com/target/repo --interval 3600 --once
```

### `source_scan.py` — White-Box Source Scan (SAST + LLM triage)
Finds the bug classes black-box testing can never see: eval/exec sinks, insecure deserialization, SQLi via string interpolation, path traversal, unsafe reflection — across Python, JS/TS, C/C++, Go, Java, Ruby, PHP. Deterministic sink detection + source-proximity scoring, then LLM triage judges real reachability (`input_chain`) and suggests probes.

```bash
python source_scan.py --repo https://github.com/target/repo --top 25
python source_scan.py --repo . --base-url http://localhost:11434/v1 --model gemma-4-12b
```

Both emit findings in engine-compatible format (`title/asset/severity/detail`). LLM mode is strictly better; deterministic mode is the offline fallback.

## Dashboard

- **Live SSE feed** — every phase, tool call, and finding streams into the UI in real time
- **Findings tab** — severity-banded cards for every result type (exploits, config validations, fuzz paths, origins, creds, JWT, headers, agentic steps, etc.)
- **Phase progress** bar, health score chart, pair/relay timeline, elapsed timer
- **Scan history** — past scans persist to `scan_history/`, restorable with full events and report
- **Report export** — Markdown, HTML, and PDF download; includes a dedicated **Web Configuration Validations** table with per-check fixes
- **AI Chat** — ask follow-up questions about the finished scan
- **Dark/light theme**, mock demo mode (no model needed)

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Frontend UI |
| GET | `/events` | SSE event stream |
| POST | `/api/demo` | Start mock demo |
| GET/POST | `/api/models/discover` | List available models |
| POST | `/api/models/check` | Verify model is loaded |
| POST | `/api/engagements` | Create engagement |
| POST | `/api/engagements/{eid}/run` | Start pipeline run |
| GET | `/api/engagements/{eid}/state` | Get run state + findings |
| GET | `/api/engagements/{eid}/events` | Get event log |
| GET | `/api/engagements/{eid}/report` | Get report text |
| GET | `/api/engagements/{eid}/download` | Download report as .md |
| GET | `/api/engagements/{eid}/download/html` | Download report as HTML |
| GET | `/api/engagements/{eid}/download/pdf` | Download report as PDF |
| POST | `/api/engagements/{eid}/chat` | Chat about findings |
| GET | `/api/history` | List scan history |
| GET | `/api/history/{eid}` | Get a saved scan |
| DELETE | `/api/history/{eid}` | Delete a saved scan |

## Authorization

Only run this tool against targets you are explicitly authorized to test. Testing without authorization is illegal in most jurisdictions. The report generator includes a scope & authorization section — keep it accurate.

## Notes

- `scan_history/` and generated reports are gitignored.
- The pipeline tolerates missing model endpoints: recon and the attack battery run without a model; only the AI breach-assessment stage and chat require one.
