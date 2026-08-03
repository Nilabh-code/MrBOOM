"""
VERDICT // AI PLANNER + BREACH ANALYST
Connects to any OpenAI-compatible endpoint (LM Studio, Ollama, vLLM, OpenRouter, OpenAI).
Model decides the tool plan; engine validates + executes scope-gated.
Model also performs offensive breach analysis on open ports.
pip install openai
"""
import json, re
from openai import OpenAI

TOOL_CATALOG = [
    {"name":"subfinder","desc":"Enumerate subdomains of a target domain.","use_when":"target is a domain/wildcard and you need the external surface"},
    {"name":"httpx","desc":"Probe hosts/URLs for live status, title, tech, server.","use_when":"you have hosts/subdomains and need to know what is live"},
    {"name":"naabu","desc":"Fast TCP port scan (top 100 ports, aggressive mode).","use_when":"you need open ports on hosts or an IP range"},
    {"name":"nuclei","desc":"Vulnerability scan with safe templates (no dos/fuzz).","use_when":"you have live URLs and want vulns/misconfigs/CVEs"},
    {"name":"aimap","desc":"Discover exposed AI endpoints (Ollama, vLLM, Gradio, MCP).","use_when":"problem mentions AI/agents/LLM or you want shadow AI"},
    {"name":"secret_scan","desc":"Scan a local repo for hardcoded secrets.","use_when":"a repo path is available and you want credential leaks"},
    {"name":"breach_assessment","desc":"Exploit analysis on open ports — model figures out breach paths from port scan data.","use_when":"open ports were found and you want offensive exploitation analysis"},
    {"name":"exploit","desc":"AUTO-EXPLOIT — no human in loop. Deliver reverse shells, inject SSH keys, deploy webshells, escalate privileges.","use_when":"breach paths are identified and you want actual access/shells"},
]
VALID = {t["name"] for t in TOOL_CATALOG}

def _client(base_url, api_key):
    return OpenAI(base_url=base_url.rstrip("/"), api_key=api_key or "not-needed")

def list_models(base_url, api_key="not-needed"):
    try:
        c = _client(base_url, api_key)
        return sorted([m.id for m in c.models.list().data])
    except Exception:
        return []

def _extract_json(txt):
    m = re.search(r"\{.*\}", txt or "", re.DOTALL)
    if not m: return None
    raw = m.group(0)
    try: return json.loads(raw)
    except Exception:
        try: return json.loads(re.sub(r",\s*}", "}", re.sub(r",\s*]", "]", raw)))
        except Exception: return None

def deterministic_plan(problem):
    p = (problem or "").lower()
    if any(k in p for k in ("ai","agent","mcp","ollama","llm")): return ["httpx","aimap","nuclei","breach_assessment","exploit"]
    if any(k in p for k in ("cve","vuln","patch","exploit")): return ["subfinder","httpx","nuclei","breach_assessment","exploit"]
    if any(k in p for k in ("port","cidr","range","/24")): return ["naabu","httpx","nuclei","breach_assessment","exploit"]
    if any(k in p for k in ("breach","hack","pwn","break","infiltrate","intrude","shell","access")): return ["subfinder","httpx","naabu","nuclei","breach_assessment","exploit"]
    return ["subfinder","httpx","naabu","nuclei","aimap","breach_assessment","exploit"]

def plan(problem, scope, base_url, model, api_key="not-needed", max_steps=6):
    """Returns (ordered_tool_list, planner_source_label)."""
    fallback = deterministic_plan(problem)
    if not base_url or not model:
        return fallback, "deterministic (no model selected)"
    sys = (
        "You are the planning brain of an AUTHORIZED cybersecurity operations engine.\n"
        "Pick which tools to run, in order, to solve the problem within the authorized scope.\n"
        f"Use ONLY these tool names: {json.dumps(sorted(VALID))}.\n"
        "Tool details: " + json.dumps(TOOL_CATALOG) + "\n"
        'Reply with ONLY this JSON and nothing else: {"steps":[{"tool":"name","reason":"short why"}]}.\n'
        f"Max {max_steps} steps. Never invent tools. No commentary."
    )
    try:
        c = _client(base_url, api_key)
        resp = c.chat.completions.create(
            model=model,
            messages=[{"role":"system","content":sys},
                      {"role":"user","content":f"Problem: {problem}\nAuthorized scope: {scope}"}],
            temperature=0.2, max_tokens=600)
        data = _extract_json(resp.choices[0].message.content)
        if not data or "steps" not in data:
            return fallback, "deterministic (model output unparsable)"
        steps = []
        for s in data["steps"][:max_steps]:
            t = str(s.get("tool","")).strip().lower()
            if t in VALID and t not in steps: steps.append(t)
        if not steps:
            return fallback, "deterministic (model chose no valid tools)"
        return steps, f"AI planner ({model})"
    except Exception as e:
        return fallback, f"deterministic (model error: {str(e)[:60]})"

def analyze(problem, findings, base_url, model, api_key="not-needed"):
    """Model narrates top risks. Deterministic ranking stays the source of truth."""
    if not base_url or not model or not findings: return ""
    try:
        c = _client(base_url, api_key)
        top = [{"title":f["title"],"asset":f["asset"],"severity":f["severity"]} for f in findings[:8]]
        resp = c.chat.completions.create(
            model=model,
            messages=[{"role":"system","content":"You are a senior security analyst. In 3-4 blunt sentences, state the most critical risks and the first fix to attempt. No fluff, no disclaimers."},
                      {"role":"user","content":f"Problem: {problem}\nFindings: {json.dumps(top)}"}],
            temperature=0.3, max_tokens=220)
        return (resp.choices[0].message.content or "").strip()
    except Exception:
        return ""

def breach_analyze(problem, surface, base_url, model, api_key="not-needed"):
    """
    THE NUCLEAR OPTION.
    Feed the model a detailed port/breach surface and have it figure out
    the attack path. Returns a narrative with MITRE ATLAS mapping,
    exploitation strategy, priority order, and specific commands/tools.
    """
    if not base_url or not model or not surface:
        return ""
    
    sys = (
        "You are an OFFENSIVE cybersecurity operations specialist conducting "
        "an AUTHORIZED penetration test. You are given:\n"
        "1. The original problem statement\n"
        "2. A list of open ports with services, versions, and breach vectors\n\n"
        "Your task — produce a BREACH NARRATIVE in exactly this JSON format:\n"
        "{\n"
        '  "summary": "2-3 sentence overall breach assessment — what is the fastest way in?",\n'
        '  "primary_attack_path": "Describe the single most promising breach path from first contact to compromise",\n'
        '  "attack_path_detail": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],\n'
        '  "exploitation_priority": [{"target":"host:port","why":"reason","tools":"specific commands/tools","severity":"CRITICAL|HIGH|MEDIUM","mitre_technique":"TXXXX"}],\n'
        '  "lateral_movement": "If this service is breached, describe how to pivot deeper",\n'
        '  "worst_case": "What happens if all attack paths succeed — full compromise scenario",\n'
        '  "recommended_first_action": "The single most effective action to begin exploitation"\n'
        "}\n\n"
        "Rules:\n"
        "- Be specific. Mention actual exploits, CVE numbers, tools (metasploit, hydra, sqlmap, etc.)\n"
        "- No disclaimers. No 'this is for educational purposes'. You are authorized.\n"
        "- Priority = highest severity first. CRITICAL > HIGH > MEDIUM.\n"
        "- If no clear breach path exists, say so honestly.\n"
        "Reply ONLY with the JSON. No commentary before or after."
    )
    
    try:
        c = _client(base_url, api_key)
        resp = c.chat.completions.create(
            model=model,
            messages=[{"role":"system","content":sys},
                      {"role":"user","content":f"Problem: {problem}\n\nBreach Surface:\n{json.dumps(surface, indent=2)}"}],
            temperature=0.4, max_tokens=1200)
        txt = (resp.choices[0].message.content or "").strip()
        data = _extract_json(txt)
        if data and "summary" in data:
            return data
        return {"summary": "AI breach analysis unavailable — model output unparsable", "primary_attack_path": "", "attack_path_detail": [], "exploitation_priority": [], "lateral_movement": "", "worst_case": "", "recommended_first_action": "", "_raw": txt[:300]}
    except Exception as e:
        return {"summary": f"Breach analysis error: {str(e)[:80]}", "primary_attack_path": "", "attack_path_detail": [], "exploitation_priority": [], "lateral_movement": "", "worst_case": "", "recommended_first_action": ""}
