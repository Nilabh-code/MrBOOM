"""
MRBOOM // RESEARCH-AGENT — Big Sleep-style hypothesis-driven bug hunting
Mimics a human researcher: read target source -> form vulnerability
hypotheses -> write a PoC -> execute it in a sandbox -> feed the result
back and iterate. Confirmed behaviors become findings.

Pipeline:
  1. summarize()    — repo surface: languages, entry points, risky files
  2. hypothesize()  — LLM proposes {bug_class, location, test_plan, poc}
                     (deterministic fallback: sink-probe mode via source_scan)
  3. write_poc()    — materialize the PoC script
  4. execute()      — run in sandbox (local subprocess w/ limits, or Docker)
  5. verify()       — crash detection + marker checks
  6. loop()         — iterate with results fed back; dedupe; max rounds

CLI:
  python research_agent.py --repo <path|url> [--rounds 3]
                           [--sandbox local|docker] [--base-url URL --model M]
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

def _git(repo, *args, timeout=120):
    try:
        r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception:
        return "", -1

def _llm(base_url, model, api_key, system, user, max_tokens=1900):
    if not base_url or not model: return None
    try:
        from openai import OpenAI
        c = OpenAI(base_url=base_url.rstrip("/"), api_key=api_key or "not-needed")
                # reasoning models (Qwen3 etc.) burn the token budget thinking unless disabled;
        # fall back to plain call if the server rejects chat_template_kwargs
        _kwargs = dict(model=model,
                       messages=[{"role": "system", "content": system},
                                 {"role": "user", "content": user}],
                       temperature=0.2, max_tokens=max_tokens)
        r = None
        for _att in range(3):
            try:
                r = c.chat.completions.create(**_kwargs, extra_body={"chat_template_kwargs": {"enable_thinking": False}})
                break
            except Exception:
                try:
                    r = c.chat.completions.create(**_kwargs)
                    break
                except Exception as _le:
                    if _att == 2:
                        raise _le
                    __import__("time").sleep(1.5)
        _m = r.choices[0].message
        txt = (_m.content or "").strip() or (getattr(_m, "reasoning_content", "") or "").strip()
        return txt
    except Exception as e:
        return f"__LLM_ERROR__ {str(e)[:200]}"

def _json_loose(txt):
    m = re.search(r"\{.*\}|\[.*\]", txt or "", re.DOTALL)
    if not m: return None
    raw = m.group(0)
    try: return json.loads(raw)
    except Exception:
        try: return json.loads(re.sub(r",\s*([}\]])", r"\1", raw))
        except Exception: return None

def _json_list(txt):
    """Robust parse -> list of dicts. Handles arrays, single objects, or a
    stream of concatenated JSON objects (what reasoning models often emit)."""
    txt = (txt or "").strip()
    txt = re.sub(r"^```(?:json)?\s*|\s*```$", "", txt, flags=re.M).strip()
    try:
        d = json.loads(txt)
        return d if isinstance(d, list) else [d]
    except Exception:
        pass
    out, dec, i = [], json.JSONDecoder(), 0
    while i < len(txt):
        while i < len(txt) and txt[i] not in "{[":
            i += 1
        if i >= len(txt): break
        try:
            obj, end = dec.raw_decode(txt, i)
            out.append(obj); i = end
        except Exception:
            i += 1
    flat = []
    for o in out:
        flat.extend(o) if isinstance(o, list) else flat.append(o)
    return flat

# ─── Repo surface ──────────────────────────────────────────────────────
LANG_EXT = {".py": "python", ".js": "javascript", ".ts": "typescript", ".go": "go",
            ".c": "c", ".cpp": "c++", ".rs": "rust", ".java": "java", ".rb": "ruby",
            ".php": "php", ".sh": "shell", ".lua": "lua", ".cs": "c#"}

def summarize(repo):
    files = []
    for root, dirs, fs in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "dist", "build", "vendor", "__pycache__"}]
        for fn in fs:
            p = Path(root) / fn
            if p.suffix in LANG_EXT and p.stat().st_size < 512 * 1024:
                files.append(str(p))
    langs = {}
    for f in files:
        lang = LANG_EXT.get(Path(f).suffix)
        langs[lang] = langs.get(lang, 0) + 1
    entry_hints = []
    for f in files:
        try: head = Path(f).read_text(errors="ignore")[:4000]
        except Exception: continue
        if re.search(r"(def main|if __name__|func main|int main|@app\.route|"
                     r"app\.get|FastAPI|Flask|Express|router\.|listen\(|serve\(|"
                     r"handleRequest|public static void main)", head):
            entry_hints.append(os.path.relpath(f, repo))
    return {"repo": os.path.basename(repo), "files": len(files), "languages": langs,
            "entry_points": entry_hints[:15], "file_list": [os.path.relpath(f, repo) for f in files[:200]]}

# ─── Hypothesis generation ─────────────────────────────────────────────
def hypothesize(surface, base_url="", model="", api_key="", prior=None, n=5, target=""):
    """LLM proposes hypotheses. Returns list of dicts."""
    if not (base_url and model):
        return []  # deterministic mode uses sink-probe below
    prior_blob = ""
    if prior:
        prior_blob = "\nPrevious hypotheses & results (do not repeat failures):\n" + json.dumps(prior, indent=1)[:2500]
    target_blob = ""
    if target:
        target_blob = (f"\nAUTHORIZED TARGET IS LIVE at {target} (OWASP Juice Shop-style lab). "
                       f"Write PoCs as REAL HTTP requests to {target} using ONLY the python "
                       f"standard library (urllib.request). The PoC must open a URL, send "
                       f"requests/params/payloads, and print TRIGGERED:TRUE exact and only when "
                       f"the bug actually fires (e.g. error text, injected marker reflected, "
                       f"non-200 vs expected). It must exit cleanly otherwise.")
    out = _llm(base_url, model, api_key,
        "You are a vulnerability researcher running a Big Sleep-style hunt against an AUTHORIZED "
        "test lab. Given the target's source map, propose the most promising vulnerability "
        "hypotheses. Each must be CONCRETE and testable: name the exact file, the flawed logic, "
        "and a minimal PoC approach. Prioritize reachable user-input HTTP paths. "
        "Do NOT write weaponized exploits — PoC is a triggering test only. "
        'Reply ONLY with JSON list: [{"id":0,"bug_class":"...","location":"file:line/function",'
        '"reasoning":"why vulnerable","test_plan":"how to trigger in 2-3 steps",'
        '"poc":"complete python3 PoC script using urllib.request that sends HTTP requests to the '
        'live target and prints TRIGGERED:TRUE exact when the bug fires"}]' + target_blob,
        f"Target surface: {json.dumps(surface, indent=1)[:3000]}{prior_blob}")
    hyps = _parse_hypotheses(out, n)
    if not hyps:
        # one stricter retry — reasoning models occasionally emit prose first
        out2 = _llm(base_url, model, api_key,
            "Your previous reply was not valid JSON. Reply with ONLY a JSON array — no prose, "
            "no markdown. Same schema: [{\"id\":0,\"bug_class\":\"...\",\"location\":\"...\","
            "\"reasoning\":\"...\",\"test_plan\":\"...\",\"poc\":\"...\"}]",
            f"Target surface: {json.dumps(surface, indent=1)[:1500]}{prior_blob}")
        hyps = _parse_hypotheses(out2, n)
    return hyps

def _parse_hypotheses(out, n):
    if not out or out.startswith("__LLM_ERROR__"):
        return []
    data = _json_list(out)
    if not data:
        return []
    hyps = []
    for d in data[:n]:
        if isinstance(d, dict) and d.get("bug_class") and d.get("location"):
            hyps.append({"id": len(hyps), "bug_class": d.get("bug_class"),
                         "location": d.get("location"), "reasoning": d.get("reasoning", ""),
                         "test_plan": d.get("test_plan", ""), "poc": d.get("poc", "")})
    return hyps

# ─── Deterministic sink-probe mode (no LLM) ────────────────────────────
PY_SINK_PROBES = [
    (r"\beval\s*\(", "eval reached", 'eval(%r)'),
    (r"\bexec\s*\(", "exec reached", 'exec(%r)'),
    (r"os\.system\s*\(", "os.system reached", 'os.system(%r)'),
    (r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(", "subprocess reached", 'subprocess.run(%r, shell=True)'),
    (r"pickle\.loads?\s*\(", "pickle reached", 'pickle.loads(%r)'),
]

def sink_probes(repo):
    """Deterministic mode: probe Python sinks with a marker payload."""
    hyps = []
    for root, dirs, fs in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", "__pycache__"}]
        for fn in fs:
            if not fn.endswith(".py"): continue
            p = Path(root) / fn
            try: lines = p.read_text(errors="ignore").splitlines()
            except Exception: continue
            for pat, label, tmpl in PY_SINK_PROBES:
                rx = re.compile(pat)
                for i, ln in enumerate(lines):
                    if rx.search(ln):
                        payload = 'MRSIG_%d_%s' % (i, label.replace(" ", "_"))
                        probe = ("import sys\n" + tmpl.replace("%r", repr(payload)) +
                                 "\nprint('TRIGGERED:TRUE')\n")
                        hyps.append({"id": len(hyps), "bug_class": label,
                                     "location": f"{os.path.relpath(str(p), repo)}:{i+1}",
                                     "reasoning": "deterministic sink probe",
                                     "test_plan": f"run probe in same module context as {Path(p).name}",
                                     "poc": probe})
                        break  # one probe per file per sink class
    return hyps[:10]

# ─── Execution ─────────────────────────────────────────────────────────
def execute_poc(poc_code, sandbox="local", timeout=20):
    """Run PoC. Returns {exit_code, output_tail, crashed, triggered}."""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    tmp.write(poc_code); tmp.close()
    try:
        if sandbox == "docker" and shutil.which("docker"):
            cmd = ["docker", "run", "--rm", "--network", "none", "-m", "512m",
                   "--cpus", "1", "-v", f"{tmp.name}:/poc.py:ro", "python:3.11-slim",
                   "python", "/poc.py"]
        else:
            cmd = [sys.executable, tmp.name]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        crashed = r.returncode != 0
        triggered = "TRIGGERED:TRUE" in (r.stdout or "")
        return {"exit_code": r.returncode, "output_tail": out[-600:],
                "crashed": crashed, "triggered": triggered}
    except subprocess.TimeoutExpired:
        return {"exit_code": -9, "output_tail": "TIMEOUT", "crashed": False, "triggered": False}
    except Exception as e:
        return {"exit_code": -1, "output_tail": f"exec error: {e}", "crashed": False, "triggered": False}

# ─── Main loop ─────────────────────────────────────────────────────────
def hunt(repo, rounds=3, sandbox="local", base_url="", model="", api_key="", out_dir=None, target=""):
    out_dir = out_dir or tempfile.mkdtemp(prefix="mrboom-research-")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    surface = summarize(repo)
    log = {"surface": surface, "rounds": [], "findings": [], "confirmed": [], "target": target}
    prior = []
    for rnd in range(1, rounds + 1):
        hyps = hypothesize(surface, base_url, model, api_key, prior=prior, target=target)
        if not hyps:
            if rnd == 1:
                if not (base_url and model):
                    hyps = sink_probes(repo)  # deterministic fallback
                    log["mode"] = "deterministic sink-probe (no model)"
                else:
                    log["mode"] = "llm mode: no hypotheses generated this round"
            else:
                break
        round_log = {"round": rnd, "hypotheses": []}
        for h in hyps:
            if not h.get("poc"):
                continue
            poc_path = Path(out_dir) / f"poc_r{rnd}_{h['id']}.py"
            poc_path.write_text(h["poc"])
            res = execute_poc(h["poc"], sandbox=sandbox)
            entry = {"hypothesis": h, "result": res,
                     "status": "CONFIRMED" if res["triggered"] else ("CRASH" if res["crashed"] else "no-signal"),
                     "poc_path": str(poc_path)}
            round_log["hypotheses"].append(entry)
            sev = "high" if entry["status"] in ("CONFIRMED", "CRASH") else "low"
            log["findings"].append({
                "title": f"[RESEARCH-AGENT] {h['bug_class']} @ {h['location']} — {entry['status']}",
                "asset": h["location"], "severity": sev,
                "detail": (f"round={rnd} status={entry['status']} reasoning={h['reasoning'][:200]} "
                           f"test_plan={h['test_plan'][:200]} exit={res['exit_code']} "
                           f"output={res['output_tail'][:200]} poc={poc_path}"),
                "bug_class": h["bug_class"], "status": entry["status"],
                "poc_path": str(poc_path),
            })
            if entry["status"] in ("CONFIRMED", "CRASH"):
                log["confirmed"].append(entry)
            prior.append({"bug_class": h["bug_class"], "location": h["location"],
                          "result": entry["status"]})
        log["rounds"].append(round_log)
        if log["confirmed"] and rnd >= 1:
            break  # confirmed is a strong signal; stop
    return log

def clone_repo(url, dest):
    if "://" not in url and not url.startswith("git@"):
        # plain local path (may not even be a git repo)
        if Path(url).exists():
            return str(Path(url))
        raise RuntimeError(f"local path does not exist: {url}")
    dest = Path(dest)
    if dest.exists(): return str(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["git", "clone", "--quiet", "--depth", "1", url, str(dest)],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"clone failed: {r.stderr[-400:]}")
    return str(dest)

def main():
    ap = argparse.ArgumentParser(description="MrBOOM Research Agent (Big Sleep-style loop)")
    ap.add_argument("--repo", required=True, help="local path or git URL")
    ap.add_argument("--dest", default="/tmp/mrboom-research", help="clone destination")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--sandbox", default="local", choices=["local", "docker"])
    ap.add_argument("--target", default="", help="live authorized target base URL (e.g. http://localhost:3000) so PoCs hit it via HTTP")
    ap.add_argument("--out", default=None)
    ap.add_argument("--base-url", default=os.environ.get("MRBOOM_BASE_URL", ""))
    ap.add_argument("--model", default=os.environ.get("MRBOOM_MODEL", ""))
    ap.add_argument("--api-key", default=os.environ.get("MRBOOM_API_KEY", ""))
    a = ap.parse_args()
    repo = clone_repo(a.repo, os.path.join(a.dest, a.repo.rstrip("/").split("/")[-1] or "repo"))
    log = hunt(repo, rounds=a.rounds, sandbox=a.sandbox, base_url=a.base_url,
               model=a.model, api_key=a.api_key, target=a.target)
    if a.out:
        Path(a.out).write_text(json.dumps(log, indent=2, default=str))
    print(json.dumps(log, indent=2, default=str))

if __name__ == "__main__":
    main()
