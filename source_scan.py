"""
MRBOOM // SOURCE-SCAN — white-box vulnerability discovery + LLM triage
Fills MrBOOM's biggest gap: black-box only. When source code is available
(GitHub URL or local repo), this module hunts the bug classes black-box
testing can never see: auth bypass logic, deserialization, injection,
command execution, path traversal, unsafe reflection.

Pipeline:
  1. gather()   — walk repo, skip vendored dirs, collect candidate sinks
  2. heuristics — deterministic sink patterns per language + nearby
                  "source" detection (request params, argv, recv, files...)
  3. triage()   — LLM judges each candidate for REAL exploitability:
                  JSON verdict {vulnerable, class, confidence, input_chain,
                  suggested_probe}. No model = heuristic score only.
  4. findings   — engine-compatible output.

CLI:
  python source_scan.py --repo <path|url> [--dest DIR] [--top N]
                        [--base-url URL --model M] [--out FILE]
"""
import argparse, json, os, re, shutil, subprocess, sys
from pathlib import Path

# ─── Vendored / generated dirs to skip ─────────────────────────────────
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "vendor",
             "bower_components", "__pycache__", "site-packages", ".tox", "target",
             "coverage", ".idea", ".vscode", "minified", "static/vendor"}
SKIP_EXT = {".min.js", ".min.css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".woff", ".woff2", ".ttf", ".eot", ".ico", ".pdf", ".zip", ".gz",
            ".lock", ".pyc", ".so", ".dll", ".exe", ".class", ".jar", ".bin"}
MAX_FILE_BYTES = 512 * 1024

# ─── Sink patterns per language ────────────────────────────────────────
SINKS = {
    "py": [
        (r"\beval\s*\(", "eval() — arbitrary code execution"),
        (r"\bexec\s*\(", "exec() — arbitrary code execution"),
        (r"os\.system\s*\(", "os.system — command injection"),
        (r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(", "subprocess — command injection"),
        (r"shell\s*=\s*True", "shell=True — command injection"),
        (r"pickle\.loads?\s*\(", "pickle — insecure deserialization"),
        (r"yaml\.load\s*\((?![^)]*Loader=SafeLoader)", "yaml.load — unsafe deserialization"),
        (r"\b(execute|executemany|executescript)\s*\(.*(f[\"']|%s|\.format|\+)", "SQL execution with string interpolation — SQLi"),
        (r"render_template_string\s*\(", "render_template_string — SSTI"),
        (r"render_template\s*\(.*f[\"']", "template with f-string — SSTI-ish"),
        (r"os\.(popen|spawn|fork)\s*\(", "os process spawn"),
        (r"requests?\.get\s*\(.*(url|uri|target)", "request to user-controlled URL — SSRF"),
        (r"urlopen\s*\(.*(url|uri|target)", "urlopen user-controlled URL — SSRF"),
        (r"open\s*\(.*(filename|path|name)", "open with user-controlled path — traversal"),
        (r"shutil\.(copy|move|rmtree)\s*\(.*(path|src|src_file)", "file ops on user path"),
        (r"tempfile\.mktemp\s*\(", "tempfile.mktemp — insecure temp file"),
        (r"assert\s+", "assert used as security check (disabled under -O)"),
        (r"__import__\s*\(", "dynamic import — unsafe reflection"),
        (r"getattr\s*\(.*user", "getattr on user input — unsafe reflection"),
    ],
    "js": [
        (r"\beval\s*\(", "eval — arbitrary code execution"),
        (r"new\s+Function\s*\(", "Function constructor — code execution"),
        (r"(child_process\.)?(exec|execSync|spawn|spawnSync|fork)\s*\(", "child_process — command injection"),
        (r"\.innerHTML\s*=", "innerHTML — DOM XSS"),
        (r"document\.write\s*\(", "document.write — DOM XSS"),
        (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML — DOM XSS"),
        (r"window\.open\s*\(.*(url|href|src)", "window.open user URL — open redirect/XSS"),
        (r"location\s*=\s*.*(url|href|src)", "location assignment — open redirect"),
        (r"JSON\.parse\s*\(.*(body|data|content)", "JSON.parse on user data — prototype pollution surface"),
        (r"(prototype\.)?__proto__", "prototype pollution pattern"),
        (r"\.writeFile(Sync)?\s*\(.*(path|file|name)", "writeFile user path — traversal"),
        (r"sql\.(query|execute)\s*\(", "SQL query — SQLi"),
        (r"\.exec\s*\(.*sql", "SQL exec — SQLi"),
        (r"\.query\s*\(.*\+", "query with concatenation — SQLi"),
    ],
    "c": [
        (r"\bstrcpy\s*\(", "strcpy — buffer overflow"),
        (r"\bstrcat\s*\(", "strcat — buffer overflow"),
        (r"\bsprintf\s*\(", "sprintf — format string / overflow"),
        (r"\bgets\s*\(", "gets — buffer overflow"),
        (r"\bmemcpy\s*\([^,]+,[^,]+,\s*[a-z_]+(?!sizeof)", "memcpy with variable length — overflow surface"),
        (r"\bscanf\s*\(", "scanf — unchecked input"),
        (r"\bsystem\s*\(", "system — command injection"),
        (r"\bpopen\s*\(", "popen — command injection"),
        (r"\bstrncpy\s*\(", "strncpy — non-NUL-terminated buffer"),
        (r"\balloca\s*\(", "alloca — stack overflow"),
        (r"free\s*\([^;]+\);\s*[^;{}]*\buse\b", "potential use-after-free"),
        (r"realloc\s*\([^,]+,\s*(size|len|n)", "realloc with unchecked size — integer overflow"),
        (r"\batol?\s*\(", "atoi/atol — unchecked numeric parse"),
    ],
    "go": [
        (r"exec\.Command\s*\(", "exec.Command — command injection"),
        (r"os/exec.*Command", "exec import — command injection"),
        (r"(db|sql)\.(Query|QueryRow|Exec)\s*\(.*(\+|\"\s*\")", "SQL with concatenation — SQLi"),
        (r"unsafe\.Pointer", "unsafe.Pointer — memory safety risk"),
        (r"ioutil\.ReadFile\s*\(.*(path|file|name)", "ReadFile user path — traversal"),
        (r"os\.(Remove|Rename|Create)\s*\(.*(path|file|name)", "file ops on user path"),
        (r"json\.Unmarshal\s*\(", "Unmarshal — surface for malformed input"),
        (r"html/template.*(NoEscape|template\.HTML)", "unsafe template.HTML — XSS"),
    ],
    "java": [
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", "Runtime.exec — command injection"),
        (r"ProcessBuilder\s*\([^)]*(cmd|command|args)", "ProcessBuilder — command injection"),
        (r"Class\.forName\s*\([^)]*(name|user|input)", "dynamic class load — unsafe reflection"),
        (r"ObjectInputStream\s*\(", "ObjectInputStream — Java deserialization RCE"),
        (r"(readObject|readUnshared)\s*\(", "readObject — deserialization RCE"),
        (r"\.executeQuery\s*\([^)]*(\+|String\.format)", "SQL with concatenation — SQLi"),
        (r"\.executeUpdate\s*\([^)]*(\+|String\.format)", "SQL with concatenation — SQLi"),
        (r"jndi|InitialContext\s*\(", "JNDI lookup — log4shell-style surface"),
        (r"System\.getenv\s*\([^)]*\)\s*[\"']\+|getProperty.*\+", "env concat — injection surface"),
        (r"File\([^)]*(path|name|filename)", "File with user path — traversal"),
    ],
    "rb": [
        (r"\beval\s*\(", "eval — code execution"),
        (r"\bsystem\s*\(", "system — command injection"),
        (r"\bexec\s*\(", "exec — command injection"),
        (r"`[^`]*#\{", "backtick command with interpolation — command injection"),
        (r"ERB\.new|\.erb", "ERB — SSTI surface"),
        (r"YAML\.load\s*\(", "YAML.load — unsafe deserialization"),
        (r"Marshal\.load\s*\(", "Marshal.load — deserialization RCE"),
        (r"send\s*\([^)]*(params|input|data)", "send with user input — unsafe reflection"),
        (r"File\.(open|read|write|delete)\s*\([^)]*(params|input|file|path)", "file ops on user path"),
    ],
    "php": [
        (r"\beval\s*\(", "eval — code execution"),
        (r"\bsystem\s*\(|shell_exec\s*\(|passthru\s*\(|exec\s*\(", "command execution"),
        (r"preg_replace\s*\([^,]*[\"']/e", "preg_replace /e — code execution"),
        (r"unserialize\s*\(", "unserialize — PHP object injection"),
        (r"extract\s*\([^)]*(REQUEST|GET|POST)", "extract on superglobal — variable overwrite"),
        (r"mysqli?_query\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE).*(\$|\.)", "SQL with variable — SQLi"),
        (r"\binclude\s*\([^)]*(\$|get)", "include with variable — LFI/RFI"),
        (r"\brequire\s*\([^)]*(\$|get)", "require with variable — LFI/RFI"),
        (r"file_get_contents\s*\([^)]*(\$|get)", "file read with variable — LFI/SSRF"),
        (r"\$\_?(GET|POST|REQUEST|COOKIE|FILES)\b", "superglobal use"),
    ],
}

# ─── Source (user-input) proximity signals ─────────────────────────────
SOURCE_RE = re.compile(
    r"\b(request|req|body|params|param|query|q\b|headers?|cookies?|input|argv|args?|"
    r"recv|read|form|data|content|url|uri|path|filename|name|user|username|target|"
    r"search|searchterm|id\b|token|page|file|upload|value|message|text|key|"
    r"\$_?(GET|POST|REQUEST|COOKIE|FILES|SERVER))\b", re.I)
SOURCE_STRONG = re.compile(
    r"\b(request|body|params|query|headers|cookies|argv|recv|input|form|files|"
    r"\$_?(GET|POST|REQUEST|COOKIE|FILES))\b", re.I)

# extensions -> language key
def _lang_for(path):
    name = path.name.lower()
    if name.endswith(".py"): return "py"
    if name.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")): return "js"
    if name.endswith((".c", ".h", ".cpp", ".cc", ".cxx", ".hpp")): return "c"
    if name.endswith((".go",)): return "go"
    if name.endswith((".java", ".jsp", ".jspx")): return "java"
    if name.endswith((".rb", ".rake", ".gemspec")): return "rb"
    if name.endswith((".php", ".phtml", ".php3", ".php4", ".php5", ".inc")): return "php"
    return None

def gather(repo):
    """Walk repo, return candidates: [{file, line, snippet, lang, sink, source_near}]"""
    candidates = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            if any(fn.endswith(e) for e in SKIP_EXT): continue
            path = Path(root) / fn
            lang = _lang_for(path)
            if not lang: continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES: continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            lines = text.splitlines()
            for pat, label in SINKS.get(lang, []):
                rx = re.compile(pat)
                for i, ln in enumerate(lines):
                    if rx.search(ln):
                        window = "\n".join(lines[max(0, i - 3): i + 4])
                        src_near = bool(SOURCE_STRONG.search(window))
                        src_any = bool(SOURCE_RE.search(window))
                        candidates.append({
                            "file": str(path), "line": i + 1,
                            "sink": label, "lang": lang,
                            "snippet": window, "source_near": src_near,
                            "source_any": src_any,
                        })
    return candidates

def score(c):
    """Deterministic exploitability heuristic (0-10)."""
    s = 3.0
    if c["source_near"]: s += 4.0
    elif c["source_any"]: s += 2.0
    sev_words = {"code execution": 2, "command injection": 2, "deserialization": 2,
                 "buffer overflow": 2, "rce": 2, "sqli": 1.5, "sql": 1, "xss": 1,
                 "traversal": 1, "ssrf": 1, "reflection": 1, "lfi": 1}
    for w, v in sev_words.items():
        if w in c["sink"].lower():
            s += v
    return round(min(s, 10), 1)

# ─── LLM triage ────────────────────────────────────────────────────────
def _llm(base_url, model, api_key, system, user, max_tokens=800):
    if not base_url or not model: return None
    try:
        from openai import OpenAI
        c = OpenAI(base_url=base_url.rstrip("/"), api_key=api_key or "not-needed")
        r = c.chat.completions.create(
            model=model, messages=[{"role": "system", "content": system},
                                   {"role": "user", "content": user}],
            temperature=0.2, max_tokens=max_tokens)
        return (r.choices[0].message.content or "").strip()
    except Exception as e:
        return f"__LLM_ERROR__ {str(e)[:200]}"

def _json_loose(txt):
    m = re.search(r"\[.*\]|\{.*\}", txt or "", re.DOTALL)
    if not m: return None
    raw = m.group(0)
    try: return json.loads(raw)
    except Exception:
        try: return json.loads(re.sub(r",\s*([}\]])", r"\1", raw))
        except Exception: return None

def triage(candidates, base_url="", model="", api_key="", max_batch=12):
    """LLM judges candidate exploitability. Returns enriched candidates."""
    if not candidates: return []
    if not (base_url and model):
        for c in candidates:
            c["verdict"] = {"vulnerable": None, "class": "unknown",
                            "confidence": None, "input_chain": "",
                            "note": "deterministic mode (no model) — heuristic score only"}
        return candidates
    out = []
    for i in range(0, len(candidates), max_batch):
        batch = candidates[i:i + max_batch]
        blob = json.dumps([{"id": j, "file": c["file"], "line": c["line"],
                            "sink": c["sink"], "snippet": c["snippet"][:600]}
                           for j, c in enumerate(batch)])
        resp = _llm(
            base_url, model, api_key,
            "You are a senior application security engineer triaging static-analysis "
            "candidates. For EACH id, judge whether the pattern is a REAL, reachable "
            "vulnerability (data flow from user input to the sink) vs a false positive. "
            "Be skeptical: most candidates are safe or unreachable. "
            'Reply ONLY with JSON: [{"id":0,"vulnerable":true|false,"class":"bug class",'
            '"confidence":0.0-1.0,"input_chain":"user input -> ... -> sink","suggested_probe":"test input"}], '
            "one entry per id, same ids.",
            f"Candidates:\n{blob}")
        if not resp or resp.startswith("__LLM_ERROR__"):
            for c in batch:
                c["verdict"] = {"vulnerable": None, "class": "unknown", "confidence": None,
                                "input_chain": "", "note": f"LLM error: {resp[:120] if resp else 'no model'}"}
            out.extend(batch)
            continue
        data = _json_loose(resp) or []
        by_id = {d.get("id"): d for d in data if isinstance(d, dict)}
        for j, c in enumerate(batch):
            v = by_id.get(j, {})
            c["verdict"] = {"vulnerable": v.get("vulnerable"), "class": v.get("class", "unknown"),
                            "confidence": v.get("confidence"), "input_chain": v.get("input_chain", ""),
                            "suggested_probe": v.get("suggested_probe", ""),
                            "note": "" if v else "no verdict in LLM response"}
        out.extend(batch)
    return out

def scan_repo(repo, top=25, base_url="", model="", api_key=""):
    """End-to-end scan. Returns engine-compatible findings."""
    cands = gather(repo)
    scored = sorted(cands, key=score, reverse=True)[:top]
    scored = triage(scored, base_url, model, api_key)
    findings = []
    for c in scored:
        v = c["verdict"]
        if v.get("vulnerable") is False:
            continue  # LLM says false positive; deterministic mode keeps everything
        sev = "low"
        if v.get("vulnerable"):
            sev = "high" if (v.get("confidence") or 0) >= 0.7 else "medium"
        elif c["source_near"] and score(c) >= 6:
            sev = "medium"
        findings.append({
            "title": f"[SOURCE-SCAN] {c['sink']}",
            "asset": f"{c['file']}:{c['line']}",
            "severity": sev,
            "detail": (f"{c['sink']} in {c['file']}:{c['line']} "
                       f"(lang={c['lang']}, heuristic={score(c)}/10). "
                       f"Verdict: vulnerable={v.get('vulnerable')} "
                       f"class={v.get('class')} conf={v.get('confidence')} "
                       f"chain={v.get('input_chain')} probe={v.get('suggested_probe')} "
                       f"note={v.get('note','')}"),
            "sink": c["sink"], "line": c["line"], "lang": c["lang"],
            "snippet": c["snippet"][:400], "heuristic": score(c),
            "verdict": v,
        })
    return findings

def clone_repo(url, dest):
    dest = Path(dest)
    if dest.exists():
        return str(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["git", "clone", "--quiet", "--depth", "1", url, str(dest)],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"clone failed: {r.stderr[-400:]}")
    return str(dest)

def main():
    ap = argparse.ArgumentParser(description="MrBOOM Source-Scan (SAST + LLM triage)")
    ap.add_argument("--repo", required=True, help="local path or git URL")
    ap.add_argument("--dest", default="/tmp/mrboom-srcscan", help="clone destination")
    ap.add_argument("--top", type=int, default=25, help="max candidates to triage")
    ap.add_argument("--out", default=None, help="write findings JSON to file")
    ap.add_argument("--base-url", default=os.environ.get("MRBOOM_BASE_URL", ""))
    ap.add_argument("--model", default=os.environ.get("MRBOOM_MODEL", ""))
    ap.add_argument("--api-key", default=os.environ.get("MRBOOM_API_KEY", ""))
    a = ap.parse_args()

    repo = clone_repo(a.repo, os.path.join(a.dest, (a.repo.rstrip("/").split("/")[-1] or "repo")))
    findings = scan_repo(repo, top=a.top, base_url=a.base_url, model=a.model, api_key=a.api_key)
    if a.out:
        Path(a.out).write_text(json.dumps(findings, indent=2, default=str))
    print(json.dumps({"repo": repo, "findings": findings}, indent=2, default=str))

if __name__ == "__main__":
    main()
