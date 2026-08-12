"""
MRBOOM // PATCH-GAP HUNTER — 1-day -> 0-day discovery engine
Turns known security fixes into NEW bug findings by answering one question:
"is this fix complete, or does a bypass / sibling-sink path still exist?"

Pipeline:
  1. watch()      — clone/track target repos (shallow, blob-filtered)
  2. fixes()      — scan commit history for security-relevant commits
                   (CVE refs, fix keywords, risky-area heuristics)
  3. reverse()    — reconstruct the vulnerable state from the fix diff
                   (LLM-assisted; deterministic stats fallback)
  4. analyze()    — LLM judges fix completeness: sibling sinks, bypass
                   paths, suggested probe. Structured JSON verdict.
  5. scan_repo()  — end-to-end: findings in engine-compatible format

Offline mode (no --base-url/--model): keyword filter + diff heuristics +
sibling-sink co-occurrence scan. LLM mode is strictly better.

CLI:
  python patchgap.py --repo <path|url> [--commits N] [--base-url URL --model M]
  python patchgap.py --watch <url> [--interval 3600]   # cron-friendly loop
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

# ─── Security-relevant commit keywords ─────────────────────────────────
# Strong words flag a commit on their own; weak words need a second signal
# (CVE ref, risky file, or another keyword hit) to avoid noise.
STRONG_WORDS = [
    "cve", "security", "vulnerab", "exploit", "use-after-free", "uaf", "use after free",
    "overflow", "out-of-bounds", "oob", "injection", "xss", "sqli", "csrf", "ssrf",
    "rce", "arbitrary", "deserial", "auth bypass", "privilege", "escalat",
    "dos", "denial of service", "crash", "null deref", "race condition", "toctou",
    "path traversal", "traversal", "smuggling", "request smuggling", "sandbox",
    "isolation", "info disclosure", "malicious", "untrusted",
]
WEAK_WORDS = [
    "fix", "patch", "hardening", "bypass", "bounds", "buffer", "leak", "redirect",
    "parse", "length", "size", "header", "cookie", "upload", "command", "exec",
    "eval", "template", "query", "sql", "signed", "certificate", "tls", "http",
]
RISKY_AREAS = re.compile(
    r"(auth|login|session|token|parse|parser|decode|unpack|deserial|alloc|free|"
    r"bounds|length|size|count|offset|index|request|header|cookie|upload|"
    r"file|path|url|redirect|command|exec|eval|template|render|query|sql)", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# ─── Helpers ────────────────────────────────────────────────────────────
def _git(repo, *args, timeout=120):
    try:
        r = subprocess.run(["git", "-C", repo, *args],
                           capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception:
        return "", -1

def _is_security_commit(msg, files=None):
    low = (msg or "").lower()
    if CVE_RE.search(msg): return True, "cve reference"
    strong = [w for w in STRONG_WORDS if w in low]
    if strong: return True, ", ".join(strong[:4])
    weak = [w for w in WEAK_WORDS if w in low]
    if not weak: return False, ""
    # weak signal needs a second signal: another keyword or a risky file
    files = files or []
    risky = [f for f in files if RISKY_AREAS.search(f)]
    if len(weak) >= 2 or risky:
        return True, ", ".join(weak[:3]) + (" + risky files" if risky else "")
    return False, ""

def _path_risky(files):
    risky = [f for f in files if RISKY_AREAS.search(f)]
    return risky

def clone_repo(url, dest, depth=200):
    """Shallow-ish clone for speed. Returns repo path. Existing dirs are
    refreshed best-effort: a transient fetch failure never crashes a watcher.
    Plain local paths are used directly (no clone needed)."""
    if "://" not in url and not url.startswith("git@"):
        if Path(url).exists():
            return str(Path(url))
        raise RuntimeError(f"local path does not exist: {url}")
    dest = Path(dest)
    if (dest / ".git").exists() or dest.exists():
        try:
            _git(str(dest), "fetch", "--quiet", "--depth", str(depth), "origin")
            _git(str(dest), "pull", "--quiet", "--ff-only")
        except Exception:
            pass  # stale data is fine for diff analysis
        return str(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--quiet", "--depth", str(depth), "--filter=blob:none",
           url, str(dest)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        # partial-clone fetch errors are common; clean up and retry with a
        # plain (full-history) clone before giving up
        shutil.rmtree(dest, ignore_errors=True)
        r2 = subprocess.run(["git", "clone", "--quiet", url, str(dest)],
                            capture_output=True, text=True, timeout=900)
        if r2.returncode != 0:
            raise RuntimeError(f"clone failed: {r.stderr[-400:] or r2.stderr[-400:]}")
    return str(dest)

def fixes(repo, n=50, after=None):
    """Return security-relevant commits as list of dicts (newest first)."""
    args = ["log", "--format=%H%x1f%an%x1f%ad%x1f%s%x1f%b", "--date=short"]
    if after: args += ["--since", after]
    args += [f"-n{n}"]
    out, rc = _git(repo, *args)
    if rc != 0: return []
    commits, seen = [], set()
    for block in out.split("\n\n"):
        line = block.split("\x1f")
        if len(line) < 5: continue
        sha, author, date, subj, body = line[0], line[1], line[2], line[3], "\x1f".join(line[4:])
        if sha in seen: continue
        seen.add(sha)
        # -m: include merge commits (one diff per parent); dedupe afterwards
        files_out, _ = _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "-m", sha)
        files = sorted(set(f for f in files_out.splitlines() if f))
        is_sec, why = _is_security_commit(
            subj if subj.startswith("Merge") else f"{subj}\n{body}", files)
        if not is_sec: continue
        commits.append({
            "sha": sha, "author": author, "date": date,
            "subject": subj.strip(), "message": f"{subj}\n{body}".strip(),
            "why": why, "files": files,
            "risky_files": _path_risky(files),
        })
    return commits

def diff_of(repo, sha):
    """Full diff of a commit (handles merge parents best-effort)."""
    out, _ = _git(repo, "show", "--format=", "-M", "--stat", sha)
    out2, _ = _git(repo, "show", "--format=", "-M", sha)
    return (out + "\n" + out2).strip()

def _sibling_sinks(repo, commit):
    """Deterministic heuristic: fix touched a sink; does the same sink
    pattern still appear elsewhere in the repo (possible incomplete fix)?"""
    out, _ = _git(repo, "show", "--format=", "-U3", commit["sha"])
    changed_lines = [l for l in out.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
    sinks = []
    for l in changed_lines:
        m = re.search(r"\b(exec|eval|system|sprintf|strcpy|strcat|memcpy|gets|"
                      r"pickle\.loads|yaml\.load|subprocess|sql_query|execute|"
                      r"read\(|write\(|send\(|recv\(|os\.open|fopen|unlink|"
                      r"chmod|render|template|redirect)\b", l, re.I)
        if m and m.group(1).lower() not in sinks:
            sinks.append(m.group(1).lower())
    if not sinks: return []
    flags = []
    for s in sinks:
        out, _ = _git(repo, "grep", "-l", "--ignore-case", s, "--", "*.py", "*.c", "*.cpp", "*.js", "*.go", "*.rs", "*.java")
        other_files = [f for f in out.splitlines() if f and f not in commit["files"]]
        if other_files:
            flags.append({"sink": s, "other_files": other_files[:8], "count": len(other_files)})
    return flags

def _severity(bug_class, msg):
    m = (msg or "").lower() + " " + (bug_class or "").lower()
    if any(k in m for k in ("rce", "remote code", "arbitrary code", "command injection", "deserial")):
        return "critical"
    if any(k in m for k in ("sqli", "sql injection", "xss", "ssrf", "auth bypass", "privilege", "path traversal", "uaf", "overflow")):
        return "high"
    if any(k in m for k in ("dos", "crash", "info disclosure", "leak", "race")):
        return "medium"
    return "low"

# ─── LLM layer (OpenAI-compatible; mirrors planner.py) ──────────────────
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
    m = re.search(r"\{.*\}", txt or "", re.DOTALL)
    if not m: return None
    raw = m.group(0)
    try: return json.loads(raw)
    except Exception:
        try: return json.loads(re.sub(r",\s*([}\]])", r"\1", raw))
        except Exception: return None

def reverse_patch(commit, diff, base_url="", model="", api_key=""):
    """LLM reconstructs the vulnerable state + bug class. Falls back to
    deterministic stats when no model or on error."""
    fallback = {
        "vulnerable_snippet": "see diff (no model)",
        "bug_class": "unknown",
        "trigger": "",
        "notes": f"{len(diff.splitlines())} diff lines, {len(commit['files'])} files, "
                 f"risky areas: {commit['risky_files'][:5]}",
    }
    out = _llm(
        base_url, model, api_key,
        "You are a vulnerability researcher. Given a security fix commit diff, "
        "reconstruct the VULNERABLE state and classify the bug. "
        'Reply ONLY with JSON: {"vulnerable_snippet": "short code/pseudocode of the pre-fix flaw", '
        '"bug_class": "e.g. integer overflow, use-after-free, auth bypass, SQL injection, deserialization", '
        '"trigger": "what input/condition triggers it"}',
        f"Commit: {commit['subject']}\nFiles: {json.dumps(commit['files'])}\nDiff:\n{diff[:8000]}")
    if not out or out.startswith("__LLM_ERROR__"):
        return fallback
    data = _json_loose(out)
    if not data:
        return fallback
    data["notes"] = fallback["notes"]
    return data

def analyze_bypass(repo, commit, diff, base_url="", model="", api_key=""):
    """LLM judges fix completeness + suggests bypass probes. Deterministic
    sibling-sink scan supplements the verdict."""
    siblings = _sibling_sinks(repo, commit)
    out = _llm(
        base_url, model, api_key,
        "You are an elite vulnerability researcher hunting INCOMPLETE FIXES. "
        "A maintainer just patched a security bug. Determine if the fix is complete. "
        "Consider: sibling sinks of the same pattern elsewhere, bypass of the new check, "
        "missing input-validation on alternate paths, integer/type edge cases, "
        "TOCTOU windows. "
        'Reply ONLY with JSON: {"fix_likely_complete": true|false, "reason": "short", '
        '"sibling_sinks": ["file:line pattern..."] or [], "bypass_paths": ["..."], '
        '"suggested_probe": "concrete PoC-ish test input or request to try", '
        '"bug_class": "..."}',
        f"Commit subject: {commit['subject']}\nCommit message:\n{commit['message'][:1500]}\n"
        f"Files changed: {json.dumps(commit['files'])}\nDiff:\n{diff[:10000]}")
    if not out or out.startswith("__LLM_ERROR__"):
        return {"fix_likely_complete": None, "reason": f"LLM unavailable: {out if out else 'no model'}"}
    data = _json_loose(out) or {"fix_likely_complete": None, "reason": "unparsable LLM output", "raw": out[:500]}
    data["deterministic_siblings"] = siblings or []
    return data

# ─── Orchestration ──────────────────────────────────────────────────────
def scan_repo(repo, commits_n=50, base_url="", model="", api_key="", after=None):
    """End-to-end: security fixes -> reversed patches -> bypass verdicts.
    Returns findings in engine-compatible format."""
    repo = str(repo)
    comms = fixes(repo, n=commits_n, after=after)
    findings = []
    for c in comms:
        diff = diff_of(repo, c["sha"])
        rev = reverse_patch(c, diff, base_url, model, api_key)
        byp = analyze_bypass(repo, c, diff, base_url, model, api_key)
        sev = _severity(rev.get("bug_class", ""), c["message"])
        findings.append({
            "title": f"[PATCH-GAP] {c['subject'][:90]}",
            "asset": str(repo),
            "severity": sev,
            "detail": (f"Commit {c['sha'][:10]} ({c['date']}) by {c['author']}. "
                       f"Class: {rev.get('bug_class')}. Trigger: {rev.get('trigger')}. "
                       f"Fix complete: {byp.get('fix_likely_complete')}. "
                       f"Reason: {byp.get('reason','')[:200]} "
                       f"Bypass paths: {byp.get('bypass_paths', [])} "
                       f"Sibling sinks: {byp.get('sibling_sinks', [])} "
                       f"Probe: {byp.get('suggested_probe','')}"),
            "commit": c["sha"], "date": c["date"], "why": c["why"],
            "bug_class": rev.get("bug_class"), "files": c["files"],
            "bypass": byp,
        })
    return findings

def watch(urls, dest_dir, interval, commits_n=50, base_url="", model="", api_key="", once=False):
    """Continuous loop: scan, print findings, sleep. Cron-friendly: --once."""
    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    while True:
        for url in urls:
            name = url.rstrip("/").split("/")[-1] or "repo"
            repo = clone_repo(url, os.path.join(dest_dir, name))
            print(f"[{datetime.now(timezone.utc).isoformat()}] scanning {name} ...", flush=True)
            try:
                for f in scan_repo(repo, commits_n=commits_n, base_url=base_url,
                                   model=model, api_key=api_key):
                    print(json.dumps(f, indent=2, default=str), flush=True)
            except Exception as e:
                print(f"[{name}] scan error: {e}", flush=True)
        if once: return
        time.sleep(interval)

# ─── CLI ────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="MrBOOM Patch-Gap Hunter")
    ap.add_argument("--repo", help="local path or git URL of target repo")
    ap.add_argument("--watch", nargs="+", help="git URLs to watch continuously")
    ap.add_argument("--dest", default="~/.mrboom/patchgap", help="clone destination dir")
    ap.add_argument("--commits", type=int, default=50, help="how many commits back to scan")
    ap.add_argument("--after", default=None, help="only commits since ISO date (YYYY-MM-DD)")
    ap.add_argument("--once", action="store_true", help="watch mode: single pass then exit")
    ap.add_argument("--interval", type=int, default=3600, help="watch loop interval (s)")
    ap.add_argument("--out", default=None, help="write findings JSON to this file")
    ap.add_argument("--base-url", default=os.environ.get("MRBOOM_BASE_URL", ""), help="OpenAI-compatible base URL")
    ap.add_argument("--model", default=os.environ.get("MRBOOM_MODEL", ""), help="model name")
    ap.add_argument("--api-key", default=os.environ.get("MRBOOM_API_KEY", ""), help="API key")
    a = ap.parse_args()

    if a.watch:
        watch(a.watch, os.path.expanduser(a.dest), a.interval, a.commits,
              a.base_url, a.model, a.api_key, once=a.once)
        return

    if not a.repo:
        ap.error("need --repo or --watch")
    repo = clone_repo(a.repo, os.path.join(os.path.expanduser(a.dest),
                     (a.repo.rstrip("/").split("/")[-1] or "repo")))
    findings = scan_repo(repo, a.commits, a.base_url, a.model, a.api_key, a.after)
    if a.out:
        Path(a.out).write_text(json.dumps(findings, indent=2, default=str))
    print(json.dumps({"repo": repo, "findings": findings}, indent=2, default=str))

if __name__ == "__main__":
    main()
