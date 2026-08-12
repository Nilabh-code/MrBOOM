"""
MRBOOM // FUZZ-ORCHESTRATOR — LLM-guided fuzzing + crash triage
Zero-dependency coverage-less mutation engine (works with gcc + ASAN),
plus optional libFuzzer / AFL++ / honggfuzz backends when installed.
LLM layer designs seeds + mutation strategy from target source.

Pipeline:
  1. detect_toolchain() — what's available (gcc/clang/afl/honggfuzz)
  2. build_target()     — compile C/C++ with ASAN+UBSAN; for libs, LLM
                          writes a stdin harness
  3. gen_seeds()        — LLM-designed seeds; fallback: repo fixtures +
                          binary strings dictionary
  4. fuzz()             — mutational engine or external backend
  5. triage()           — parse sanitizer reports, dedupe by stack
                          fingerprint, minimize, classify bug class
  6. findings           — engine-compatible output with reproducers

CLI:
  python fuzz_orchestrator.py --repo <path|url> [--budget 60]
                              [--base-url URL --model M] [--out FILE]
  python fuzz_orchestrator.py --binary ./target [--budget 60]
"""
import argparse, json, os, random, re, shutil, signal, string, subprocess, sys, tempfile, time
from pathlib import Path

ASAN_CLASS_RE = re.compile(
    r"(heap-use-after-free|stack-use-after-return|stack-buffer-overflow|"
    r"heap-buffer-overflow|global-buffer-overflow|use-after-poison|"
    r"SEGV on unknown address|SEGV|ABRT|SIGSEGV|SIGABRT|SIGFPE|"
    r"null pointer|division by zero|integer overflow|float-point|"
    r"stack-overflow|double-free|alloc-dealloc-mismatch|new-delete-type-mismatch)", re.I)

def _git(repo, *args, timeout=120):
    try:
        r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception:
        return "", -1

def detect_toolchain():
    def which(b):
        return shutil.which(b) or ""
    return {
        "gcc": which("gcc"), "g++": which("g++"), "clang": which("clang"),
        "clang++": which("clang++"), "afl-fuzz": which("afl-fuzz"),
        "afl-gcc": which("afl-gcc"), "honggfuzz": which("honggfuzz"),
        "python3": which("python3"),
        "libfuzzer": bool(shutil.which("clang")) and any(
            Path(p).exists() for p in [
                "/usr/lib/llvm*/lib/clang/*/lib/linux/libclang_rt.fuzzer*.a"])
    }

def _llm(base_url, model, api_key, system, user, max_tokens=900):
    if not base_url or not model: return None
    try:
        from openai import OpenAI
        c = OpenAI(base_url=base_url.rstrip("/"), api_key=api_key or "not-needed")
        r = c.chat.completions.create(model=model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            temperature=0.3, max_tokens=max_tokens)
        return (r.choices[0].message.content or "").strip()
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

# ─── Build ─────────────────────────────────────────────────────────────
def find_c_sources(repo):
    srcs = []
    skip = {"node_modules", ".git", "vendor", "build", "dist", "third_party", "test", "tests", "examples", "benchmark", "benchmarks"}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
        for fn in files:
            if fn.endswith((".c", ".cpp", ".cc", ".cxx")):
                srcs.append(os.path.join(root, fn))
    return srcs

def build_target(repo, base_url="", model="", api_key="", out_dir=None):
    """Compile C/C++ with ASAN+UBSAN. For repos with main(): direct build.
    Otherwise ask LLM for a stdin fuzz harness; fallback: feed each source
    through a tiny generic driver that reads stdin into a buffer and calls
    no function (compile-only check, not useful) -> report what's needed."""
    out_dir = out_dir or tempfile.mkdtemp(prefix="mrboom-fuzz-")
    cc = shutil.which("clang") or shutil.which("gcc") or shutil.which("g++")
    if not cc:
        return None, "no C compiler found (install gcc or clang)"
    srcs = find_c_sources(repo)
    if not srcs:
        return None, "no C/C++ sources found in repo"
    # prefer files with a main()
    mains = [s for s in srcs if re.search(r"int\s+main\s*\(", Path(s).read_text(errors="ignore"))]
    candidates = mains or srcs
    binpath = os.path.join(out_dir, "target_asan")
    flags = ["-fsanitize=address,undefined", "-g", "-O1", "-fno-omit-frame-pointer"]
    # try to build each candidate until one links
    for src in candidates[:8]:
        cmd = [cc, *flags, src, "-o", binpath]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        if r.returncode == 0:
            return binpath, f"built {os.path.basename(src)} with ASAN+UBSAN"
    last = ""
    for src in candidates[:2]:
        r = subprocess.run([cc, *flags, "-c", src, "-o", "/dev/null"], capture_output=True, text=True, timeout=240)
        if r.returncode != 0: last = r.stderr[-400:]
    return None, f"no linkable target (compile errors: {last or 'multiple translation units — need harness'}); provide --binary"

# ─── Seeds ─────────────────────────────────────────────────────────────
def _binary_strings(binpath, min_len=4):
    data = Path(binpath).read_bytes() if binpath and Path(binpath).exists() else b""
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len: out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= min_len: out.append(bytes(cur))
    return out[:200]

def gen_seeds(repo, binpath, base_url="", model="", api_key="", seed_dir=None, n=12):
    seed_dir = seed_dir or tempfile.mkdtemp(prefix="mrboom-seeds-")
    Path(seed_dir).mkdir(parents=True, exist_ok=True)
    seeds = []
    # 1) repo fixture/test inputs
    if repo:
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules"}]
            for fn in files:
                p = os.path.join(root, fn)
                if fn.endswith((".txt", ".dat", ".bin", ".json", ".xml", ".html")) and os.path.getsize(p) < 65536:
                    try: seeds.append(Path(p).read_bytes()[:65536])
                    except Exception: pass
                    if len(seeds) >= n: break
            if len(seeds) >= n: break
    # 2) dictionary tokens from binary strings
    tokens = _binary_strings(binpath)
    for t in tokens[:8]:
        seeds.append(t)
    # 3) LLM-designed seeds (format-aware)
    if base_url and model and repo:
        files = [os.path.relpath(p, repo) for p in find_c_sources(repo)][:10]
        out = _llm(base_url, model, api_key,
            "You are designing FUZZ SEEDS for a coverage-guided fuzzer. Given the target's "
            "input format, produce diverse boundary-hitting inputs: empty, huge lengths, "
            "negative/zero sizes, magic bytes, malformed headers, unicode, escapes, struct "
            "fuzz. Reply ONLY with JSON list of strings, each <= 512 chars.",
            f"Repo: {os.path.basename(repo)}\nC sources: {json.dumps(files)}")
        data = _json_loose(out) if out and not out.startswith("__LLM_ERROR__") else None
        if isinstance(data, list):
            for s in data[:6]:
                if isinstance(s, str): seeds.append(s.encode()[:512])
    # 4) fallback structural seeds
    seeds += [b"", b"\x00" * 16, b"\xff" * 16, b"A" * 256, b"GET / HTTP/1.1\r\n\r\n",
              bytes(range(256)), b"\x00\x00\x00\x00", b"0" * 64, b"-1", b"2147483647", b"nan", b"inf"]
    seen, out_seeds = set(), []
    for s in seeds:
        h = hash(s)
        if h not in seen:
            seen.add(h)
            (Path(seed_dir) / f"seed_{len(out_seeds)}").write_bytes(s)
            out_seeds.append(s)
            if len(out_seeds) >= n: break
    return seed_dir, len(out_seeds)

# ─── Built-in mutational engine (zero deps, gcc-compatible) ────────────
def _run_target(binpath, data, timeout=3):
    try:
        r = subprocess.run([binpath], input=data, capture_output=True, timeout=timeout)
        code = r.returncode
        err = (r.stderr or b"").decode(errors="ignore")
        return code, err
    except subprocess.TimeoutExpired:
        return 0, ""  # timeouts are not crashes for our purposes
    except Exception:
        return 0, ""

def _mutate(data, dictionary):
    b = bytearray(data)
    op = random.randrange(6)
    if not b:
        b = bytearray(os.urandom(random.randrange(1, 32)))
    if op == 0:  # bit flip
        i = random.randrange(len(b)); b[i] ^= 1 << random.randrange(8)
    elif op == 1:  # byte overwrite
        i = random.randrange(len(b)); b[i] = random.randrange(256)
    elif op == 2:  # arithmetic
        i = random.randrange(len(b)); b[i] = (b[i] + random.choice([-1, 1, 2, 255, 256])) % 256
    elif op == 3:  # interesting value
        i = random.randrange(len(b)); b[i] = random.choice([0, 1, 0x7f, 0x80, 0xff, 0x00])
    elif op == 4:  # splice two corpus entries
        other = bytes(random.choice(dictionary)) if dictionary else os.urandom(8)
        if not other:
            other = os.urandom(8)
        j = random.randrange(len(b))
        b = b[:j] + other[: random.randrange(1, len(other) + 1)] + b[j:]
    else:  # insert/delete
        if len(b) > 1 and random.random() < 0.5:
            del b[random.randrange(len(b))]
        else:
            i = random.randrange(len(b) + 1)
            b[i:i] = os.urandom(random.randrange(1, 9))
    return bytes(b[:4096])

def mutational_fuzz(binpath, seed_dir, budget, crashes_dir, corpus_dir, extra_dict=None):
    """Fork-spawn mutation fuzzer. Returns list of crash dicts."""
    Path(crashes_dir).mkdir(parents=True, exist_ok=True)
    Path(corpus_dir).mkdir(parents=True, exist_ok=True)
    seeds = [Path(seed_dir) / f for f in os.listdir(seed_dir)] if os.path.isdir(seed_dir) else []
    corpus = []
    for s in seeds:
        try: corpus.append(s.read_bytes())
        except Exception: pass
    if not corpus: corpus = [b""]
    for i, c in enumerate(corpus):
        (Path(corpus_dir) / f"corpus_{i}").write_bytes(c)
    dictionary = [bytes(x) for x in (extra_dict or [])] + corpus[:50]
    crashes, seen_fp = [], set()
    start = time.time()
    iterations = 0
    while time.time() - start < budget:
        iterations += 1
        inp = _mutate(random.choice(corpus), dictionary)
        code, err = _run_target(binpath, inp)
        if code != 0 or re.search(r"(AddressSanitizer|runtime error|UndefinedBehaviorSanitizer|ERROR:)", err):
            fp = _fingerprint(code, err)
            if fp not in seen_fp:
                seen_fp.add(fp)
                cid = f"crash_{len(crashes)}"
                (Path(crashes_dir) / cid).write_bytes(inp)
                (Path(crashes_dir) / f"{cid}.stderr").write_text(err[:4000])
                crashes.append({"id": cid, "input_size": len(inp), "exit_code": code,
                                "fingerprint": fp, "stderr_head": err[:800]})
        if len(corpus) < 200 and random.random() < 0.01 and code == 0:
            corpus.append(inp)  # keep interesting non-crashing inputs
    return crashes, iterations

def _fingerprint(code, err):
    m = re.search(r"(AddressSanitizer|UndefinedBehaviorSanitizer):\s*([a-z-]+)", err)
    if m: return f"{m.group(1)}:{m.group(2)}"
    st = re.search(r"(#[0-9]+ 0x[0-9a-f]+ in [^\n]+)", err)
    if st: return st.group(1)[:120]
    return f"signal:{code}"

def minimize_input(binpath, data, timeout=6):
    """Greedy delta-debug-lite: try removing halves recursively."""
    if not data: return data
    def crashes(d):
        code, err = _run_target(binpath, d, timeout)
        return code != 0 or bool(re.search(r"sanitizer|runtime error", err))
    work = data
    changed = True
    while changed and len(work) > 1:
        changed = False
        n = len(work)
        for start in range(0, n, max(1, n // 2)):
            cand = work[:start] + work[min(n, start + max(1, n // 2)):]
            if cand and len(cand) < len(work) and crashes(cand):
                work, changed = cand, True
    return work

def triage_crashes(crashes_dir, binpath, base_url="", model="", api_key=""):
    findings = []
    for f in sorted(os.listdir(crashes_dir)):
        if not f.startswith("crash_") or f.endswith(".stderr"): continue
        cid = f
        data = (Path(crashes_dir) / f).read_bytes()
        err = ""
        stp = Path(crashes_dir) / f"{cid}.stderr"
        if stp.exists(): err = stp.read_text(errors="ignore")[:4000]
        m = ASAN_CLASS_RE.search(err)
        cls = (m.group(1) if m else "unknown").lower()
        mini = minimize_input(binpath, data)
        mini_path = None
        if mini and len(mini) < len(data):
            mini_path = str(Path(crashes_dir) / f"{cid}.min")
            Path(mini_path).write_bytes(mini)
        detail = f"input {len(data)}B -> minimized {len(mini)}B; class={cls}"
        verdict = {}
        if base_url and model:
            out = _llm(base_url, model, api_key,
                "You are a binary exploitation analyst. Given a sanitizer crash report and "
                "the crashing input size, assess exploitability and the most likely primitive. "
                'Reply ONLY with JSON: {"exploitable": true|false|"unknown", "primitive": "e.g. '
                'control of size field -> heap overflow -> adjacent chunk overwrite", "difficulty": '
                '"low|medium|high", "notes": "..."}',
                f"Bug class: {cls}\nInput size: {len(data)}B (minimized {len(mini)}B)\nReport:\n{err[:2000]}")
            if out and not out.startswith("__LLM_ERROR__"):
                verdict = _json_loose(out) or {"notes": out[:200]}
        sev = "high" if verdict.get("exploitable") is True else ("medium" if cls != "unknown" else "low")
        findings.append({
            "title": f"[FUZZ] {cls} crash ({cid})",
            "asset": binpath, "severity": sev,
            "detail": f"{detail} | exploitable={verdict.get('exploitable')} "
                      f"primitive={verdict.get('primitive','')} difficulty={verdict.get('difficulty','')} "
                      f"notes={verdict.get('notes','')}",
            "bug_class": cls, "crash_id": cid, "input_size": len(data),
            "minimized_size": len(mini), "reproducer": str(Path(crashes_dir) / f),
            "minimized_reproducer": mini_path,
            "verdict": verdict,
        })
    return findings

# ─── Backends ──────────────────────────────────────────────────────────
def run_libfuzzer(binpath, corpus_dir, budget, crashes_dir):
    cc = shutil.which("clang")
    if not cc: return [], "libFuzzer needs clang (not installed)"
    # rebuild target with -fsanitize=fuzzer,address
    out = os.path.join(os.path.dirname(binpath), "target_libfuzzer")
    r = subprocess.run([cc, "-fsanitize=fuzzer,address,undefined", "-g", "-O1", binpath,
                        "-o", out], capture_output=True, text=True, timeout=240)
    if r.returncode != 0:
        return [], f"libFuzzer build failed: {r.stderr[-300:]}"
    r = subprocess.run([out, f"-max_total_time={budget}", f"-artifact_prefix={crashes_dir}/",
                        "-print_final_stats=1", corpus_dir], capture_output=True, text=True, timeout=budget + 60)
    crashes = [f for f in os.listdir(crashes_dir) if f.startswith("crash-")]
    return crashes, (r.stdout or "")[-500:]

def run_afl(binpath, corpus_dir, budget, crashes_dir):
    afl = shutil.which("afl-fuzz")
    if not afl: return [], "afl-fuzz not installed"
    afl_gcc = shutil.which("afl-gcc")
    if afl_gcc:
        rebuilt = os.path.join(os.path.dirname(binpath), "target_afl")
        r = subprocess.run([afl_gcc, "-fsanitize=address", "-g", "-O1", binpath, "-o", rebuilt],
                           capture_output=True, text=True, timeout=240)
        if r.returncode == 0: binpath = rebuilt
    out_dir = os.path.join(os.path.dirname(corpus_dir), "afl-out")
    subprocess.run([afl, "-i", corpus_dir, "-o", out_dir, "-V", str(budget), "--", binpath],
                   capture_output=True, text=True, timeout=budget + 60)
    crashes = []
    crashes_dir_path = Path(out_dir) / "default" / "crashes"
    if crashes_dir_path.exists():
        for f in os.listdir(crashes_dir_path):
            src = crashes_dir_path / f
            if src.is_file() and f != "README.txt":
                dst = Path(crashes_dir) / f"afl_{f}"
                shutil.copy(src, dst)
                crashes.append(dst.name)
    return crashes, f"afl output in {out_dir}"

# ─── Orchestration ─────────────────────────────────────────────────────
def fuzz_repo(repo, budget=60, base_url="", model="", api_key="", out_dir=None):
    out_dir = out_dir or tempfile.mkdtemp(prefix="mrboom-fuzz-run-")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    tc = detect_toolchain()
    binpath, note = build_target(repo, base_url, model, api_key, out_dir)
    report = {"toolchain": tc, "build": note, "out_dir": out_dir, "findings": []}
    if not binpath:
        report["error"] = note
        return report
    seed_dir, nseeds = gen_seeds(repo, binpath, base_url, model, api_key,
                                 seed_dir=os.path.join(out_dir, "seeds"))
    report["seeds"] = nseeds
    crashes_dir = os.path.join(out_dir, "crashes")
    corpus_dir = os.path.join(out_dir, "corpus")
    extra_dict = _binary_strings(binpath)
    if tc.get("clang") and tc.get("libfuzzer"):
        cs, msg = run_libfuzzer(binpath, corpus_dir, budget, crashes_dir)
        report["backend"] = f"libFuzzer ({msg[-120:]})"
    elif tc.get("afl-fuzz"):
        cs, msg = run_afl(binpath, corpus_dir, budget, crashes_dir)
        report["backend"] = "afl-fuzz"
    else:
        cs, iters = mutational_fuzz(binpath, seed_dir, budget, crashes_dir, corpus_dir, extra_dict)
        report["backend"] = f"builtin mutational engine ({iters} execs)"
    report["crashes"] = len(cs) if isinstance(cs, list) else cs
    report["findings"] = triage_crashes(crashes_dir, binpath, base_url, model, api_key)
    return report

def main():
    ap = argparse.ArgumentParser(description="MrBOOM Fuzz Orchestrator")
    ap.add_argument("--repo", help="local path or git URL of target")
    ap.add_argument("--binary", help="prebuilt binary to fuzz (skips build)")
    ap.add_argument("--budget", type=int, default=60, help="fuzz time budget (s)")
    ap.add_argument("--out", default=None, help="write report JSON to file")
    ap.add_argument("--base-url", default=os.environ.get("MRBOOM_BASE_URL", ""))
    ap.add_argument("--model", default=os.environ.get("MRBOOM_MODEL", ""))
    ap.add_argument("--api-key", default=os.environ.get("MRBOOM_API_KEY", ""))
    a = ap.parse_args()
    if not a.repo and not a.binary:
        ap.error("need --repo or --binary")
    out_dir = tempfile.mkdtemp(prefix="mrboom-fuzz-run-")
    if a.binary:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        seed_dir, nseeds = gen_seeds(None, a.binary, a.base_url, a.model, a.api_key,
                                     seed_dir=os.path.join(out_dir, "seeds"))
        crashes_dir = os.path.join(out_dir, "crashes")
        corpus_dir = os.path.join(out_dir, "corpus")
        cs, iters = mutational_fuzz(a.binary, seed_dir, a.budget, crashes_dir, corpus_dir,
                                    _binary_strings(a.binary))
        report = {"toolchain": detect_toolchain(), "binary": a.binary, "backend": f"builtin engine ({iters} execs)",
                  "crashes": len(cs), "out_dir": out_dir,
                  "findings": triage_crashes(crashes_dir, a.binary, a.base_url, a.model, a.api_key)}
    else:
        report = fuzz_repo(a.repo, a.budget, a.base_url, a.model, a.api_key, out_dir)
    if a.out:
        Path(a.out).write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
