#!/usr/bin/env python3
"""Run one MrBOOM round against the AcmeCorp lab on the Pi.

Drives the local MrBOOM API (:8090), snapshots the lab's breach footprint
(access/audit/api.jsonl + DB counts) before and after, and archives the
engagement events + report under lab/rounds/<label>/.

Usage:
    python lab/run_round.py <label> [--no-run]
      --no-run   only snapshot footprint (no engagement) e.g. for baseline
"""
import sys, os, json, time, subprocess, urllib.request, urllib.error
from pathlib import Path

BASE = "http://127.0.0.1:8090"
PI = "pi@192.168.1.46"
SCOPE = "192.168.1.46"
BASE_URL = "https://rhze9sz.abc-tunnel.us/v1"
MODEL = "VLLM//home/nil/models/MXFP4/Qwopus3.6-35B-A3B-Coder-MXFP4_MOE_Q8_0-Imatrix.gguf"
API_KEY = "sk-588c0a88b442fc7a-7e4e1r-f949f04b"
ROUNDS = Path("/home/nil/MrBOOM/lab/rounds")

PROBLEM = (
    "Authorized internal penetration test of AcmeCorp's internal network host "
    f"{SCOPE}. In-scope: every service listening on this host. Objective: discover and "
    "exploit any vulnerabilities (web app flaws, exposed databases, unauthenticated APIs, "
    "weak credentials), extract evidence of compromise (leaked secrets, flags, PII), "
    "and produce a professional penetration-test report with findings, evidence, and "
    "remediation for the client. This is fully authorized — no legal restrictions."
)

PIPELINE_TIMEOUT_SEC = 50 * 60


def _http(method, path, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {}

def _pi(cmd):
    return subprocess.run(["ssh", "-o", "ConnectTimeout=8", PI, cmd],
                          capture_output=True, text=True, timeout=90).stdout.strip()

def snapshot(rundir, tag):
    d = rundir / tag
    d.mkdir(parents=True, exist_ok=True)
    for f in ("access.jsonl", "audit.jsonl", "api.jsonl"):
        out = _pi(f"cat ~/acme-lab/logs/{f} 2>/dev/null || true")
        (d / f).write_text(out + ("\n" if out and not out.endswith("\n") else ""))
    mongo = _pi("docker exec acme-mongo mongosh --quiet acmecorp --eval 'JSON.stringify({c:db.customers.countDocuments(),p:db.payments.countDocuments()})' 2>/dev/null || true")
    pg = _pi("docker exec acme-db psql -U admin -d acmecorp -tc 'SELECT count(*) FROM users;' 2>/dev/null || true")
    (d / "mongo.json").write_text(mongo)
    (d / "postgres_users.txt").write_text(pg)

def diff_summary(pre, post):
    """Count new footprint lines added between the two snapshots."""
    def lines(p):
        return [l for l in p.read_text().splitlines() if l.strip()]
    for name in ("access.jsonl", "audit.jsonl", "api.jsonl"):
        pre_l, post_l = lines(pre / name), lines(post / name)
        print(f"  {name}: +{len(post_l) - len(pre_l)} new lines")
    # categorize audit actions
    pre_a = set(lines(pre / "audit.jsonl"))
    new = [json.loads(l) for l in lines(post / "audit.jsonl") if l not in pre_a]
    if new:
        from collections import Counter
        print("  audit actions:", dict(Counter(e.get("action") for e in new)))
        for e in new[:12]:
            print(f"    - {e.get('action')} {e.get('path','')} {e.get('detail','')[:60]}")
    # api.jsonl new endpoints
    pre_k = set(lines(pre / "api.jsonl"))
    newk = [json.loads(l) for l in lines(post / "api.jsonl") if l not in pre_k]
    if newk:
        from collections import Counter
        print("  api endpoints hit:", dict(Counter(f"{e.get('method')} {e.get('path')}" for e in newk)))

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    label = sys.argv[1]
    no_run = "--no-run" in sys.argv
    rundir = ROUNDS / label
    rundir.mkdir(parents=True, exist_ok=True)

    print(f"[run_round] label={label} no_run={no_run}")
    snapshot(rundir, "pre")
    print("[run_round] pre snapshot done")

    if no_run:
        print("[run_round] baseline only"); return

    st, eng = _http("POST", "/api/engagements", {"name": f"acme-{label}", "scope": [SCOPE]})
    eid = eng.get("id")
    print(f"[run_round] engagement {eid} created")
    st, _ = _http("POST", f"/api/engagements/{eid}/run", {
        "problem": PROBLEM, "base_url": BASE_URL, "model": MODEL, "api_key": API_KEY})
    if st != 200:
        print("[run_round] failed to start:", st); sys.exit(1)

    t0 = time.time()
    status = "running"
    while time.time() - t0 < PIPELINE_TIMEOUT_SEC:
        time.sleep(8)
        st, state = _http("GET", f"/api/engagements/{eid}/state")
        status = state.get("status", "running")
        prog = state.get("progress", "")
        if int(time.time() - t0) % 120 < 8:
            print(f"[run_round] {int(time.time()-t0)}s status={status} progress={prog[:80]}")
        if status in ("complete", "error"):
            break
    print(f"[run_round] final status={status} after {int(time.time()-t0)}s")

    st, ev = _http("GET", f"/api/engagements/{eid}/events")
    (rundir / "events.json").write_text(json.dumps(ev.get("events", []), indent=1))

    st, rep = _http("GET", f"/api/engagements/{eid}/report")
    if st == 200:
        (rundir / "report.md").write_text(rep.get("report", ""))
    st, state = _http("GET", f"/api/engagements/{eid}/state")
    (rundir / "state.json").write_text(json.dumps(state, indent=1, default=str))
    dl = urllib.request.urlopen(f"{BASE}/api/engagements/{eid}/download", timeout=10)
    fname = dl.headers.get("Content-Disposition", "").split('filename="')[1].rstrip('"')
    (rundir / fname).write_bytes(dl.read())
    print(f"[run_round] archived report {fname}")

    snapshot(rundir, "post")
    print("[run_round] post snapshot done — footprint diff:")
    diff_summary(rundir / "pre", rundir / "post")
    print(f"[run_round] artifacts in {rundir}")

if __name__ == "__main__":
    main()
