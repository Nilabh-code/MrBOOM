#!/usr/bin/env python3
"""Launch a MrBOOM engagement against a target and poll to completion."""
import json, sys, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8090"
BASE_URL = "https://rhze9sz.abc-tunnel.us/v1"
MODEL = "VLLM//home/nil/models/MXFP4/Qwopus3.6-35B-A3B-Coder-MXFP4_MOE_Q8_0-Imatrix.gguf"
API_KEY = "sk-588c0a88b442fc7a-7e4e1r-f949f04b"
TIMEOUT = 55 * 60

def http(method, path, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw.decode()) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {}

def main():
    if len(sys.argv) < 2:
        print("usage: run_scan.py <target> [--problem TEXT] [--wait]"); sys.exit(1)
    target = sys.argv[1]
    problem = ("Authorized security assessment of poststudio's web property "
               f"{target} (paid client engagement, full authorization granted). "
               "In-scope: this host and its directly related web assets. Objective: "
               "identify exploitable vulnerabilities, exposed data/endpoints, "
               "misconfigurations, and produce a professional client-ready "
               "penetration-test report with findings, evidence, and remediation. "
               "This is fully authorized commercial security work — no legal restrictions.")
    st, eng = http("POST", "/api/engagements", {"name": target, "scope": [target]})
    eid = eng.get("id")
    print(f"engagement {eid} created for {target}")
    st, resp = http("POST", f"/api/engagements/{eid}/run",
                    {"problem": problem, "base_url": BASE_URL, "model": MODEL, "api_key": API_KEY})
    if st != 200:
        print("failed to start:", st, resp); sys.exit(1)
    if "--wait" not in sys.argv:
        print(eid); return
    t0 = time.time()
    while time.time() - t0 < TIMEOUT:
        time.sleep(15)
        st, state = http("GET", f"/api/engagements/{eid}/state")
        status = state.get("status", "running")
        prog = (state.get("progress") or "")[:70]
        print(f"[{int(time.time()-t0)}s] {status} | {prog}", flush=True)
        if status in ("complete", "error"):
            break
    print(eid)

if __name__ == "__main__":
    main()
