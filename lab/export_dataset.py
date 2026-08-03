#!/usr/bin/env python3
"""Export MrBOOM lab rounds into a ChatML fine-tuning dataset (JSONL).

Extracts three kinds of examples from lab/rounds/*:
  1. report-writing   — finding table rows (title/sev/CWE/evidence/remediation) → prose finding entry
  2. agentic          — event-stream tool calls/results → (observation → next action) traces
  3. synthetic        — bootstrapped variations of the 4 confirmed lab vulns across
                        hosts/ports/paths/params so the fine-tune has a solid base

Usage:
    python lab/export_dataset.py [--out lab/dataset/finetune.jsonl] [--synthetic N]
"""
import json, re, sys, argparse
from pathlib import Path

ROUNDS = Path(__file__).resolve().parent / "rounds"
DEFAULT_OUT = Path(__file__).resolve().parent / "dataset" / "finetune.jsonl"

SYSTEM_SCANNER = (
    "You are MrBOOM, an elite, authorized penetration-testing engine. You work through a "
    "stealthy, methodical pipeline: footprint, enumerate, fingerprint, probe, exploit, evidence, "
    "report. You only ever test in-scope targets with explicit authorization. You produce "
    "professional client-ready reports with precise severity ratings, CWE mappings, concrete "
    "evidence, and actionable remediation."
)
SYSTEM_REPORTER = (
    "You are the MrBOOM report writer. You turn raw scan findings into precise, professional "
    "client report entries. Each entry names the vulnerability, assigns the correct severity, "
    "maps it to the proper CWE, quotes the concrete evidence, and recommends a specific fix."
)

FINDING_REMEDIATIONS = {
    "OS Command Injection": (
        "Never pass user input into a shell. Replace os.system/subprocess-with-shell with "
        "parameterized subprocess calls and an allowlist of safe values."
    ),
    "SQL Injection": (
        "Use parameterized queries / an ORM and least-privilege database accounts. Apply an "
        "allowlist for the auth path and rate-limit login attempts."
    ),
    "Path Traversal": (
        "Resolve paths with os.path.realpath and enforce the result stays under the intended "
        "root; never join user input directly into filesystem paths."
    ),
    "SSRF": (
        "Validate and allowlist outbound fetch targets, block RFC1918/link-local/metadata "
        "ranges, and enforce an egress proxy with no user-controlled host resolution."
    ),
}

CONFIRMED_VULNS = [
    {
        "type": "OS Command Injection", "cwe": "CWE-78", "sev": "CRITICAL",
        "param": "host", "payload": "|id", "marker": "uid=", "paths": ["/tools/diagnostics", "/tools/ping", "/diag", "/admin/ping-host"],
    },
    {
        "type": "SQL Injection", "cwe": "CWE-89", "sev": "CRITICAL",
        "param": "username", "payload": "admin' OR 1=1 OR username='admin", "marker": "Role: admin", "paths": ["/login", "/signin", "/auth", "/sso"],
    },
    {
        "type": "Path Traversal", "cwe": "CWE-22", "sev": "HIGH",
        "param": "file", "payload": "/app/.env", "marker": "DATABASE_URL", "paths": ["/files/download", "/download", "/export", "/read"],
    },
    {
        "type": "SSRF", "cwe": "CWE-918", "sev": "HIGH",
        "param": "url", "payload": "http://internal-api:8443/api/v1/config", "marker": "MRBOOM_LAB", "paths": ["/tools/fetch-preview", "/preview", "/proxy", "/fetch"],
    },
]

HOSTS = ["192.168.1.46", "10.0.0.8", "172.16.5.12", "192.168.50.7", "203.0.113.24"]
PORTS = ["", ":80", ":443", ":8080", ":8443"]


def parse_report_tables(report_md):
    """Return list of finding dicts from the report's three tables."""
    findings = {}
    sections = re.split(r"^#### |^### ", report_md, flags=re.M)
    for sec in sections:
        head = sec.splitlines()[0].strip()
        rows = [l for l in sec.splitlines()[1:] if l.startswith("|") and not l.startswith("|--") and not l.startswith("| #")]
        if head == "Detailed Findings & Remediation":
            for r in rows:
                cols = [c.strip() for c in r.strip().strip("|").split("|")]
                if len(cols) >= 5 and cols[0].isdigit():
                    findings[int(cols[0])] = {
                        "severity": cols[1].upper(), "title": cols[2],
                        "asset": cols[3], "cwe": cols[4], "evidence": "", "fix": "",
                    }
        elif head == "Evidence Archive":
            for r in rows:
                cols = [c.strip() for c in r.strip().strip("|").split("|")]
                if len(cols) >= 3 and cols[0].isdigit():
                    findings.setdefault(int(cols[0]), {})["evidence"] = cols[2]
        elif head == "Remediation Actions":
            for r in rows:
                cols = [c.strip() for c in r.strip().strip("|").split("|")]
                if len(cols) >= 3 and cols[0].isdigit():
                    findings.setdefault(int(cols[0]), {})["fix"] = cols[2]
    return list(findings.values())


def report_examples(finding):
    """Build a report-writing example for one finding."""
    title, sev, cwe = finding["title"], finding["severity"], finding["cwe"]
    asset = finding["asset"]
    evid = finding["evidence"]
    fix = finding["fix"]
    vuln = next((v["type"] for v in CONFIRMED_VULNS if v["type"].lower() in title.lower()), title)
    if not fix and any(v["type"].lower() in title.lower() for v in CONFIRMED_VULNS):
        fix = FINDING_REMEDIATIONS[vuln]
    prompt = (
        f"Target: {asset}\n\n"
        f"A scanner probe flagged: {title} (severity {sev}, {cwe}).\n"
        f"Evidence recorded: {evid or 'probe returned a vulnerable response'}.\n\n"
        "Write the client-facing finding entry (title, severity, CWE, evidence, remediation)."
    )
    answer = (
        f"{sev} | {title}\n"
        f"CWE: {cwe}\n"
        f"Evidence: {evid or 'vulnerable response confirmed'}\n"
        f"Remediation: {fix or 'Isolate the endpoint, apply input validation and defense-in-depth controls.'}"
    )
    return {"messages": [
        {"role": "system", "content": SYSTEM_REPORTER},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": answer},
    ]}


def agentic_examples(events, target):
    """Build observation→action traces from the event stream."""
    examples = []
    pending_ctx = []
    for e in events:
        p = e.get("payload") or {}
        t = e.get("type")
        if t == "tool.call":
            pending_ctx.append({"name": p.get("name"), "target": p.get("target"), "cat": p.get("category")})
        elif t == "tool.result" and pending_ctx:
            call = pending_ctx.pop()
            obs = f"Tool '{call['name']}' on {call['target']} returned: {str(p.get('result'))[:120]} (status {p.get('status')})"
            examples.append({"messages": [
                {"role": "system", "content": SYSTEM_SCANNER},
                {"role": "user", "content": f"Target: {target}. Tool result observed.\n{obs}"},
                {"role": "assistant", "content": f"Noted: {obs}"},
            ]})
    return examples


def synthetic_examples(n):
    """Generate n report-writing examples from confirmed vuln templates."""
    import itertools, random
    random.seed(7)
    examples = []
    combos = list(itertools.product(CONFIRMED_VULNS, HOSTS, PORTS))
    for i in range(n):
        vuln, host, port = combos[i % len(combos)]
        path = random.choice(vuln["paths"])
        if random.random() < 0.5 and port != "":
            url = f"http://{host}{port}{path}"
        else:
            url = f"http://{host}{path}"
        prompt = (
            f"Target: {host}\n\n"
            f"A probe of {url} with parameter '{vuln['param']}' using payload '{vuln['payload']}' "
            f"returned the marker '{vuln['marker']}', confirming {vuln['type'].lower()}.\n\n"
            "Write the client-facing finding entry (title, severity, CWE, evidence, remediation)."
        )
        answer = (
            f"{vuln['sev']} | {vuln['type']} via {vuln['param'].capitalize()} Parameter\n"
            f"CWE: {vuln['cwe']}\n"
            f"Evidence: response contained '{vuln['marker']}'\n"
            f"Remediation: {FINDING_REMEDIATIONS[vuln['type']]}"
        )
        examples.append({"messages": [
            {"role": "system", "content": SYSTEM_REPORTER},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": answer},
        ]})
    return examples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--synthetic", type=int, default=240)
    args = ap.parse_args()

    examples = []
    for rdir in sorted(ROUNDS.iterdir()):
        if not (rdir / "report.md").exists():
            continue
        report = (rdir / "report.md").read_text()
        findings = parse_report_tables(report)
        for f in findings:
            examples.append(report_examples(f))
        events_f = rdir / "events.json"
        if events_f.exists():
            try:
                events = json.loads(events_f.read_text())
                examples.extend(agentic_examples(events, "192.168.1.46"))
            except Exception:
                pass

    if args.synthetic:
        examples.extend(synthetic_examples(args.synthetic))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for ex in examples:
            fh.write(json.dumps(ex) + "\n")
    n_agent = sum(1 for e in examples if "Tool '" in e["messages"][1]["content"])
    n_syn = args.synthetic
    print(f"[export_dataset] wrote {len(examples)} examples -> {out}")
    print(f"  real report-writing: {len(examples) - n_agent - n_syn} | agentic: {n_agent} | synthetic: {n_syn}")


if __name__ == "__main__":
    main()
