"""
MRBOOM // DISCLOSURE — responsible disclosure workflow
Turns confirmed findings into professional, legitimate disclosures:
GHSA-style advisory drafts, CVE request bodies, CVSS v3.1 scoring,
and a disclosure timeline tracker (90-day clock, vendor contact,
publication).

Disclosure policy (always): only disclose with authorization. Never
weaponize. Report to the vendor first, coordinate a fix, then publish.
This module generates DOCUMENTS — it never sends anything.

CLI:
  python disclosure.py advisory --finding findings.json [--vendor X]
  python disclosure.py cve --finding findings.json
  python disclosure.py cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  python disclosure.py timeline new --finding-id F1 --vendor X
  python disclosure.py timeline update --id 1 --status vendor-fixed
  python disclosure.py timeline list
"""
import argparse, json, math, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

# ─── CVSS v3.1 base score calculator ───────────────────────────────────
CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    # PR is scope-dependent in CVSS v3.1: L/H increase 0.62→0.68 and 0.27→0.50
    # when Scope is Changed.
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.50}},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 1.0, "C": 1.0},
}

def _roundup(x):
    return math.ceil(x * 10) / 10

def cvss3(vector):
    """Compute CVSS v3.1 Base Score from a vector string.
    Returns (score, severity, parsed)."""
    v = vector.strip().replace(" ", "").upper()
    if not v.startswith("CVSS:3.1/"):
        v = "CVSS:3.1/" + v
    parts = {}
    for tok in v.split("/")[1:]:
        if ":" in tok:
            k, val = tok.split(":", 1)
            parts[k] = val
    try:
        av = CVSS_METRICS["AV"][parts["AV"]]; ac = CVSS_METRICS["AC"][parts["AC"]]
        ui = CVSS_METRICS["UI"][parts["UI"]]
        s = parts["S"] if parts["S"] in ("U", "C") else "U"
        pr = CVSS_METRICS["PR"][s][parts["PR"]]
        c = {"H": 0.56, "L": 0.22, "N": 0.0}[parts["C"]]
        i = {"H": 0.56, "L": 0.22, "N": 0.0}[parts["I"]]
        a = {"H": 0.56, "L": 0.22, "N": 0.0}[parts["A"]]
    except KeyError:
        return None, "invalid vector", v
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if s == "U":
        impact = 6.42 * iss
    else:
        # changed-scope impact (verified against NVD, e.g. CVE-2021-45046 = 9.0)
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif s == "U":
        score = _roundup(min(impact + exploit, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploit), 10))
    sev = ("None" if score == 0 else "Low" if score < 4 else "Medium"
           if score < 7 else "High" if score < 9 else "Critical")
    return score, sev, v

def severity_for(score):
    if score is None: return "unknown"
    if score == 0: return "none"
    if score < 4: return "low"
    if score < 7: return "medium"
    if score < 9: return "high"
    return "critical"

# ─── Advisory draft (GHSA-style) ───────────────────────────────────────
def _fmt_date():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def draft_advisory(finding, vendor="", affected="", cwe="", cvss_vector=""):
    """Build a markdown security advisory draft from a finding dict."""
    title = finding.get("title", "Untitled finding")
    detail = finding.get("detail", "")
    score = sev = None
    if cvss_vector:
        score, sev, _ = cvss3(cvss_vector)
    elif finding.get("severity"):
        sev = finding.get("severity")
    sev_line = sev or "TBD"
    score_line = f"{score:.1f}" if score is not None else "TBD"
    vuln_class = finding.get("bug_class") or finding.get("class") or finding.get("sink") or "TBD"
    affected = affected or finding.get("asset") or "TBD"
    return f"""# Security Advisory: {title}

**Severity:** {sev_line} (CVSS {score_line})  |  **CWE:** {cwe or 'TBD'}
**Affected:** {affected}
**Vendor:** {vendor or 'TBD'}
**Reported:** {_fmt_date()}

## Summary
{detail[:1000]}

## Vulnerability Description
**Class:** {vuln_class}

(Expand: root cause, trigger conditions, reachable input paths.)

## Proof of Concept
(Paste minimal PoC — triggering test only. No weaponization.)

## Impact
(What an attacker could achieve: confidentiality/integrity/availability.)

## Remediation
(Recommended fix: input validation, bounds checks, proper free ordering, etc.)

## Timeline
- {_fmt_date()} — Discovered
- TBD — Vendor contacted
- TBD — Vendor acknowledged
- TBD — Fix released
- TBD — Coordinated disclosure

## Credit
Nilabh (agrobothex@gmail.com) via MrBOOM
"""

# ─── CVE request body (GitHub CNA / MITRE CVE form) ────────────────────
def cve_request(finding, vendor="", affected="", cwe=""):
    title = finding.get("title", "Untitled")
    detail = finding.get("detail", "")
    return f"""CVE REQUEST — {title}

1. **Vulnerability Type:** {finding.get('bug_class') or finding.get('sink') or 'TBD'}
2. **Vendor of the product:** {vendor or 'TBD'}
3. **Affected Product/Version:** {affected or finding.get('asset') or 'TBD'}
4. **CWE:** {cwe or 'TBD'}
5. **Description:** {detail[:1200]}
6. **Proof of Concept:** (attach minimized reproducer; triggering test only)
7. **Impact:** (describe CIA impact; CVSS vector if computed)
8. **Suggested remediation:** (if known)
9. **Discoverer:** Nilabh (agrobothex@gmail.com)
10. **Disclosure state:** vendor contacted, fix coordinated, publication pending
"""

# ─── Timeline tracker ──────────────────────────────────────────────────
TIMELINE_PATH = os.environ.get("MRBOOM_TIMELINE", "~/.mrboom/disclosure_timeline.jsonl")

def _tl_path():
    p = Path(TIMELINE_PATH).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def tl_new(finding_id, vendor, notes=""):
    entry = {"id": None, "finding_id": finding_id, "vendor": vendor,
             "status": "discovered", "discovery_date": _fmt_date(),
             "vendor_contacted": "", "vendor_response": "",
             "fix_status": "", "publication_date": "", "notes": notes,
             "created": datetime.now(timezone.utc).isoformat()}
    entries = tl_list()
    entry["id"] = (max((e.get("id", 0) for e in entries), default=0) + 1)
    with open(_tl_path(), "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry

def tl_update(id_, **fields):
    entries = tl_list()
    for e in entries:
        if e.get("id") == id_:
            for k, v in fields.items():
                if k in e:
                    e[k] = v
            break
    with open(_tl_path(), "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return entries

def tl_list():
    p = _tl_path()
    if not p.exists(): return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

def tl_summary():
    entries = tl_list()
    counts = {}
    for e in entries:
        counts[e.get("status", "?")] = counts.get(e.get("status", "?"), 0) + 1
    return {"total": len(entries), "by_status": counts,
            "overdue_90d": [e for e in entries
                            if e.get("status") not in ("published", "vendor-fixed", "withdrawn")
                            and _days_since(e.get("discovery_date", "")) > 90]}

def _days_since(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
        return (datetime.now(timezone.utc).date() - d.date()).days
    except Exception:
        return 0

# ─── CLI ───────────────────────────────────────────────────────────────
def _load_finding(path):
    data = json.loads(Path(path).read_text())
    return data if isinstance(data, dict) else (data[0] if isinstance(data, list) and data else {})

def main():
    ap = argparse.ArgumentParser(description="MrBOOM Disclosure Workflow")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("advisory", help="draft a GHSA-style advisory")
    p.add_argument("--finding", required=True)
    p.add_argument("--vendor", default="")
    p.add_argument("--affected", default="")
    p.add_argument("--cwe", default="")
    p.add_argument("--cvss", default="")

    p = sub.add_parser("cve", help="draft a CVE request body")
    p.add_argument("--finding", required=True)
    p.add_argument("--vendor", default="")
    p.add_argument("--affected", default="")
    p.add_argument("--cwe", default="")

    p = sub.add_parser("cvss", help="compute CVSS v3.1 score")
    p.add_argument("vector", help="e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    p = sub.add_parser("timeline", help="disclosure timeline tracker")
    ts = p.add_subparsers(dest="tcmd", required=True)
    t1 = ts.add_parser("new"); t1.add_argument("--finding-id", required=True)
    t1.add_argument("--vendor", required=True); t1.add_argument("--notes", default="")
    t2 = ts.add_parser("update"); t2.add_argument("--id", type=int, required=True)
    for f in ("status", "vendor_contacted", "vendor_response", "fix_status", "publication_date", "notes"):
        t2.add_argument(f"--{f}", default=None)
    ts.add_parser("list")
    ts.add_parser("summary")

    a = ap.parse_args()
    if a.cmd == "cvss":
        score, sev, vec = cvss3(a.vector)
        print(json.dumps({"vector": vec, "score": score, "severity": sev}, indent=2))
    elif a.cmd == "advisory":
        print(draft_advisory(_load_finding(a.finding), a.vendor, a.affected, a.cwe, a.cvss))
    elif a.cmd == "cve":
        print(cve_request(_load_finding(a.finding), a.vendor, a.affected, a.cwe))
    elif a.cmd == "timeline":
        if a.tcmd == "new":
            print(json.dumps(tl_new(a.finding_id, a.vendor, a.notes), indent=2))
        elif a.tcmd == "update":
            fields = {k: v for k, v in vars(a).items() if k in
                      ("status", "vendor_contacted", "vendor_response", "fix_status", "publication_date", "notes")
                      and v is not None}
            print(json.dumps(tl_update(a.id, **fields), indent=2))
        elif a.tcmd == "list":
            print(json.dumps(tl_list(), indent=2))
        elif a.tcmd == "summary":
            print(json.dumps(tl_summary(), indent=2))

if __name__ == "__main__":
    main()
