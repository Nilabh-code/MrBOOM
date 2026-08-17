"""
MRBOOM // NUCLEI-GEN — generate Nuclei YAML templates from findings.
Turns engine/app findings (dicts) or a findings JSON file into a set of
reproducible Nuclei templates so results can be re-verified offline or
fed into `nuclei -t out/ -l targets.txt`.

Supported finding shapes:
  - {title, asset, severity, evidence, cwe, tool, ...}   (engine findings)
  - nuclei jsonl-style {name, host, 'template-id', 'matched-at', severity}

Output: one .yaml per finding, deduped by (title|name, asset).
"""
import os, re, json, argparse, hashlib

def _slug(s, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return s[:maxlen].rstrip("-") or "finding"

def _norm_sev(sev):
    m = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low","INFO":"info"}
    return m.get(str(sev).upper(), "medium")

def _host_from_asset(asset):
    a = str(asset or "")
    a = re.sub(r"^[a-z]+://", "", a)
    return a.split("/")[0] or "host"

def _yaml_str(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'

def _matchers(finding):
    """Derive matchers from evidence/title. Falls back to a status+word matcher."""
    evid = str(finding.get("evidence") or finding.get("matched-at") or "")
    title = str(finding.get("title") or finding.get("name") or "")
    m = []
    # pull a distinctive keyword from evidence (longest alpha token)
    words = re.findall(r"[A-Za-z_]{6,}", evid)
    if words:
        kw = max(words, key=len)
        m.append({"type":"word","words":[kw]})
    else:
        m.append({"type":"status","status":[200,301,302]})
    return m, title or evid or "finding"

def gen_template(finding, base_url=None):
    """Return a Nuclei template dict for one finding."""
    title = str(finding.get("title") or finding.get("name") or "generated")
    asset = finding.get("asset") or finding.get("host") or ""
    sev = _norm_sev(finding.get("severity") or finding.get("level") or "medium")
    cve = str(finding.get("cwe") or finding.get("template-id") or "").strip()
    evid = str(finding.get("evidence") or finding.get("matched-at") or "")

    tid = _slug(title)
    # ensure id uniqueness per (title, asset)
    h = hashlib.sha1(f"{title}|{asset}".encode()).hexdigest()[:6]
    tid = f"{tid}-{h}"

    path = "/"
    a = str(asset)
    if "://" in a:
        path = re.sub(r"^[a-z]+://[^/]+", "", a) or "/"
    matchers, desc = _matchers(finding)

    template = {
        "id": tid,
        "info": {
            "name": f"{title} (auto-generated)",
            "author": ["mrboom"],
            "severity": sev,
            "description": desc[:300],
            "tags": "auto-generated," + (cve.lower() if cve else "retest"),
        },
    }
    if cve and cve.upper().startswith("CVE-"):
        template["info"]["classification"] = {"cve-id":[cve.upper()]}

    req = {
        "method": "GET",
        "path": ["{{BaseURL}}" + (path if path != "/" else "")],
        "matchers": [],
    }
    for mt in matchers:
        if mt["type"] == "word":
            req["matchers"].append({"type":"word","words":mt["words"],"part":"body"})
        elif mt["type"] == "status":
            req["matchers"].append({"type":"status","status":mt["status"]})
    template["requests"] = [req]
    return template, tid

def _to_yaml(obj, indent=0):
    sp = "  " * indent
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out.append(f"{sp}{k}:")
                out.append(_to_yaml(v, indent + 1))
            else:
                out.append(f"{sp}{k}: {_yaml_str(v)}")
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, dict):
                sub = _to_yaml(v, indent + 1).lstrip()
                first, _, rest = sub.partition("\n")
                out.append(f"{sp}- {first}")
                if rest:
                    out.append(rest)
            else:
                out.append(f"{sp}- {_yaml_str(v)}")
    return "\n".join(out)

def generate(findings, out_dir="nuclei_out"):
    """Write one template per finding. Returns list of written paths."""
    os.makedirs(out_dir, exist_ok=True)
    seen, paths = set(), []
    for f in findings:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title") or f.get("name") or "")
        asset = f.get("asset") or f.get("host") or ""
        key = f"{title}|{asset}"
        if not title or key in seen:
            continue
        seen.add(key)
        tpl, tid = gen_template(f)
        path = os.path.join(out_dir, f"{tid}.yaml")
        with open(path, "w") as fh:
            fh.write(_to_yaml(tpl) + "\n")
        paths.append(path)
    return paths

def load_findings(path):
    """Load findings from .json (list or {findings:[...]}) or .jsonl."""
    if path.endswith(".jsonl"):
        out = []
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
        return out
    with open(path) as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        for k in ("findings", "results", "data"):
            if isinstance(data.get(k), list):
                return data[k]
        return [data]
    return data if isinstance(data, list) else []

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="MrBOOM Nuclei template generator")
    ap.add_argument("--findings", required=True, help="findings json/jsonl file")
    ap.add_argument("--out", default="nuclei_out", help="output directory")
    a = ap.parse_args()
    found = load_findings(a.findings)
    paths = generate(found, a.out)
    print(f"wrote {len(paths)} template(s) to {a.out}/")
    for p in paths:
        print(" ", p)
