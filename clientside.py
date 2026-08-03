"""
MRBOOM // CLIENT-SIDE WEB ASSESSMENT
Static analysis of web client surfaces: cookie hardening, CSP/SRI,
service workers, WebSockets, DOM-XSS sinks, and third-party inventory.
Safe, non-intrusive — fetches pages and bundles like a browser would.
"""
import json, re, uuid, urllib.request, urllib.error, urllib.parse, ssl, socket, threading
from datetime import datetime, timezone
import stealth

def now(): return datetime.now(timezone.utc).strftime("%H:%M:%S")

_dns_cache = {}
_dns_lock = threading.Lock()

def _resolve_host(host, timeout=4):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:
        return host
    key = host.lower()
    with _dns_lock:
        if key in _dns_cache:
            return _dns_cache[key]
    out = [None]
    def _look():
        try:
            out[0] = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except Exception:
            out[0] = None
    t = threading.Thread(target=_look, daemon=True)
    t.start()
    t.join(timeout)
    result = out[0]
    with _dns_lock:
        _dns_cache[key] = result
    return result

def _find(sev, score, title, asset, tool, cwe, evidence, fix, retest="—"):
    return {"id": str(uuid.uuid4())[:8], "severity": sev, "score": score,
            "title": title, "asset": asset, "tool": tool, "cwe": cwe,
            "evidence": evidence, "exploitable": False, "fix": fix,
            "retest": retest, "proof": None}

def _get(url, timeout=8):
    try:
        parsed = urllib.parse.urlparse(url)
        ip = _resolve_host(parsed.hostname, timeout=min(4, timeout))
        if ip is None:
            return None, {}, "", None
        conn_url = urllib.parse.urlunparse(parsed._replace(netloc=ip + ((":" + str(parsed.port)) if parsed.port else "")))
        req = urllib.request.Request(conn_url, headers={**stealth.headers(), "Host": parsed.netloc})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", "ignore")
        return resp.status, dict(resp.headers), body, resp.url
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), "", None
    except Exception:
        return None, {}, "", None

# ─── COOKIES ──────────────────────────────────────────────────────────────
def _analyze_cookies(asset, headers, findings):
    setc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not setc:
        return
    cookies = setc.split("\n") if "\n" in setc else [setc]
    for raw in cookies:
        name = raw.split("=")[0].strip()
        flags = raw.lower()
        probs = []
        if "secure" not in flags:
            probs.append("Secure flag missing")
        if "httponly" not in flags:
            probs.append("HttpOnly flag missing")
        if "samesite" not in flags:
            probs.append("SameSite attribute missing")
        elif "samesite=none" in flags:
            probs.append("SameSite=None allows cross-site sends")
        if probs:
            findings.append(_find(
                "MEDIUM", 48,
                f"Cookie hardening: {name}", asset, "clientside", "CWE-614",
                f"{raw.split(';')[0]} → {', '.join(probs)}",
                f"Set {name} with Secure; HttpOnly; SameSite=Lax (or Strict)."))

# ─── CSP / SRI ────────────────────────────────────────────────────────────
def _analyze_security_headers(asset, headers, findings):
    csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
    if not csp:
        findings.append(_find(
            "MEDIUM", 48, "Missing Content-Security-Policy", asset,
            "clientside", "CWE-693",
            "No CSP header returned",
            "Set a Content-Security-Policy restricting script-src and object-src."))
    else:
        bad = []
        if re.search(r"(^|[\s;])script-src[^;]*'unsafe-inline'", csp): bad.append("script-src 'unsafe-inline'")
        if re.search(r"(^|[\s;])script-src[^;]*'unsafe-eval'", csp): bad.append("script-src 'unsafe-eval'")
        if "default-src" not in csp and "script-src" not in csp: bad.append("no default-src/script-src")
        if bad:
            findings.append(_find(
                "MEDIUM", 48, "Weak Content-Security-Policy", asset,
                "clientside", "CWE-693",
                f"{'; '.join(bad)} present in: {csp[:200]}",
                "Remove unsafe-inline/unsafe-eval; pin sources with nonces/hashes."))
    if headers.get("X-Frame-Options") is None and headers.get("content-security-policy") is None:
        findings.append(_find(
            "LOW", 24, "No clickjacking protection", asset,
            "clientside", "CWE-1021",
            "Missing X-Frame-Options / frame-ancestors",
            "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    if headers.get("Referrer-Policy") is None:
        findings.append(_find(
            "LOW", 24, "Missing Referrer-Policy", asset,
            "clientside", "CWE-200",
            "No Referrer-Policy header",
            "Set Referrer-Policy: strict-origin-when-cross-origin."))
    if headers.get("Strict-Transport-Security") is None and str(asset).startswith("https"):
        findings.append(_find(
            "LOW", 24, "Missing HSTS", asset, "clientside", "CWE-319",
            "No Strict-Transport-Security header",
            "Set Strict-Transport-Security with a long max-age."))

# ─── SERVICE WORKERS ──────────────────────────────────────────────────────
_SW_PATHS = ["/sw.js", "/service-worker.js", "/serviceworker.js", "/sw/index.js"]

def _analyze_service_workers(asset, findings):
    for path in _SW_PATHS:
        status, _, body, _ = _get(asset.rstrip("/") + path, timeout=6)
        if status == 200 and body:
            issues = []
            if "self.addEventListener('message'" in body or '"message"' in body:
                issues.append("message handler present")
            if "postMessage" in body and "event.data" in body:
                issues.append("may pass untrusted event.data to fetch")
            findings.append(_find(
                "LOW" if not issues else "MEDIUM", 24 if not issues else 48,
                "Service worker in use", asset, "clientside", "CWE-346",
                f"{path} ({len(body)} bytes){(' — ' + ', '.join(issues)) if issues else ''}",
                "Validate messages from clients and scope the worker tightly."))

# ─── WEBSOCKETS ───────────────────────────────────────────────────────────
_WS_RE = re.compile(r'''(["'])(wss?://[^"'\s\\]+)''')

def _analyze_websockets(asset, body, findings):
    found = set(m.group(2) for m in _WS_RE.finditer(body))
    for ws in sorted(found):
        findings.append(_find(
            "LOW", 24, "WebSocket endpoint exposed", asset, "clientside", "CWE-384",
            ws,
            f"Confirm {ws} requires auth (cookies/Origin check) and validates messages."))

# ─── DOM-XSS SINKS ────────────────────────────────────────────────────────
_SINKS = [
    ("innerHTML", r"\.innerHTML\s*="),
    ("outerHTML", r"\.outerHTML\s*="),
    ("document.write", r"document\.write\s*\("),
    ("eval()", r"(?:window\.)?eval\s*\("),
    ("Function()", r"new\s+Function\s*\("),
    ("setTimeout(str)", r"setTimeout\s*\(\s*[\"'\`]"),
    ("setInterval(str)", r"setInterval\s*\(\s*[\"'\`]"),
    ("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\("),
]
_SOURCES = [
    ("location", r"(?:location|window\.location)(?:\.hash|\.search|\.href|\.pathname)?\b"),
    ("document.referrer", r"document\.referrer"),
    ("postMessage", r"\.postMessage\s*\(|addEventListener\s*\(\s*['\"]message['\"]"),
    ("URL params", r"(?:getParameter|URLSearchParams)"),
    ("localStorage", r"localStorage\s*\.\s*getItem"),
    ("window.name", r"window\.name"),
]

def _analyze_dom_xss(asset, body, findings):
    sinks = []
    for label, pat in _SINKS:
        for m in re.finditer(pat, body):
            line = body[max(0, m.start()-90):m.end()+90].replace("\n", " ")
            sinks.append((label, line.strip()))
    src_count = sum(1 for _, pat in _SOURCES if re.search(pat, body))
    if sinks and src_count:
        used = {label for label, _ in sinks}
        findings.append(_find(
            "MEDIUM", 48, "Potential DOM-XSS sink usage", asset, "clientside", "CWE-79",
            f"Sources seen: {src_count} sink types: {', '.join(sorted(used))}",
            "Sanitize untrusted input before reaching sinks; use textContent, not innerHTML."))
    elif sinks:
        used = {label for label, _ in sinks}
        findings.append(_find(
            "LOW", 24, "Dangerous DOM sink present", asset, "clientside", "CWE-79",
            f"HTML/exec sinks used: {', '.join(sorted(used))}",
            "Escape data before sinks and avoid eval/Function/document.write."))

# ─── THIRD-PARTY INVENTORY ────────────────────────────────────────────────
def _analyze_third_party(asset, body, findings):
    third = set()
    for m in re.finditer(r'''<(?:script|iframe|link|img)[^>]+(?:src|href)=["'](https?://[^"'?]+)''', body, re.I):
        u = m.group(1)
        if not re.match(r'https?://(?:www\.)?(?:[a-z0-9-]+\.)?' + re.escape(re.sub(r'https?://(?:www\.)?', '', urllib.parse.urlparse(asset).netloc).split(':')[0]) + r'(?:[./:]|$)', u, re.I):
            third.add(u)
    for u in sorted(third):
        findings.append(_find(
            "LOW", 24, "Third-party resource loaded", asset, "clientside", "CWE-829",
            u,
            "Inventory external dependencies; pin + integrity-check and review their supply chain."))

# ─── SRI CHECK ────────────────────────────────────────────────────────────
def _analyze_sri(asset, body, findings):
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.I)
    without_sri = [s for s in scripts if not re.search(r'\bintegrity\s*=', body[body.find(s)-200:body.find(s)+len(s)+50])]
    if len(scripts) > 0 and without_sri:
        findings.append(_find(
            "LOW", 24, "Scripts loaded without SRI", asset, "clientside", "CWE-353",
            f"{len(without_sri)}/{len(scripts)} external scripts lack integrity= (e.g. {without_sri[0]})",
            "Add integrity+SRI to all third-party scripts."))

# ─── MAIN ─────────────────────────────────────────────────────────────────
def scan_clientside(urls, domain=""):
    """Assess client-side security posture of the given URLs. Returns findings list."""
    findings = []
    seen = set()
    for url in urls[:10]:
        status, headers, body, final = _get(url, timeout=8)
        if status is None or not body:
            continue
        asset = final or url
        if asset in seen:
            continue
        seen.add(asset)
        _analyze_cookies(asset, headers, findings)
        _analyze_security_headers(asset, headers, findings)
        _analyze_service_workers(asset, findings)
        _analyze_websockets(asset, body, findings)
        _analyze_dom_xss(asset, body, findings)
        _analyze_third_party(asset, body, findings)
        _analyze_sri(asset, body, findings)
        # also scan referenced JS bundles for sinks
        for js in re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:[^"\']*))["\']', body, re.I)[:5]:
            js_url = urllib.parse.urljoin(asset, js)
            st, _, jb, _ = _get(js_url, timeout=6)
            if st == 200 and jb:
                _analyze_dom_xss(js_url, jb, findings)
    return findings

if __name__ == "__main__":
    import sys
    stealth.init()
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    for f in scan_clientside([target]):
        print(f"{f['severity']:7} [{f['cwe']}] {f['title']} :: {f['evidence'][:120]}")
