"""
bb_web_validation: configuration-level web security validations that a mature
pentest covers beyond exploit probes. Runs a battery of checks across live URLs:
TLS posture, cipher/cert quality, dangerous HTTP methods, cookie flags,
directory listing, admin/auth exposure, unauthenticated API exposure,
information disclosure, login rate limiting, security.txt, CORS credential
behavior, host-header injection / cache-poisoning indicators, CSP bypass,
clickjacking, CRLF injection, and open redirects.

Results are finding dicts compatible with the main findings/scorecard model.
"""

import json, re, socket, ssl, urllib.request, urllib.error, urllib.parse
from datetime import datetime

# Non-empty -> typ has a specific fix; else generic.
VALIDATION_FIXES = {
    "tls_old_version": "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
    "tls_1_2_only": "Enable TLS 1.3 where supported.",
    "weak_cipher": "Disable RC4/DES/3DES/CBC/NULL/export ciphers; use AEAD (TLS_AES_256_GCM or ChaCha20).",
    "cert_expiring": "Renew the TLS certificate before expiry; alert on <30d.",
    "self_signed_cert": "Replace self-signed certificate with a trusted CA-issued one.",
    "trace_enabled": "Disable HTTP TRACE to prevent cross-site tracing (XST).",
    "put_enabled": "Restrict HTTP PUT/DELETE to authenticated, allow-listed paths.",
    "method_options_permissive": "Restrict HTTP methods via server config (Allow header).",
    "cookie_flags": "Set Secure; HttpOnly; SameSite=Lax (or Strict) on all cookies.",
    "directory_listing": "Disable directory indexes; serve an index file or 403.",
    "admin_exposed": "Restrict admin/console paths by IP or auth; remove if unused.",
    "api_unauthenticated": "Require authentication on API endpoints handling sensitive data.",
    "server_banner": "Hide or strip the Server/X-Powered-By banner.",
    "powered_by": "Remove the X-Powered-By header.",
    "stack_trace": "Disable debug mode; sanitize stack traces in production.",
    "no_rate_limit": "Enforce login rate limiting / account lockout.",
    "missing_security_txt": "Publish a security.txt with contact + policy.",
    "cors_credentialed": "Never reflect arbitrary origins with Access-Control-Allow-Credentials: true.",
    "cors_reflect": "Restrict Access-Control-Allow-Origin to trusted origins.",
    "host_header_injection": "Validate the Host header; use absolute URLs internally.",
    "csp_weak": "Remove unsafe-inline/unsafe-eval/wildcards from the CSP.",
    "missing_csp": "Add a Content-Security-Policy restricting script-src and object-src.",
    "clickjacking": "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
    "crlf_injection": "Sanitize CR/LF from user input before reflecting in headers.",
    "open_redirect": "Validate redirect targets against an allow-list.",
    "cache_indicators": "Verify caching is unkeyed-input-safe (host/path keys).",
    "security_txt": "Good: security.txt is present.",
    "tls_issuer": "Informational: TLS issuer observed.",
}


def _headers():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_probe(host, port=443, timeout=6):
    """Best-effort TLS handshake: negotiated protocol, cipher, cert metadata."""
    try:
        ctx = _ssl_ctx()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                meta = {
                    "version": (getattr(tls, "version", lambda: "")() or ""),
                    "cipher": (tls.cipher() or ("", "", 0))[0],
                    "bits": (tls.cipher() or ("", "", 0))[2],
                }
                der = tls.getpeercert(binary_form=True)
                if der:
                    try:
                        from cryptography import x509
                        cert = x509.load_der_x509_certificate(der)
                        na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
                        meta["not_after"] = str(na)
                        meta["issuer"] = cert.issuer.rfc4514_string()
                    except Exception:
                        try:
                            meta["not_after"] = str(tls.getpeercert().get("notAfter", ""))
                        except Exception:
                            pass
                return meta
    except Exception as e:
        return {"error": str(e)[:80]}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _req(method, url, headers=None, body=None, timeout=6, no_redirect=False):
    """Low-level request returning (status, headers_dict, body_str)."""
    try:
        req = urllib.request.Request(url, data=body, headers={**_headers(), **(headers or {})}, method=method)
        if no_redirect:
            opener = urllib.request.build_opener(_NoRedirect)
            resp = opener.open(req, timeout=timeout, context=_ssl_ctx())
        else:
            resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx())
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", errors="ignore")
        except Exception:
            b = ""
        return e.code, dict(e.headers or {}), b
    except Exception:
        return 0, {}, ""


def bb_web_validation(urls, api_eps=None, domain="", timeout=90):
    """Run the validation battery across live URLs. Returns list of findings."""
    import time as _time
    t0 = _time.time()
    findings = []
    _seen = set()

    def _rec(typ, url, evidence, severity, cwe, title=None, extra=None):
        key = (typ, url, str(evidence)[:60])
        if key in _seen:
            return
        _seen.add(key)
        f = {
            "url": url, "type": typ, "evidence": str(evidence)[:400],
            "severity": severity, "cwe": cwe, "asset": domain or url,
            "score": {"critical": 95, "high": 85, "medium": 60, "low": 30, "info": 5}.get(severity.lower(), 50),
            "fix": VALIDATION_FIXES.get(typ, "Review configuration and apply hardening."),
        }
        if title:
            f["title"] = title
        if extra:
            f.update(extra)
        findings.append(f)

    def _live():
        return _time.time() - t0 < timeout

    hosts = []
    for u in (urls or [])[:8]:
        try:
            p = urllib.parse.urlparse(u)
            if p.hostname:
                hosts.append((p.hostname, p.scheme, u.rstrip("/")))
        except Exception:
            pass
    if not hosts:
        return findings

    # 1) TLS config + cipher suites + cert chain (parallel across unique hosts)
    import concurrent.futures as _cf
    tls_hosts = []
    for h, scheme, u in hosts:
        if scheme == "https" and h not in tls_hosts:
            tls_hosts.append(h)
    tls_meta = {}
    if tls_hosts and _live():
        with _cf.ThreadPoolExecutor(max_workers=min(5, len(tls_hosts))) as pool:
            futs = {pool.submit(tls_probe, h, 443): h for h in tls_hosts}
            for fut in _cf.as_completed(futs):
                h = futs[fut]
                try:
                    tls_meta[h] = fut.result()
                except Exception:
                    tls_meta[h] = {"error": "probe exception"}
    for h, scheme, u in hosts:
        if scheme != "https" or h not in tls_meta or not _live():
            continue
        meta = tls_meta[h]
        if not meta or meta.get("error"):
            _rec("tls_unreachable", u, f"TLS probe failed: {meta.get('error', '?')}", "low", "CWE-295", title="TLS probe failed")
            continue
        ver = meta.get("version", "")
        if ver and ("1.0" in ver or "1.1" in ver):
            _rec("tls_old_version", u, f"Negotiated {ver}", "high", "CWE-326", title="Outdated TLS version")
        if ver and "1.2" in ver and "1.3" not in ver:
            _rec("tls_1_2_only", u, f"Negotiated {ver} (no TLS 1.3)", "low", "CWE-326", title="TLS 1.3 not offered")
        cipher = meta.get("cipher", "")
        if cipher and any(w in cipher.lower() for w in ["rc4", "des", "3des", "cbc", "null", "export"]):
            _rec("weak_cipher", u, f"Negotiated weak cipher: {cipher} ({meta.get('bits', '?')} bits)", "high", "CWE-327", title="Weak TLS cipher")
        na = meta.get("not_after", "")
        if na:
            try:
                exp = datetime.strptime(na.split(" ")[0], "%Y-%m-%d")
                days = (exp - datetime.now()).days
                if days < 30:
                    _rec("cert_expiring", u, f"TLS cert expires {na} ({days}d)", "medium", "CWE-295", title="TLS certificate expiring soon")
            except Exception:
                pass
        if "self-signed" in (meta.get("issuer", "").lower()):
            _rec("self_signed_cert", u, f"Self-signed issuer: {meta.get('issuer', '?')}", "medium", "CWE-295", title="Self-signed TLS certificate")
        if meta.get("issuer"):
            _rec("tls_issuer", u, f"Issuer: {meta.get('issuer', '?')}", "info", "CWE-295", title="TLS issuer disclosed")

    # 2) Dangerous HTTP methods (OPTIONS/TRACE/PUT/DELETE)
    for h, scheme, u in hosts[:6]:
        if not _live():
            break
        for m in ["OPTIONS", "TRACE", "PUT", "DELETE"]:
            st, hdrs, _ = _req(m, u, headers={"Host": h})
            if m == "OPTIONS" and st == 200:
                allow = hdrs.get("Allow") or hdrs.get("Public") or ""
                if allow and any(x.strip().upper() in ("TRACE", "PUT", "DELETE") for x in allow.split(",")):
                    _rec("method_options_permissive", u, f"OPTIONS allows: {allow}", "medium", "CWE-749", title="Permissive HTTP methods advertised")
            if m == "TRACE" and st == 200:
                _rec("trace_enabled", u, "TRACE returns 200 (XST potential)", "high", "CWE-16", title="HTTP TRACE method enabled")
            if m == "PUT" and st in (200, 201, 204):
                _rec("put_enabled", u, f"PUT returns {st} (possible upload)", "medium", "CWE-650", title="HTTP PUT method enabled")

    # 3) Cookie flags (Secure / HttpOnly / SameSite)
    for h, scheme, u in hosts[:6]:
        try:
            st, hdrs, _ = _req("GET", u)
            if st not in (200, 301, 302):
                continue
            sc = hdrs.get("Set-Cookie", "")
            if not sc:
                continue
            for c in sc.split(", "):
                name = c.split("=")[0].strip()
                if not name or "=" not in c:
                    continue
                flags = c.lower()
                probs = []
                if "secure" not in flags:
                    probs.append("missing Secure")
                if "httponly" not in flags:
                    probs.append("missing HttpOnly")
                if "samesite" not in flags:
                    probs.append("missing SameSite")
                if probs:
                    _rec("cookie_flags", u, f"Cookie {name}: {', '.join(probs)}", "medium", "CWE-614", title="Insecure cookie flags", extra={"cookie": name})
        except Exception:
            continue

    # 4) Directory listing
    for h, scheme, u in hosts[:6]:
        for p in ["/", "/assets/", "/static/", "/uploads/", "/images/", "/css/", "/files/", "/downloads/"]:
            if not _live():
                break
            try:
                st, _, body = _req("GET", u.rstrip("/") + p)
                if st == 200 and body and ("Index of" in body or "Parent Directory" in body or "<title>Index of" in body):
                    _rec("directory_listing", u.rstrip("/") + p, "Directory listing exposed (Index of)", "medium", "CWE-548", title="Directory listing enabled")
                    break
            except Exception:
                continue

    # 5) Admin/auth path exposure
    for h, scheme, u in hosts[:4]:
        for p in ["/admin", "/admin/", "/administrator", "/manager", "/console", "/dashboard", "/wp-admin/", "/phpmyadmin/", "/user/login", "/account/login"]:
            if not _live():
                break
            try:
                st, _, body = _req("GET", u.rstrip("/") + p)
                low = (body or "").lower()
                if st in (200, 301, 302) and any(k in low for k in ["login", "password", "sign in", "dashboard", "admin", "console"]):
                    _rec("admin_exposed", u.rstrip("/") + p, f"Admin path returns {st}", "medium", "CWE-287", title="Admin interface exposed", extra={"path": p})
            except Exception:
                continue

    # 6) Unauthenticated API exposure
    api_targets = [ep for ep in (api_eps or [])[:25] if ep.startswith("/api/")]
    api_root = hosts[0][2] if hosts else ""
    for ep in api_targets:
        if not _live():
            break
        target = (api_root + ep) if not ep.startswith("http") else ep
        try:
            st, hdrs, _ = _req("GET", target)
            if st in (200, 201) and "json" in hdrs.get("Content-Type", "").lower():
                _rec("api_unauthenticated", target, f"Unauthenticated API returns {st} JSON", "medium", "CWE-306", title="Unauthenticated API endpoint")
        except Exception:
            continue

    # 7) Information disclosure (banner + stack traces)
    for h, scheme, u in hosts[:6]:
        try:
            _, hdrs, body = _req("GET", u)
            srv = hdrs.get("Server", "")
            ph = hdrs.get("X-Powered-By", "")
            if srv and any(k in srv.lower() for k in ["apache/", "nginx/", "iis/", "caddy", "tomcat", "jetty", "openresty", "gunicorn", "werkzeug", "express", "php/"]):
                _rec("server_banner", u, f"Server banner: {srv}", "low", "CWE-200", title="Web server version disclosed")
            if ph:
                _rec("powered_by", u, f"X-Powered-By: {ph}", "low", "CWE-200", title="Technology disclosed via X-Powered-By")
            low = (body or "").lower()
            if re.search(r"traceback \(most recent call last\)|stack trace|werkzeug debugger|/usr/lib/python[0-9.]+/site-packages|\.py\", line \d+|syntaxerror|valueerror: invalid|exception stack", low):
                _rec("stack_trace", u, "Debug/stack-trace information in response body", "medium", "CWE-209", title="Debug information disclosed")
        except Exception:
            continue

    # 8) Login rate limiting
    for h, scheme, u in hosts[:4]:
        if not _live():
            break
        target = u.rstrip("/") + "/login"
        try:
            statuses = []
            for _ in range(3):
                st, _, _ = _req("GET", target)
                statuses.append(st)
            if statuses and all(s in (200, 301, 302) for s in statuses):
                _rec("no_rate_limit", target, f"3 rapid requests to login returned no 429/lockout ({statuses})", "medium", "CWE-307", title="Login rate limiting absent")
        except Exception:
            continue

    # 9) security.txt
    for h, scheme, u in hosts[:3]:
        for p in ["/.well-known/security.txt", "/security.txt"]:
            try:
                st, _, body = _req("GET", u.rstrip("/") + p)
                if st == 200 and "contact" in (body or "").lower():
                    _rec("security_txt", u.rstrip("/") + p, f"security.txt present ({len(body)}b)", "info", "CWE-693", title="security.txt present")
                elif st != 200 and p == "/.well-known/security.txt":
                    _rec("missing_security_txt", u.rstrip("/") + p, f"security.txt not found ({st})", "info", "CWE-693", title="security.txt missing")
            except Exception:
                continue

    # 10) CORS credential behavior
    for h, scheme, u in hosts[:6]:
        try:
            evil = "https://evil.example"
            st, hdrs, _ = _req("GET", u, headers={"Origin": evil})
            if st == 0:
                continue
            acao = hdrs.get("Access-Control-Allow-Origin", "")
            if acao == evil or acao == "*":
                if hdrs.get("Access-Control-Allow-Credentials", "").lower() == "true":
                    _rec("cors_credentialed", u, f"ACAO reflects {evil} with credentials", "high", "CWE-942", title="CORS trusted origin with credentials")
                else:
                    _rec("cors_reflect", u, f"ACAO reflects arbitrary origin ({acao}) without credentials", "low", "CWE-942", title="CORS reflects arbitrary origins")
        except Exception:
            continue

    # 11) Host header injection / cache poisoning indicator
    for h, scheme, u in hosts[:6]:
        try:
            st, hdrs, body = _req("GET", u, headers={"Host": "evil.example.com"})
            if st == 0:
                continue
            if "evil.example.com" in (body or ""):
                _rec("host_header_injection", u, "Host header reflected in response body", "medium", "CWE-644", title="Host header reflected (injection/cache poisoning)")
            if hdrs.get("X-Cache") or hdrs.get("CF-Cache-Status") or hdrs.get("Age"):
                _rec("cache_indicators", u, f"Caching detected ({hdrs.get('X-Cache') or hdrs.get('CF-Cache-Status') or 'Age'}) — verify poisoning surface", "info", "CWE-525", title="Caching headers present")
        except Exception:
            continue

    # 12) CSP bypass / missing CSP + clickjacking
    for h, scheme, u in hosts[:6]:
        try:
            _, hdrs, _ = _req("GET", u)
            csp = hdrs.get("Content-Security-Policy", "")
            if csp:
                low = csp.lower()
                if "*" in low or "unsafe-inline" in low or "unsafe-eval" in low:
                    _rec("csp_weak", u, f"CSP allows unsafe sources: {csp[:120]}", "medium", "CWE-693", title="Weak Content-Security-Policy")
            else:
                _rec("missing_csp", u, "No Content-Security-Policy header", "medium", "CWE-693", title="Missing Content-Security-Policy")
            xfo = hdrs.get("X-Frame-Options", "")
            if not xfo and "frame-ancestors" not in csp.lower():
                _rec("clickjacking", u, "Missing X-Frame-Options / CSP frame-ancestors", "low", "CWE-1021", title="No clickjacking protection")
        except Exception:
            continue

    # 13) CRLF injection in reflected params (header response)
    for h, scheme, u in hosts[:4]:
        if not _live():
            break
        try:
            probe = "x=1%0d%0aX-Injected:1"
            target = u.rstrip("/") + ("&" if "?" in u else "/?") + probe
            st, hdrs, _ = _req("GET", target)
            if st and hdrs.get("X-Injected") == "1":
                _rec("crlf_injection", target, "CRLF reflected into response header (X-Injected)", "high", "CWE-93", title="CRLF header injection")
        except Exception:
            continue

    # 14) Open redirect (next/return/redirect params)
    for h, scheme, u in hosts[:4]:
        if not _live():
            break
        for pname in ["next", "redirect", "return", "url", "target", "dest", "redirect_uri", "continue"]:
            sep = "&" if "?" in u else "/?"
            target = u.rstrip("/") + sep + urllib.parse.quote(f"{pname}=//evil.example", safe="=/?&")
            try:
                st, hdrs, _ = _req("GET", target, no_redirect=True)
                loc = hdrs.get("Location", "")
                if st in (301, 302, 303, 307, 308) and "evil.example" in loc:
                    _rec("open_redirect", target, f"Redirects to {loc}", "medium", "CWE-601", title="Open redirect", extra={"redirect": loc})
                    break
            except Exception:
                continue

    return findings
