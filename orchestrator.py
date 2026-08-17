"""MrBOOM LLM Orchestrator — the model drives the engagement.

Instead of a fixed stage sequence, the LLM receives a condensed live picture
of the attack surface after every tool result and decides the next move
(recon, fingerprint, targeted probes, attacks, or finish). The harness:

- exposes a registry of hardened probe tools (all in-scope guarded)
- executes the chosen action and feeds the result back
- enforces hard caps (steps, wall-clock, per-tool timeouts)
- reuses the one-shot pipeline's report/memory/history infrastructure
"""

import json
import os
import re
import time
import traceback
import urllib.parse
import urllib.request
import urllib.error
import ssl

MAX_STEPS = 10000
TIME_BUDGET_S = 86400  # 24h — step cap governs the hunt

# Shared quick-tunnel / CDN-provider apexes: a hostname under these has NO
# subdomain tree of its own — enumerating just surfaces other people's tunnels.
SHARED_TUNNEL_APEXES = (
    "trycloudflare.com", "cloudflaretunnel.com", "argotunnel.com",
    "ngrok.io", "ngrok.app", "ngrok.dev", "ngrok-free.app",
    "tunnelmole.com", "loca.lt", "serveo.net", "bore.pub",
    "pagekite.net", "r2.dev", "workers.dev",
)


def is_shared_tunnel(domain):
    d = (domain or "").lower().strip(".")
    return any(d == a or d.endswith("." + a) for a in SHARED_TUNNEL_APEXES)

_tool_fns = {}
_ACTIVE_ENG = None  # set by run_llm so fanout jobs pass the scope gate too


def _register(name, fn, desc, params):
    _tool_fns[name] = {"fn": fn, "desc": desc, "params": params}
    return fn


def tool_specs(app_mod):
    """One-line-per-tool spec list injected into the orchestrator prompt."""
    _ensure_tools(app_mod)
    return "\n".join(
        f"- {n}: {m['desc']} params={{{', '.join(m['params'])}}}"
        for n, m in _tool_fns.items()
    )


def _ensure_tools(app_mod):
    if _tool_fns:
        return

    # ── HTTP helpers (shared) ─────────────────────────────────────────
    def _get(url, timeout=8, headers=None, host_header=None, no_redirect=False):
        try:
            return app_mod.http_get(url, timeout=timeout, host_header=host_header,
                                    no_redirect=no_redirect, extra_headers=headers)
        except Exception as e:
            return 0, {}, str(e)[:120]

    def _post(url, payload=None, headers=None, timeout=8):
        data = json.dumps(payload).encode() if isinstance(payload, (dict, list)) else (
            (payload.encode() if isinstance(payload, str) else None))
        hdrs = app_mod.stealth.headers(headers or {})
        if data and "Content-Type" not in hdrs:
            hdrs["Content-Type"] = "application/json"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            resp = urllib.request.urlopen(urllib.request.Request(url, data=data, headers=hdrs, method="POST"),
                                          timeout=timeout, context=ctx)
            return resp.status, dict(resp.headers), app_mod._read_body(resp)
        except urllib.error.HTTPError as e:
            try:
                body = app_mod._read_body(e)
            except Exception:
                body = ""
            return e.code, dict(e.headers or {}), body
        except Exception as e:
            return 0, {}, str(e)[:140]

    # ── TOOLS ─────────────────────────────────────────────────────────
    def _t_resolve_host(host):
        ip = app_mod._resolve_host(host, timeout=5)
        return {"host": host, "ip": ip}
    _register("resolve_host", _t_resolve_host,
              "Resolve a hostname to its IP. Use to build the surface and spot wildcard DNS (many names -> same IP).",
              ["host"])

    def _t_http_probe(urls):
        out = []
        for u in list(urls or [])[:10]:
            st, h, b = app_mod.http_get_retry(u, timeout=7)
            out.append({
                "url": u, "status": st, "server": h.get("Server", ""),
                "final_url": h.get("Location", "")[:200],
                "tech": app_mod.detect_tech(st, h, b or ""),
                "title": re.search(r"<title[^>]*>([^<]{1,90})", b or "", re.I).group(1).strip() if re.search(r"<title[^>]*>([^<]{1,90})", b or "", re.I) else "",
            })
        return {"results": out}
    _register("http_probe", _t_http_probe,
              "Probe URLs/hosts for liveness: status, server, tech stack, redirect target, title. Feed it full URLs (https://host/).",
              ["urls"])

    def _t_fetch_page(url):
        st, h, b = _get(url, timeout=9)
        return {"url": url, "status": st, "headers": dict(h), "body": (b or "")[:6000]}
    _register("fetch_page", _t_fetch_page,
              "GET a single URL; return headers + first 6KB of the body. Use for deep inspection of one interesting page (admin panel, API response, config).",
              ["url"])

    def _t_subdomain_enum(domain):
        subs = app_mod.pd_subfinder(domain, timeout=45)
        if not subs:
            subs = app_mod.pd_assetfinder(domain, timeout=30)
        subs = subs or []
        extra = []
        try:
            extra = app_mod.bb_subdomain_bruteforce(domain, timeout=25)
        except Exception:
            pass
        total = sorted(set(subs) | set(extra))
        return {"domain": domain, "subdomains": total[:400], "count": len(total)}
    _register("subdomain_enum", _t_subdomain_enum,
              "Enumerate subdomains (passive + wordlist brute). Returns names only; probe them with http_probe afterwards.",
              ["domain"])

    def _t_dns_enum(domain):
        recs = app_mod.pd_dnsx(domain, timeout=20) or {}
        return {"domain": domain, "records": recs}
    _register("dns_enum", _t_dns_enum,
              "Enumerate DNS records (A/AAAA/MX/NS/TXT) for a domain.",
              ["domain"])

    def _t_whois(domain):
        out = {"domain": domain}
        ok, txt = app_mod.run_pd("whois", [domain], timeout=15)
        if ok and txt:
            for line in txt.splitlines():
                ll = line.lower().strip()
                if any(k in ll for k in ("orgname", "adminname", "org-name", "registrant", "created", "registrar", "country")):
                    out.setdefault("lines", []).append(line.strip())
            out["lines"] = out.get("lines", [])[:15]
        else:
            out["error"] = txt[:100]
        return out
    _register("whois", _t_whois,
              "WHOIS lookup for org/registrant/registrar intel.",
              ["domain"])

    def _t_port_scan(hosts):
        hosts = list(hosts or [])[:8]
        results = {}
        for host in hosts:
            try:
                r = app_mod.port_scan(host, [])
                if r:
                    results[host] = r
            except Exception:
                continue
        return {"ports": results}
    _register("port_scan", _t_port_scan,
              "TCP scan the ~160 most common ports on up to 8 hosts/IPs. Finds ssh/db/redis/docker/admin consoles.",
              ["hosts"])

    def _t_tech_fingerprint(url):
        st, h, b = app_mod.http_get_retry(url, timeout=8)
        base_tech = app_mod.detect_tech(st, h, b or "")
        try:
            ext = app_mod.bb_tech_fingerprint_extended(h, b or "")
        except Exception:
            ext = []
        return {"url": url, "status": st, "tech": sorted(set((base_tech or []) + (ext or [])))}
    _register("tech_fingerprint", _t_tech_fingerprint,
              "Deep tech stack fingerprint of ONE URL (server, CMS, framework, CDN, analytics).",
              ["url"])

    def _t_dirbust(urls):
        try:
            results, fp_stats = app_mod.bb_dirbust(list(urls or [])[:5], timeout=45)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"dirs": {k: (v or [])[:30] for k, v in (results or {}).items()}, "catchall_fp": (fp_stats or {}).get("false_positives", 0)}
    _register("dirbust", _t_dirbust,
              "Directory/wordlist enumeration against up to 5 live URLs. Catch-all/soft-404 false positives already filtered.",
              ["urls"])

    def _t_fuzz(url):
        res = app_mod.pd_ffuf(url) or app_mod.pd_gobuster(url) or []
        return {"url": url, "hits": [{"url": r.get("url", ""), "status": r.get("status"), "size": r.get("size", r.get("words", ""))} for r in res[:40]]}
    _register("fuzz", _t_fuzz,
              "Fast ffuf/gobuster content fuzz of ONE live base URL (FUZZ on root). Good for admin panels, api roots, hidden files.",
              ["url"])

    def _t_js_analysis(urls):
        try:
            r = app_mod.bb_js_assets(list(urls or [])[:8], timeout=45)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"js": r}
    _register("js_analysis", _t_js_analysis,
              "Download JS bundles of up to 8 pages; extract API endpoints, hardcoded secrets, GraphQL operations, third-party SDK hosts.",
              ["urls"])

    def _t_wayback(domain):
        wb = app_mod.bb_wayback_machine(domain, timeout=20) or {}
        try:
            sec = app_mod.bb_wayback_secrets(domain, timeout=25) or []
        except Exception:
            sec = []
        return {"domain": domain, "urls": (wb.get("urls") or [])[:100], "count": wb.get("count", 0), "secrets": sec}
    _register("wayback", _t_wayback,
              "Wayback Machine: historical URLs of the domain + archived pages that leaked secrets. Great source of old/hidden endpoints.",
              ["domain"])

    def _t_api_probe(base, paths, method="GET"):
        base = base.rstrip("/")
        out = []
        for p in list(paths or [])[:20]:
            u = base + (p if p.startswith("/") else "/" + p)
            if method.upper() == "POST":
                st, _, b = _post(u, payload={}, timeout=7)
            else:
                st, _, b = app_mod.http_get_retry(u, timeout=7)
            out.append({"url": u, "status": st, "body": (b or "")[:200]})
            time.sleep(0.1)
        return {"results": out}
    _register("api_probe", _t_api_probe,
              "Probe up to 20 API paths on one base URL (GET or POST), returning status+body. Use to enumerate real API routes (401/403 vs 200 vs 404).",
              ["base", "paths", "method"])

    def _t_login_bruteforce(url, username="ratelimit-probe@invalid.example", count=8):
        codes, bodies = [], []
        cnt = min(int(count or 8), 15)
        for i in range(cnt):
            payload = urllib.parse.urlencode({"email": username, "password": f"MrBOOM-rate-probe-{i}"}).encode()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                req = urllib.request.Request(url, data=payload, method="POST",
                                             headers=app_mod.stealth.headers({"Content-Type": "application/x-www-form-urlencoded"}))
                resp = urllib.request.urlopen(req, timeout=8, context=ctx)
                body = app_mod._read_body(resp)[:200]
                codes.append(resp.status)
            except urllib.error.HTTPError as e:
                body = app_mod._read_body(e)[:200] if e else ""
                codes.append(e.code)
            except Exception:
                codes.append(0); body = ""
            bodies.append(body)
            time.sleep(0.05)
        throttled = any(c == 429 for c in codes) or any("retry_seconds" in b or "too many" in b.lower() for b in bodies)
        shapes = sorted(set(codes))
        return {
            "url": url, "codes": codes, "rate_limited": throttled,
            "note": ("throttled (429/lockout observed)" if throttled else
                     f"NO throttling observed across {cnt} rapid failed attempts (auth status shapes: {shapes})")
        }
    _register("login_bruteforce", _t_login_bruteforce,
              "Fire <=15 rapid FAILED login attempts (unique dummy creds) at a login endpoint to test whether rate limiting/lockout is enforced. Read-only w.r.t. data.",
              ["url", "username", "count"])

    def _t_take_webhooks(urls):
        """CVE-2026-41896-style Webhook HMAC null-secret check.
        Safe by design: HMACs are computed for a non-existent repo so even an
        unpatched endpoint cannot match an application or trigger a deploy."""
        import hmac
        import hashlib
        out = []
        for u in list(urls or [])[:5]:
            u0 = u.split("?")[0].rstrip("/")
            payload = json.dumps({"ref": "refs/heads/main",
                                  "repository": {"full_name": "mrboom-nonexistent/no-such-repo-xyz", "id": 987654321}})
            null_sig = "sha256=" + hmac.new(b"", payload.encode(), hashlib.sha256).hexdigest()
            wrong_sig = "sha256=" + hashlib.sha256(b"junk").hexdigest()

            def _wh(sig):
                hdrs = {"Content-Type": "application/json", "X-GitHub-Event": "push",
                        "X-GitHub-Delivery": "mrboom-diff"}
                if sig is not None:
                    hdrs["X-Hub-Signature-256"] = sig
                st, _, b = _post(u0, payload=payload, headers=hdrs, timeout=8)
                return st, re.sub(r"\s+", " ", (b or ""))[:140]

            st0, b0 = _get(u0, timeout=8)
            if st0 == 404:
                out.append({"url": u0, "verdict": "not-a-webhook-endpoint"}); continue
            stA, bA = _wh(null_sig)
            stB, bB = _wh(wrong_sig)
            if "invalid signature" in bA.lower():
                verdict = "hmac-active-or-patched"
            elif (stA and stA != st0) or ("invalid signature" not in bA.lower() and "html" not in bA[:30].lower()):
                verdict = "possible-bypass (null-key accepted past HMAC; could not trigger anything without a real repo match)"
            else:
                verdict = "inconclusive/same-as-page"
            out.append({"url": u0, "null_key_hmac": {"status": stA, "body": bA},
                        "wrong_hmac": {"status": stB, "body": bB}, "verdict": verdict})
        return {"webhooks": out}
    _register("take_webhooks", _t_take_webhooks,
              "Test CI/webhook endpoints for HMAC-bypass (null-secret) flaws. Non-destructive: uses a repo name that cannot match any application.",
              ["urls"])

    def _t_attack_battery(urls):
        try:
            host = app_mod.clean_host((urls or [""])[0]) if urls else ""
            r = app_mod.bb_attack_engine(host or "target", list(urls or [])[:20], timeout=120)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("attack_battery", _t_attack_battery,
              "Full active attack battery on up to 20 URLs: reflected XSS, error+time-based SQLi (baseline-validated), SSTI, OS cmd injection, path traversal, SSRF.",
              ["urls"])

    def _t_web_validations(urls):
        try:
            from webvalidations import bb_web_validation as _bb_web_validation
            r = _bb_web_validation(list(urls or [])[:6], domain="", timeout=150)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("web_validations", _t_web_validations,
              "Web config validation on up to 6 URLs: TLS/cert, cookie flags, CORS, CSP, clickjacking, open methods, admin path exposure, rate limiting, host-header injection.",
              ["urls"])

    def _t_cors_check(urls):
        try:
            r = app_mod.bb_cors_check(list(urls or [])[:6], timeout=15)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("cors_check", _t_cors_check,
              "CORS misconfiguration check on up to 6 URLs (reflect-any-origin, null origin, credentialed wildcard).",
              ["urls"])

    def _t_open_redirect_check(urls):
        try:
            r = app_mod.bb_open_redirect_check(list(urls or [])[:6], timeout=15)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("open_redirect_check", _t_open_redirect_check,
              "Open redirect check on up to 6 URLs (redirect/url/next params).",
              ["urls"])

    def _t_default_creds(urls):
        try:
            r = app_mod.bb_default_creds(list(urls or [])[:6], timeout=20)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("default_creds", _t_default_creds,
              "Default credential probe against login endpoints on up to 6 URLs (admin/admin, root/root etc. — short, low-rate).",
              ["urls"])

    def _t_jwt_check(urls):
        try:
            r = app_mod.bb_jwt_check(list(urls or [])[:6], timeout=20)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("jwt_check", _t_jwt_check,
              "JWT security check: alg=none bypass, unauthenticated API access patterns.",
              ["urls"])

    def _t_cve_lookup(software):
        try:
            from cvemap import match_cves as _match_cves
            r = _match_cves(list(software or [])[:20])
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"cves": r or []}
    _register("cve_lookup", _t_cve_lookup,
              "Match detected software banners (e.g. 'nginx 1.18', 'Coolify 4.0.0-beta.472') against the local CVE corpus.",
              ["software"])

    def _t_web_intel(topic, sources="web", output_format="json", timeout=180):
        """DeepDive Goblin Scrape integration: AI-powered multi-source (web,
        x-twitter, reddit, youtube) scraping to research known bugs / exploits /
        CVEs / PoCs for a given software+version. Runs the `deepdive` CLI in its
        own venv as a subprocess and parses the JSON report."""
        import subprocess as _sp
        dd_bin = os.path.expanduser("~/Deepdive-goblin-scrape/.venv/bin/deepdive")
        if not os.path.isfile(dd_bin):
            return {"error": "deepdive not installed (~/Deepdive-goblin-scrape/.venv/bin/deepdive missing)"}
        cmd = [dd_bin, topic, "--sources", sources, "--format", output_format or "json", "--verbose"]
        try:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=os.path.expanduser("~/Deepdive-goblin-scrape"))
        except _sp.TimeoutExpired:
            return {"error": f"deepdive timed out after {timeout}s", "topic": topic}
        except Exception as e:
            return {"error": str(e)[:120], "topic": topic}
        out = r.stdout or ""
        err = (r.stderr or "")[-300:]
        if r.returncode != 0 and not out.strip():
            return {"error": f"deepdive failed ({r.returncode}): {err}", "topic": topic}
        try:
            report = json.loads(out)
            exec_sum = report.get("executive_summary", "")
            web = report.get("web_insights", []) or []
            yt = report.get("youtube_breakdown", []) or []
            analysis = report.get("deep_analysis", "")
            return {
                "topic": topic,
                "summary": exec_sum[:1200],
                "top_web_hits": [
                    {"title": (w.get("title") or "")[:120], "url": w.get("url", ""),
                     "snippet": (w.get("snippet") or w.get("content") or "")[:200]}
                    for w in web[:8]
                ],
                "youtube_hits": [{"title": (y.get("title") or "")[:120], "url": y.get("url", "")} for y in yt[:5]],
                "deep_analysis": (analysis or "")[:1500],
            }
        except Exception:
            return {"topic": topic, "raw": out[:1500], "stderr": err[:200]}
    _register("web_intel", _t_web_intel,
              "DeepDive web-intel scrape: research known bugs / CVEs / exploits / PoCs for a specific software+version by scraping web, X/Twitter, Reddit and YouTube. Use when you discover a versioned product (e.g. 'Coolify 4.0.0-beta.472', 'gunicorn 21.2.0', 'PostgreSQL 14.3') to find real-world vulns.",
              ["topic", "sources", "output_format", "timeout"])

    def _t_takeover(subdomains, domain=""):
        try:
            r = app_mod.bb_takeover_check(list(subdomains or [])[:30], domain or "", timeout=25)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"candidates": [t for t in (r or []) if t.get("vulnerable")], "checked": len(r or [])}
    _register("takeover", _t_takeover,
              "Subdomain TAKEOVER check: dangling CNAMEs pointing at deprovisioned SaaS (Heroku/S3/GitHub Pages...) on up to 30 subdomains.",
              ["subdomains", "domain"])

    def _t_origin_hunt(domain):
        try:
            r = app_mod.bb_origin_hunt(domain, time_budget=90)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"origins": r or []}
    _register("origin_hunt", _t_origin_hunt,
              "Hunt the real origin IP behind CDN/WAF (cert matches, historical DNS, direct probes).",
              ["domain"])

    def _t_sourcemap_extract(urls):
        try:
            r = app_mod.bb_sourcemap_extract(list(urls or [])[:6], timeout=30)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"results": r or []}
    _register("sourcemap_extract", _t_sourcemap_extract,
              "Follow JS sourceMappingURLs and mine unminified sources for endpoints/config.",
              ["urls"])

    def _t_crawl(url):
        try:
            r = app_mod.pd_katana(url, timeout=45)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"url": url, "urls": r or []}
    _register("crawl", _t_crawl,
              "Crawl one URL (katana) to discover paths, forms, params.",
              ["url"])

    # ── EXPLOIT BATTERY (evidence-verified, no timing-based guesses) ────
    def _t_inject_diff(urls):
        try:
            import exploitx
            r = exploitx.inject_diff(app_mod, list(urls or [])[:8], timeout=90)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or [], "checked": len(list(urls or [])[:8])}
    _register("inject_diff", _t_inject_diff,
              "SQLi+XSS via RESPONSE-DIFF verification (canary baselines, boolean TRUE/FALSE controls, echo checks). Only reports when the payload provably changes behavior vs baseline. Use on URLs WITH query params.",
              ["urls"])

    def _t_lfi_probe(urls):
        try:
            import exploitx
            r = exploitx.lfi_probe(app_mod, list(urls or [])[:6], timeout=60)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("lfi_probe", _t_lfi_probe,
              "Path traversal / LFI probe on file-like endpoints (download/file/doc/export/report). Reports only when /etc/passwd or win.ini markers appear in payload response but NOT in a canary baseline.",
              ["urls"])

    def _t_auth_bypass(api_endpoints):
        try:
            import exploitx
            r = exploitx.auth_bypass(app_mod, list(api_endpoints or [])[:20], timeout=90)
        except Exception as e:
            return {"error": str(e)[:120]}
        return {"findings": r or []}
    _register("auth_bypass", _t_auth_bypass,
              "Unauth-access + IDOR probe on discovered API endpoints: flags endpoints returning real data without creds when siblings on the same host enforce 401/403, and id-swap IDOR checks. Feed it api_endpoints found earlier.",
              ["api_endpoints"])

    # ── MULTI-AGENT FANOUT: run N independent tool calls in parallel ─────
    def _t_fanout(jobs):
        """Parallel subtask executor. jobs: [{"action": <registered tool>,
        "params": {...}}, ...]. Runs them concurrently on a worker pool and
        returns per-job results. Use when you have 2-6 INDEPENDENT leads
        (e.g. scan /api, /admin and /docs at once) instead of grinding them
        one step at a time."""
        import concurrent.futures as _cf
        import threading as _th

        jobs = list(jobs or [])[:6]
        out = []
        lock = _th.Lock()
        results = {}

        def _run(idx, job):
            act = str((job or {}).get("action", "")).lower()
            par = (job or {}).get("params") or {}
            if act not in _tool_fns or act == "fanout":
                with lock:
                    results[idx] = {"error": f"unknown/non-fanout-able tool '{act}'"}
                return
            # per-job scope gate: parallel jobs must not escape scope either.
            # FAIL CLOSED: unknown engagement, extraction failure, or gate
            # error all block the job — a prompt-injected model must never get
            # an ungated dispatch path.
            if _ACTIVE_ENG is None:
                with lock:
                    results[idx] = {"error": "blocked: no active engagement scope to verify against"}
                return
            try:
                app_m = __import__("app")
                bad = [h for h in _extract_hosts(par) if not _scope_ok(app_m, _ACTIVE_ENG, h)]
                if bad:
                    with lock:
                        results[idx] = {"error": f"blocked: out-of-scope hosts {bad}"}
                    return
            except Exception as e:
                with lock:
                    results[idx] = {"error": f"blocked: scope gate error ({type(e).__name__})"}
                return
            try:
                r = _tool_fns[act]["fn"](**par)
            except TypeError as e:
                r = {"error": f"bad params: {e}"}
            except Exception as e:
                r = {"error": f"{type(e).__name__}: {str(e)[:140]}"}
            with lock:
                results[idx] = r

        with _cf.ThreadPoolExecutor(max_workers=min(6, max(1, len(jobs)))) as ex:
            futs = [ex.submit(_run, i, j) for i, j in enumerate(jobs)]
            _cf.wait(futs, timeout=240)
        for i, j in enumerate(jobs):
            out.append({"job": i, "action": str((j or {}).get("action", ""))[:40],
                        "result": results.get(i, {"error": "no result within 240s"})})
        return {"jobs_run": len(jobs), "results": out}
    _register("fanout", _t_fanout,
              "PARALLEL subtasks: run up to 6 independent tool calls at once. "
              "jobs=[{\"action\":\"<tool>\",\"params\":{...}}, ...]. Use for independent leads "
              "(different paths/endpoints/subdomains) to stop grinding step-by-step.",
              ["jobs"])


# ── DECISION LOOP ─────────────────────────────────────────────────

SYSTEM_PROMPT = """You are MrBOOM, an autonomous offensive-security orchestrator running an AUTHORIZED pentest.
You do not execute code directly — you pick tools; a hardened harness runs them and returns real results.
You decide the engagement strategy. Work like a senior bug bounty hunter:

TYPICAL FLOW (adapt to evidence):
1. Recon first: dns_enum/subdomain_enum/http_probe/whois -> establish the REAL surface.
2. Map it: tech_fingerprint, js_analysis, api_probe on live hosts; port_scan on interesting IPs.
3. Hypothesize: given THIS stack (framework, version, exposed internal services, login pages, CI/webhooks), what breaks? Chase specific leads, not generic checklists.
4. Verify: targeted tools (login_bruteforce, take_webhooks, attack_battery, web_validations, default_creds, takeover, inject_diff, lfi_probe, auth_bypass...) against each hypothesis.
5. PARALLELIZE: when you hold 2-6 INDEPENDENT leads (separate paths, hosts, or endpoints with no shared state), batch them in ONE `fanout` call instead of grinding them one step at a time. Do NOT fanout probes that depend on each other.
6. finish with a summary when you've exhausted value or the budget runs low.

RULES:
- Targets outside the engagement scope are auto-rejected — stay in scope.
- No DoS, no destructive writes, no data modification. login_bruteforce uses dummy creds only.
- After each result, actually READ the evidence (status codes, bodies, error text) and reason about it.
- If a lead dies (404/503/Cloudflare challenge), MOVE ON; don't retry the same dead probe.
- When wildcard DNS is suspected (many names -> same IP -> same dead backend), say so and pivot to what's actually alive.

RESPONSE FORMAT — output EXACTLY this, nothing else:
reason: <1-3 short sentences: what the evidence means, what you'll do about it>
action: <tool name>
params:
```json
{"param": "value"}
```
To end the engagement:
reason: <what you concluded>
action: finish
params:
```json
{"summary": "2-5 sentence final assessment of the target's security posture"}
```"""


def _parse_action(text):
    """Parse the model's strict-format reply into (reason, action, params)."""
    reason_m = re.search(r"reason:\s*(.*?)(?:\n\s*action:|$)", text, re.S | re.I)
    reason = reason_m.group(1).strip() if reason_m else ""
    act_m = re.search(r"action:\s*[`'\"]*([A-Za-z0-9_]+)", text, re.I)
    action = act_m.group(1).lower() if act_m else ""
    params = {}
    blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    for b in blocks:
        try:
            params = json.loads(b)
            break
        except Exception:
            continue
    if not params:
        cand = re.search(r"params:\s*(\{.*\})", text, re.S | re.I)
        if cand:
            s = cand.group(1).strip()
            depth = 0
            for i, ch in enumerate(s):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            params = json.loads(s[:i + 1])
                        except Exception:
                            params = {}
                        break
    return reason, action, params if isinstance(params, dict) else {}


def _scope_ok(app_mod, eng, host):
    t = (host or "").lower().strip()
    try:
        t_url = urllib.parse.urlparse(t if "://" in t else "https://" + t)
        if t_url.hostname:
            t = t_url.hostname
    except Exception:
        pass
    if not t:
        return False
    scope = eng.get("scope") or []
    if isinstance(scope, str):
        scope = [s.strip() for s in scope.split(",") if s.strip()]
    exclusions = eng.get("exclusions") or []
    if isinstance(exclusions, str):
        exclusions = [s.strip() for s in exclusions.split(",") if s.strip()]
    for x in exclusions:
        try:
            if t == x.lower() or (x.startswith("*.") and (t == x[2:] or t.endswith("." + x[2:]))):
                return False
        except Exception:
            pass
    for a in scope:
        a = a.lower()
        if a.startswith("*."):
            root = a[2:]
            if t == root or t.endswith("." + root):
                return True
        elif t == a:
            return True
        # a bare domain in scope also permits its subdomains — matches the
        # pipeline's behaviour (subfinder/assetfinder enumerate subs by design)
        elif t.endswith("." + a):
            return True
    return False


def _extract_hosts(params):
    """Pull candidate hostnames out of tool params for the scope gate.

    Recurses into nested dicts/lists (fanout jobs, structured params) so a
    host can't hide one level deep. Only treat a value as a host/url if it
    actually looks like one: has a URL scheme, is a dotted name, or is a
    single-label internal host (localhost, intranet names) — those must also
    pass the scope allowlist, never get skipped.
    """
    hosts = set()

    def _scan(val):
        if isinstance(val, dict):
            for vv in val.values():
                _scan(vv)
            return
        if isinstance(val, (list, tuple, set)):
            for vv in val:
                _scan(vv)
            return
        if not isinstance(val, str):
            return
        x = val.strip()
        if not x:
            return
        has_scheme = "://" in x
        # version banners / free text with spaces are not hostnames
        if " " in x and not has_scheme:
            return
        if "/" in x and not has_scheme:
            return  # a bare path like "api/v1/users"
        # plain single bare word (no dot/scheme/port/dash) is a product name
        # or keyword ("apache", "mysql"), not a host — don't false-flag it.
        # Host-ish forms we keep: host:port, dotted names, hyphenated
        # intranet names, scheme'd URLs.
        if not has_scheme and "." not in x and ":" not in x and "-" not in x:
            return
        try:
            p = urllib.parse.urlparse(x if has_scheme else "https://" + x)
            h = p.hostname
        except Exception:
            h = None
        if h:
            hosts.add(h)

    _scan(params)
    return hosts


def _state_summary(eng, data, domain, steps_left, seconds_left, warning=None):
    http_res = data.get("http") or {}
    live = [u for u, v in http_res.items() if isinstance(v, dict) and v.get("status") in (200, 201, 204, 301, 302, 401, 403)]
    dead = sorted({u for u, v in http_res.items()
                   if isinstance(v, dict) and v.get("status") in (0, 502, 503, 504)})
    techs = sorted({t for v in http_res.values() if isinstance(v, dict) for t in (v.get("tech") or [])})
    findings = data.get("findings") or []
    sev_count = {}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        sev_count[s] = sev_count.get(s, 0) + 1
    ports = data.get("ports") or {}
    lines = [
        f"step {MAX_STEPS - steps_left + 1}/{MAX_STEPS} | time left: {int(seconds_left)}s",
        f"hosts/IPs resolved: {', '.join(sorted({h for h, i in (data.get('dns_ips') or {}).items() if i})[:15]) or 'none yet'}",
        f"subdomains: {data.get('subdomain_count', 0)} discovered",
        f"live URLs ({len(live)}): {'; '.join(live[:12])}",
        f"DEAD/wildcard hosts ({len(dead)}) [DO NOT re-probe — confirmed down]: {', '.join(dead[:20])}",
        f"tech: {', '.join(techs[:18]) or 'none detected yet'}",
        f"api endpoints: {', '.join((data.get('api_endpoints') or [])[:12]) or 'none yet'}",
        f"open ports: {json.dumps({k: v for k, v in list(ports.items())[:6]}) if ports else 'none scanned'}",
        f"findings so far: {sev_count or {'none': 0}} — total {len(findings)}",
    ]
    top = sorted([f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")],
                 key=lambda x: -x.get("score", 0))[:5]
    for f in top:
        lines.append(f"  • [{f.get('severity')}] {f.get('type') or f.get('title')} @ {str(f.get('url'))[:80]}")
    hist = data.get("_hist", [])[-3:]
    if hist:
        lines.append("most recent tool results:")
        for h in hist:
            lines.append(f"  • [{h['action']}] -> {str(h['result'])[:220]}")
    if warning:
        lines.append("")
        lines.append("⚠ " + warning)
    return "\n".join(lines)


def _absorb(data, action, result):
    """Fold one tool result into the shared engagement state."""
    if action == "http_probe" and isinstance(result, dict):
        for r in result.get("results", []):
            data["http"][r["url"]] = r
    elif action == "subdomain_enum" and isinstance(result, dict):
        data["subdomain_count"] = result.get("count", 0)
        data.setdefault("subdomains", []).extend(result.get("subdomains", [])[:500])
        data["subdomains"] = sorted(set(data["subdomains"]))[:400]
    elif action == "dns_enum" and isinstance(result, dict):
        for ip in (result.get("records") or {}).get("A", []):
            data["dns_ips"].setdefault(data.get("domain", ""), ip)
    elif action == "resolve_host" and isinstance(result, dict):
        if result.get("ip"):
            data["dns_ips"][result["host"]] = result["ip"]
    elif action == "port_scan" and isinstance(result, dict):
        for k, v in (result.get("ports") or {}).items():
            data["ports"][k] = v
    elif action == "tech_fingerprint" and isinstance(result, dict):
        data["http"].setdefault(result.get("url", ""), {})
        data["http"][result.get("url", "")]["tech"] = result.get("tech", [])
    elif action in ("attack_battery", "web_validations", "cors_check",
                    "open_redirect_check", "default_creds", "jwt_check",
                    "inject_diff", "lfi_probe", "auth_bypass"):
        bucket = {"attack_battery": "attack", "web_validations": "web_validations",
                  "cors_check": "bb_cors", "open_redirect_check": "bb_open_redirect",
                  "default_creds": "bb_default_creds", "jwt_check": "bb_jwt",
                  "inject_diff": "bb_injection", "lfi_probe": "bb_injection",
                  "auth_bypass": "bb_injection"}[action]
        data.setdefault(bucket, []).extend(result.get("findings", []))
        data["findings"].extend(result.get("findings", []))
    elif action == "js_analysis" and isinstance(result, dict):
        js = result.get("js") or []
        eps = set()
        for r in js:
            if isinstance(r, dict):
                if r.get("kind") == "js_endpoints":
                    eps |= set(r.get("endpoints", []))
                if r.get("kind") == "js_secrets" and r.get("secrets"):
                    data["findings"].append({"type": "Hardcoded secrets in JS", "severity": "medium",
                                             "url": r.get("url", ""), "evidence": ", ".join(r["secrets"][:5])})
        data["api_endpoints"] = sorted(set(data["api_endpoints"]) | eps)[:200]
    elif action == "api_probe" and isinstance(result, dict):
        for r in result.get("results", []):
            if r.get("status") in (200, 201, 204, 401, 403):
                data["api_endpoints"] = sorted(set(data["api_endpoints"] + [r["url"]]))[:200]
    elif action == "takeover" and isinstance(result, dict):
        data.setdefault("bb_takeover", []).extend(result.get("candidates", []))
        for c in result.get("candidates", []):
            data["findings"].append({"type": "Subdomain takeover", "severity": "critical",
                                     "url": c.get("url", ""), "evidence": str(c)[:200], "score": 85})
    elif action == "cve_lookup" and isinstance(result, dict):
        data.setdefault("cvemap_findings", []).extend(result.get("cves", []))
        data["findings"].extend(result.get("cves", []))
    elif action == "fetch_page" and isinstance(result, dict):
        data["_pages"] = data.get("_pages", [])
        data["_pages"].append({"url": result.get("url"), "status": result.get("status")})
    elif action == "wayback" and isinstance(result, dict):
        data.setdefault("wayback", {})["urls"] = result.get("urls", [])


def _finalize(app_mod, eid, eng, data, domain, log_state, emit_ir, meta_up):
    """Report + memory + history — mirrors run_oneshot's tail."""
    try:
        data["findings"] = (data.get("findings") or []) + \
            [f for r in (data.get("web_validations") or []) if isinstance(r, dict)] + \
            [f for r in (data.get("attack") or []) if isinstance(r, dict)]
        data["domain"] = domain
        data["scope"] = eng.get("scope", "")
        data["exclusions"] = eng.get("exclusions", [])
        report = app_mod.generate_report(data)
        import hashlib as _hashlib
        import os as _os
        report_id = _hashlib.md5(domain.encode()).hexdigest()[:12]
        report_filename = f"{domain.replace('.', '_')}_llm_report_{report_id}.md"
        report_path = _os.path.join(app_mod.DATA_DIR, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
        eng["report_path"] = report_path
        eng["report"] = report
        eng["report_filename"] = report_filename
        eng["status"] = "complete"
        for key, val in data.items():
            if val and key not in ("domain", "model") and not key.startswith("_"):
                eng[key] = val
        log_state(f"Report generated: {report_filename}")
        emit_ir("edit", {"path": report_filename, "lines_added": len(report.splitlines()), "lines_removed": 0})
        emit_ir("verification", {"kind": "report", "command": "generate report", "passed": True})
        cost_est = round(0.02 + 0.004 * len(data.get("_steps", [])), 2)
        emit_ir("usage", {"interval": "cumulative", "usage": {"cost_usd": cost_est}})
        emit_ir("run.finished", {"outcome": {"status": "passed"}})
        emit_ir("health.assessment", {"score": 1.0, "recommendation": "none", "signals": ["completed"]})
        meta_up(status="passed")
        app_mod.emit_sync("done", {"status": "passed"})
        try:
            app_mod.save_scan_memory(domain, data)
            log_state("Scan memory saved")
        except Exception as _me:
            log_state(f"Scan memory save failed: {_me}")
        app_mod.save_scan_history(eid)
    except Exception as e:
        eng["status"] = "error"
        eng["error"] = f"finalize: {e}"
        log_state(f"Error: {e}")


def run_llm(eid):
    app_mod = __import__("app")
    with app_mod.DB_LOCK:
        eng = app_mod.DB[eid]
        eng["events"] = list(eng.get("events", []))
        eng["logs"] = list(eng.get("logs", []))
    domain = app_mod.clean_host(eng.get("scope", ""))
    apex = app_mod.apex_domain(domain)
    base_url = eng.get("base_url", "")
    model = eng.get("model", "")
    api_key = eng.get("api_key", "")
    problem = eng.get("prompt", "") or f"Full authorized recon + vulnerability hunt on {domain}"

    pair_id = {"harness": "mrboom-llm", "model": model or "auto"}

    def emit_ir(etype, payload):
        from datetime import datetime as _dt, timezone as _tz
        ev = {"type": etype, "ts": _dt.now(_tz.utc).isoformat(),
              "source": {"pair": pair_id}, "payload": payload, "task_id": eid}
        eng["events"].append(ev)
        eng["events"] = eng["events"][-200:]
        app_mod.emit_sync("ir", ev)

    def log_state(msg):
        eng["logs"].append({"t": app_mod.now(), "msg": msg})
        eng["progress"] = msg

    def meta_up(**kw):
        app_mod.meta_state.update({"task_id": eid, "goal": problem or domain, **kw})
        app_mod.emit_sync("meta", dict(app_mod.meta_state))

    meta_up(status="running")
    log_state("LLM orchestrator engaged — model drives the engagement")
    emit_ir("message", {"role": "assistant", "text":
        f"**Mode: LLM orchestration** — the model picks every action from here. Scope: `{eng.get('scope')}`. "
        f"Hard caps: {MAX_STEPS} steps / {TIME_BUDGET_S // 60} min. Scope gate armed."})

    data = {"domain": domain, "model": model, "findings": [], "_hist": [], "_steps": [],
            "http": {}, "ports": {}, "dns_ips": {}, "api_endpoints": [], "subdomain_count": 0}
    t0 = time.time()
    _ensure_tools(app_mod)

    # resume support: a restart marks the run 'paused'; on re-run we restore
    # the accumulated recon state + step cursor so nothing is re-discovered
    _resume_data = eng.get("_resume_data")
    _start_at = 1
    if isinstance(_resume_data, dict):
        _start_at = int(_resume_data.get("_next_step", 1))
        _resume_data.pop("_next_step", None)
        data.update(_resume_data)
        log_state(f"RESUMED: restored {len(data.get('http') or {})} probed URLs, "
                  f"{len(data.get('findings') or [])} findings, {len(data.get('api_endpoints') or [])} API endpoints — continuing at step {_start_at}")
        emit_ir("message", {"role": "assistant", "text":
            f"**Scan resumed** after restart at step {_start_at}. Evidence restored from disk."})

    def _snapshot_data():
        """Persist recon state so a restart loses nothing."""
        try:
            with app_mod.DB_LOCK:
                snap = {k: v for k, v in data.items()}
                snap["_next_step"] = len(data.get("_steps") or []) + 1
                eng["_resume_data"] = snap
                app_mod.persist_engagement(eid, lock_held=True)
        except Exception:
            pass

    # warm-start from per-target scan memory so a long grind doesn't re-discover
    # what earlier runs already confirmed (API paths, dead/alive hosts, origins)
    try:
        mem = app_mod._load_scan_memory(domain) or {}
        if mem.get("api_endpoints"):
            data["api_endpoints"] = list(mem["api_endpoints"])[:200]
        # hosts that returned 503/0 in prior runs are pre-seeded as dead
        for p in (mem.get("probes") or []):
            pu = p.get("url", "")
            if not isinstance(pu, str) or "://" not in pu:
                continue
            outcome = p.get("outcome", "")
            if outcome in ("dead", "503", "error", "timeout"):
                data["http"][pu] = {"url": pu, "status": 503, "tech": [], "title": "(dead, from memory)"}
        if data["api_endpoints"] or any(True for _ in (mem.get("probes") or [])):
            log_state(f"scan memory warm-start: {len(data['api_endpoints'])} known API paths, "
                      f"{sum(1 for v in data['http'].values() if isinstance(v, dict) and v.get('status') == 503)} known-dead hosts")
    except Exception as _me:
        log_state(f"scan memory load failed: {_me}")

    # loop guard: canonical (action, params) signatures seen so the model can't
    # burn thousands of steps re-running identical probes
    _seen_actions = {}
    _dupe_warning = None
    _dupe_streak = 0
    _last_reason = ""
    _step_t0 = 0.0

    try:
        global _ACTIVE_ENG
        _ACTIVE_ENG = eng
        for step in range(_start_at, MAX_STEPS + 1):
            if eng.get("_stop"):
                log_state("stop requested — finalizing with findings collected so far")
                emit_ir("message", {"role": "assistant", "text": "Stop requested. Finalizing report from evidence so far."})
                break
            elapsed = time.time() - t0
            left = TIME_BUDGET_S - elapsed
            if left <= 0:
                log_state("Time budget exhausted — forcing finish")
                emit_ir("message", {"role": "assistant", "text": "Time budget exhausted. Wrapping up."})
                break

            summary = _state_summary(eng, data, domain, MAX_STEPS - step + 1, left, warning=_dupe_warning)
            _dupe_warning = None
            user_msg = (
                f"ENGAGEMENT GOAL:\n{problem}\n\n"
                f"SCOPE: {eng.get('scope')} | EXCLUSIONS: {eng.get('exclusions') or 'none'}\n\n"
                f"CURRENT EVIDENCE:\n{summary}\n\n"
                f"TOOLS AVAILABLE:\n{tool_specs(app_mod)}\n\n"
                f"Choose the single next action. Reply in the exact format."
            )
            emit_ir("health.assessment", {"score": round(min(1.0, step / max(3, MAX_STEPS * 0.6)), 2),
                                          "recommendation": "none", "signals": [f"step_{step}"]})
            reply = app_mod.call_model(base_url, model, api_key, [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ], timeout=150)

            if str(reply).startswith("AI_ERROR"):
                log_state(f"step {step}: model error — {str(reply)[:100]}; retrying once")
                time.sleep(3)
                reply = app_mod.call_model(base_url, model, api_key, [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ], timeout=180)
                if str(reply).startswith("AI_ERROR"):
                    log_state("model unreachable twice — aborting loop")
                    break

            reason, action, params = _parse_action(str(reply))
            _last_reason = reason
            _step_t0 = time.time()
            if reason:
                emit_ir("message", {"role": "assistant_thinking", "text": reason})

            if action == "finish" or not action:
                summary_txt = params.get("summary", "") if isinstance(params, dict) else ""
                emit_ir("message", {"role": "assistant", "text": f"**Orchestrator finished.**\n\n{summary_txt}"})
                data["ai_analysis"] = summary_txt or "LLM orchestrator completed without summary."
                log_state(f"step {step}: finish — engagement concluded")
                break

            if action not in _tool_fns:
                log_state(f"step {step}: unknown tool '{action}' — skipped")
                data["_hist"].append({"action": action, "result": "unknown tool"})
                continue

            # subdomain_enum on shared tunnel apexes (trycloudflare.com,
            # ngrok.io, etc.) surfaces OTHER people's tunnels — pure noise +
            # scope risk. Hard-block it and teach the model why.
            if action == "subdomain_enum" and is_shared_tunnel(str(params.get("domain", ""))):
                log_state(f"step {step}: subdomain_enum on tunnel apex {params.get('domain')} — blocked")
                data["_hist"].append({"action": action, "result": f"skipped: {params.get('domain')} is a shared tunnel domain"})
                _dupe_warning = (f"{params.get('domain')} is a SHARED tunnel/CDN domain — it has no subdomain tree. "
                                 "Subdomains there are other tenants, not part of this target. Skip subdomain_enum; "
                                 "instead enumerate PATHS/APIs on the live URL (api_probe, js_analysis, fetch_page, fuzz).")
                continue

            # loop guard — don't burn steps re-running identical probes
            _sig_key = f"{action}:{json.dumps(params, sort_keys=True, ensure_ascii=False)}"
            _seen_count = _seen_actions.get(_sig_key, 0)
            if _seen_count >= 2:
                _seen_actions[_sig_key] = _seen_count + 1
                _dupe_streak += 1
                if _dupe_streak >= 8:
                    log_state("model stuck proposing duplicates — forcing finish")
                    emit_ir("message", {"role": "assistant", "text": "Orchestrator exhausted distinct leads — concluding."})
                    break
                if _dupe_warning is None:
                    _dupe_warning = (f"You already ran this EXACT action {_seen_count}x: {_sig_key[:100]}. "
                                     "Its result cannot change — pursue a DIFFERENT lead with different params, "
                                     "or reply action: finish if the evidence is exhausted.")
                log_state(f"step {step}: skipped duplicate action {action} (seen {_seen_count}x)")
                data["_hist"].append({"action": action, "result": "duplicate — skipped"})
                continue
            _seen_actions[_sig_key] = _seen_count + 1
            _dupe_streak = 0

            # drop already-confirmed-dead hosts from http_probe payloads —
            # they return 503/timeout identically every time; no point probing
            if action == "http_probe" and isinstance(params.get("urls"), list):
                _dead_hosts = set()
                for _u, _v in (data.get("http") or {}).items():
                    if isinstance(_v, dict) and _v.get("status") in (0, 502, 503, 504):
                        try:
                            _dead_hosts.add((urllib.parse.urlparse(_u).hostname or "").lower())
                        except Exception:
                            pass
                _fresh = []
                _skipped_dead = []
                for _u in params["urls"]:
                    try:
                        _h = (urllib.parse.urlparse(_u if "://" in _u else "https://" + _u).hostname or "").lower()
                    except Exception:
                        _h = ""
                    if _h and _h in _dead_hosts:
                        _skipped_dead.append(_u)
                    else:
                        _fresh.append(_u)
                if _skipped_dead and not _fresh:
                    log_state(f"step {step}: http_probe dropped — all {len(_skipped_dead)} urls already confirmed dead")
                    data["_hist"].append({"action": action, "result": f"skipped: hosts already confirmed dead/dead-wildcard ({len(_skipped_dead)} urls)"})
                    _dupe_warning = ("You again probed hosts already confirmed dead: " +
                                      ", ".join(sorted({str(x) for x in _skipped_dead})[:5]) +
                                      ". Re-probing dead hosts wastes steps and can NEVER change. Probe a DIFFERENT live target or path, or finish.")
                    continue
                if _skipped_dead:
                    params = dict(params)
                    params["urls"] = _fresh
                    log_state(f"step {step}: http_probe trimmed — dropped {len(_skipped_dead)} dead urls")

            # scope gate
            bad = [h for h in _extract_hosts(params) if not _scope_ok(app_mod, eng, h)]
            if bad:
                log_state(f"step {step}: scope gate BLOCKED {bad} (action={action})")
                emit_ir("message", {"role": "assistant", "text": f"Scope gate blocked out-of-scope hosts: `{', '.join(bad)}`"})
                data["_hist"].append({"action": action, "result": f"blocked: out-of-scope {bad}"})
                continue

            log_state(f"step {step}/{MAX_STEPS}: {action}({json.dumps(params, ensure_ascii=False)[:160]})")
            with app_mod.DB_LOCK:
                eng["llm_step"] = {
                    "n": step, "max": MAX_STEPS, "action": action,
                    "params": json.dumps(params, ensure_ascii=False)[:200],
                    "reason": (_last_reason or "")[:220], "running": True,
                }
            emit_ir("tool.call", {"call_id": f"llm-{step}-{eid}", "name": action,
                                  "target": json.dumps(params, ensure_ascii=False)[:140], "category": "search"})
            try:
                result = _tool_fns[action]["fn"](**params)
            except TypeError as e:
                result = {"error": f"bad params: {e}"}
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {str(e)[:140]}"}
            with app_mod.DB_LOCK:
                if eng.get("llm_step"):
                    eng["llm_step"]["running"] = False
                    eng["llm_step"]["elapsed_s"] = round(time.time() - _step_t0, 1)
                    eng["llm_step"]["status"] = "error" if isinstance(result, dict) and result.get("error") else "ok"

            # absorb structured results into state
            _absorb(data, action, result)
            if action == "fanout" and isinstance(result, dict):
                for jr in result.get("results", []):
                    sub_act = jr.get("action", "")
                    sub_res = jr.get("result", {})
                    if isinstance(sub_res, dict) and not sub_res.get("error"):
                        data.setdefault("fanout", []).append({"action": sub_act, "result": str(sub_res)[:400]})

            data["_hist"].append({"action": action, "result": result})
            data["_hist"] = data["_hist"][-8:]
            data["_steps"].append({"step": step, "action": action, "reason": reason[:300]})

            sev_bump = []
            if isinstance(result, dict):
                for f in result.get("findings", []) or []:
                    if str(f.get("severity", "")).lower() in ("critical", "high"):
                        sev_bump.append(f"{f.get('severity','').upper()}: {f.get('type') or f.get('title')} @ {str(f.get('url'))[:60]}")
            if sev_bump:
                emit_ir("message", {"role": "assistant", "text": "**FINDINGS:** " + " | ".join(sev_bump[:4])})
            emit_ir("tool.result", {"call_id": f"llm-{step}-{eid}",
                                    "status": "error" if isinstance(result, dict) and result.get("error") else "ok",
                                    "result": json.dumps(result, ensure_ascii=False)[:300]})
            app_mod.stealth.sleep()
            if step % 5 == 0:
                _snapshot_data()
        else:
            emit_ir("message", {"role": "assistant", "text": f"Step cap ({MAX_STEPS}) reached — concluding."})

        _finalize(app_mod, eid, eng, data, domain, log_state, emit_ir, meta_up)

    except Exception as e:
        eng["status"] = "error"
        eng["error"] = str(e)
        log_state(f"Error: {e}")
        emit_ir("error", {"scope": "orchestrator", "class": type(e).__name__, "message": str(e)[:200]})
        emit_ir("run.finished", {"outcome": {"status": "failed"}})
        emit_ir("health.assessment", {"score": 0.0, "recommendation": "none", "signals": ["error"]})
        meta_up(status="failed")
        app_mod.emit_sync("done", {"status": "failed"})
        traceback.print_exc()
