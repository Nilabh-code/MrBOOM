"""
MRBOOM // VERSION-AWARE CVE CORRELATION
Matches detected service/software versions against a bundled CVE corpus.
Offline + stealthy: no outbound NVD lookups during scans.
The DB lives in cvemap_db.py and can be extended per engagement.
"""
import re, uuid

# simple version tokenizer -> sortable tuple.
# Letters are preserved as rank tokens so OpenSSL letter releases
# (1.0.1f < 1.0.1g) compare correctly instead of collapsing both to 1.0.1.
def _vtok(v):
    parts = []
    for p in re.split(r"[.\-+_]", str(v).lower().strip()):
        if not p:
            continue
        if p.isdigit():
            parts.append((0, int(p)))
        elif len(p) == 1 and p.isalpha():
            parts.append((1, ord(p)))
        else:
            # mixed alnum chunk ("4b3", "rc1") — numeric prefix if any, then letters
            m = re.match(r"^(\d+)", p)
            if m:
                parts.append((0, int(m.group(1))))
                rest = p[m.end():]
                if rest:
                    parts.append((1, sum(ord(c) for c in rest)))
            else:
                parts.append((1, sum(ord(c) for c in p)))
    return parts or [(0, 0)]

def _trim(toks):
    """Drop trailing zero tokens so 1.2 == 1.2.0."""
    toks = list(toks)
    while len(toks) > 1 and toks[-1] == (0, 0):
        toks.pop()
    return toks

def _cmp(a, b):
    ta, tb = _trim(_vtok(a)), _trim(_vtok(b))
    for x, y in zip(ta, tb):
        if x < y: return -1
        if x > y: return 1
    if len(ta) < len(tb): return -1
    if len(ta) > len(tb): return 1
    return 0

def _in_range(ver, rng):
    """rng is a list of (op, version) like [("lt","1.18.0")] or [("any",)].
       Non-eq ops AND together; multiple eq values OR together.
       Robust to malformed entries mixing 1-tuples and 2-tuples."""
    if not rng:
        return True
    ops = []
    for item in rng:
        if not isinstance(item, (tuple, list)) or len(item) < 2:
            continue  # lone ("any",) mixed with ops: ignore the marker
        ops.append((item[0], item[1]))
    if not ops:
        return True
    eq_values = [b for op, b in ops if op == "eq"]
    if eq_values and not any(_cmp(ver, b) == 0 for b in eq_values):
        return False
    for op, bound in ops:
        c = _cmp(ver, bound)
        if op == "lt" and not (c < 0): return False
        if op == "lte" and not (c <= 0): return False
        if op == "gt" and not (c > 0): return False
        if op == "gte" and not (c >= 0): return False
        if op == "eq": continue
        if op == "ne" and not (c != 0): return False
    return True

def match_cves(services, db=None):
    """services: list of {"product":str,"version":str,"asset":str,"port":int}.
       Returns findings list in engine-compatible format."""
    db = db or CVE_DB
    findings = []
    for svc in services:
        product = (svc.get("product") or "").lower()
        ver = svc.get("version") or ""
        asset = svc.get("asset") or ""
        if not product or not ver:
            continue
        for entry in db:
            if product != entry["product"]:
                continue
            if not _in_range(ver, entry["range"]):
                continue
            sev = entry.get("severity", "MEDIUM")
            findings.append({
                "id": str(uuid.uuid4())[:8],
                "severity": sev,
                "score": {"CRITICAL": 90, "HIGH": 72, "MEDIUM": 48, "LOW": 24}.get(sev, 48),
                "title": f"{product} {ver} — {entry['id']}: {entry['title']}",
                "asset": asset,
                "tool": "cvemap",
                "cwe": entry.get("cwe", "CWE-1035"),
                "evidence": f"{product} {ver} on {asset or 'target'} matches {entry['id']} ({entry['range']})",
                "exploitable": entry.get("exploitable", False),
                "fix": entry.get("fix", "Upgrade the affected component."),
                "retest": "Re-scan after upgrade",
                "proof": None,
            })
    return findings

# ─── BUNDLED CVE CORPUS ───────────────────────────────────────────────────
CVE_DB = [
    {"id": "CVE-2021-23017", "product": "nginx", "range": [("lt", "1.21.0")], "severity": "HIGH",
     "title": "DNS resolver off-by-one heap write", "cwe": "CWE-122",
     "fix": "Upgrade nginx to >= 1.21.0.", "exploitable": False},
    {"id": "CVE-2022-41742", "product": "nginx", "range": [("lt", "1.23.2")], "severity": "MEDIUM",
     "title": "ngx_http_mp4_module memory disclosure", "cwe": "CWE-200",
     "fix": "Upgrade nginx to >= 1.23.2.", "exploitable": False},
    {"id": "CVE-2024-7347", "product": "nginx", "range": [("lt", "1.27.1")], "severity": "HIGH",
     "title": "ngx_http_mp4_module buffer overread", "cwe": "CWE-125",
     "fix": "Upgrade nginx to >= 1.27.1.", "exploitable": False},
    {"id": "CVE-2023-44487", "product": "httpd", "range": [("any",)], "severity": "HIGH",
     "title": "HTTP/2 Rapid Reset DoS", "cwe": "CWE-400",
     "fix": "Apply vendor HTTP/2 mitigations.", "exploitable": False},
    {"id": "CVE-2021-41773", "product": "httpd", "range": [("eq", "2.4.49"), ("eq", "2.4.50")], "severity": "CRITICAL",
     "title": "Path traversal + RCE in Apache path normalization", "cwe": "CWE-22",
     "fix": "Upgrade to Apache 2.4.51+.", "exploitable": True},
    {"id": "CVE-2021-42013", "product": "httpd", "range": [("eq", "2.4.49"), ("eq", "2.4.50")], "severity": "CRITICAL",
     "title": "Apache 2.4.49/2.4.50 traversal bypass (RCE)", "cwe": "CWE-22",
     "fix": "Upgrade to Apache 2.4.51+.", "exploitable": True},
    {"id": "CVE-2017-9798", "product": "httpd", "range": [("lt", "2.4.29")], "severity": "HIGH",
     "title": "Optionsbleed — use-after-free in .htaccess handling", "cwe": "CWE-416",
     "fix": "Upgrade to Apache 2.4.29+.", "exploitable": False},
    {"id": "CVE-2014-0160", "product": "openssl", "range": [("gte", "1.0.1"), ("lt", "1.0.1g")], "severity": "CRITICAL",
     "title": "Heartbleed — memory disclosure", "cwe": "CWE-200",
     "fix": "Upgrade OpenSSL to 1.0.1g+.", "exploitable": True},
    {"id": "CVE-2022-0778", "product": "openssl", "range": [("lt", "1.1.1n")], "severity": "HIGH",
     "title": "BN_mod_sqrt infinite loop DoS", "cwe": "CWE-400",
     "fix": "Upgrade OpenSSL.", "exploitable": False},
    {"id": "CVE-2023-0286", "product": "openssl", "range": [("lt", "1.1.1t")], "severity": "HIGH",
     "title": "X.400 address type confusion (X.509)", "cwe": "CWE-843",
     "fix": "Upgrade OpenSSL.", "exploitable": False},
    {"id": "CVE-2024-3094", "product": "openssl", "range": [("any",)], "severity": "INFO",
     "title": "Check for XZ backdoor (CVE-2024-3094) on build host", "cwe": "CWE-1103",
     "fix": "Verify build toolchain integrity.", "exploitable": False},
    {"id": "CVE-2019-11043", "product": "php", "range": [("gte", "7.0"), ("lt", "7.3.9")], "severity": "CRITICAL",
     "title": "PHP-FPM underflow RCE via fastcgi", "cwe": "CWE-121",
     "fix": "Upgrade PHP to >= 7.3.9.", "exploitable": True},
    {"id": "CVE-2024-4577", "product": "php", "range": [("gte", "8.1"), ("lt", "8.1.29")], "severity": "CRITICAL",
     "title": "Windows argument-injection RCE", "cwe": "CWE-77",
     "fix": "Upgrade PHP to patched 8.1/8.2/8.3.", "exploitable": True},
    {"id": "CVE-2021-44228", "product": "log4j", "range": [("gte", "2.0"), ("lt", "2.15.0")], "severity": "CRITICAL",
     "title": "Log4Shell — JNDI RCE", "cwe": "CWE-502",
     "fix": "Upgrade log4j-core to 2.17.1+.", "exploitable": True},
    {"id": "CVE-2024-23897", "product": "jenkins", "range": [("lt", "2.442")], "severity": "CRITICAL",
     "title": "Arbitrary file read via CLI", "cwe": "CWE-22",
     "fix": "Upgrade Jenkins to >= 2.442.", "exploitable": True},
    {"id": "CVE-2021-22555", "product": "kubernetes", "range": [("lt", "1.22.0")], "severity": "HIGH",
     "title": "Netfilter privilege escalation (container escape)", "cwe": "CWE-269",
     "fix": "Upgrade Kubernetes; restrict pods.", "exploitable": False},
    {"id": "CVE-2022-22965", "product": "spring", "range": [("gte", "5.3.0"), ("lt", "5.3.18")], "severity": "CRITICAL",
     "title": "Spring4Shell RCE", "cwe": "CWE-94",
     "fix": "Upgrade Spring Framework to >= 5.3.18.", "exploitable": True},
    {"id": "CVE-2023-46604", "product": "activemq", "range": [("lt", "5.18.3")], "severity": "CRITICAL",
     "title": "Classpath RCE in OpenWire transport", "cwe": "CWE-502",
     "fix": "Upgrade ActiveMQ to >= 5.18.3.", "exploitable": True},
    {"id": "CVE-2023-30777", "product": "wordpress", "range": [("lt", "6.2.2")], "severity": "HIGH",
     "title": "Unauthenticated stored XSS (core)", "cwe": "CWE-79",
     "fix": "Upgrade WordPress core to >= 6.2.2.", "exploitable": False},
    {"id": "CVE-2019-15107", "product": "webmin", "range": [("lt", "1.930")], "severity": "CRITICAL",
     "title": "password_change.cgi command injection RCE", "cwe": "CWE-78",
     "fix": "Upgrade Webmin to >= 1.930.", "exploitable": True},
    {"id": "CVE-2024-1086", "product": "linux", "range": [("gte", "5.14"), ("lt", "6.6.14")], "severity": "HIGH",
     "title": "nf_tables use-after-free privilege escalation", "cwe": "CWE-416",
     "fix": "Apply kernel updates.", "exploitable": False},
    {"id": "CVE-2023-32315", "product": "openfire", "range": [("gte", "4.7.0"), ("lt", "4.7.5")], "severity": "HIGH",
     "title": "Admin panel auth bypass", "cwe": "CWE-287",
     "fix": "Upgrade Openfire to >= 4.7.5.", "exploitable": True},
    {"id": "CVE-2023-28322", "product": "tomcat", "range": [("gte", "9.0.0"), ("lt", "9.0.74")], "severity": "MEDIUM",
     "title": "HTTP request smuggling", "cwe": "CWE-444",
     "fix": "Upgrade Tomcat to >= 9.0.74.", "exploitable": False},
    {"id": "CVE-2022-1388", "product": "f5", "range": [("any",)], "severity": "CRITICAL",
     "title": "BIG-IP iControl REST auth bypass RCE", "cwe": "CWE-306",
     "fix": "Apply vendor patch; restrict management interface.", "exploitable": True},
    {"id": "CVE-2023-20198", "product": "cisco", "range": [("any",)], "severity": "CRITICAL",
     "title": "IOS XE web UI privilege escalation", "cwe": "CWE-306",
     "fix": "Apply Cisco advisory; disable web UI if unused.", "exploitable": True},
    {"id": "CVE-2021-26855", "product": "exchange", "range": [("lt", "2016"), ("any",)], "severity": "CRITICAL",
     "title": "ProxyLogon SSRF to RCE", "cwe": "CWE-918",
     "fix": "Apply cumulative updates per Microsoft guidance.", "exploitable": True},
    {"id": "CVE-2024-3400", "product": "panos", "range": [("gte", "10.0"), ("lt", "11.1")], "severity": "CRITICAL",
     "title": "PAN-OS GlobalProtect command injection RCE", "cwe": "CWE-77",
     "fix": "Upgrade PAN-OS; restrict GlobalProtect exposure.", "exploitable": True},
    {"id": "CVE-2023-35078", "product": "ivanti", "range": [("any",)], "severity": "CRITICAL",
     "title": "MobileIron/Sentinel auth bypass", "cwe": "CWE-306",
     "fix": "Apply vendor patch.", "exploitable": True},
    {"id": "CVE-2024-1709", "product": "connectwise", "range": [("any",)], "severity": "CRITICAL",
     "title": "ScreenConnect auth bypass (CWE-284)", "cwe": "CWE-284",
     "fix": "Upgrade ScreenConnect to 23.9.8+.", "exploitable": True},
]
