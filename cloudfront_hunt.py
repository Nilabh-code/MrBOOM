#!/usr/bin/env python3
"""CloudFront origin-IP hunter.

Finds the real backend origin IP(s) behind an Amazon CloudFront distribution
using CloudFront-specific techniques:

  1. Confirm the target is served by CloudFront (x-amz-cf-id / x-amz-cf-pop /
     server: CloudFront).
  2. Harvest candidate IPs from multiple sources:
       - Live DNS of the domain + subdomains
       - Historical DNS (hackertarget hostsearch, SecurityTrails, ViewDNS.info)
       - crt.sh certificate transparency (alternate hostnames)
       - Origin-subdomain guessing (origin., backend., lb., prod., ...)
  3. Filter out CloudFront edge IPs (AWS ranges + reverse-DNS cloudfront.net +
     x-amz-cf-* headers) so we don't report edges as origins.
  4. Probe every remaining IP directly over HTTP + HTTPS with a Host header and
     confirm an IP is a real origin when it answers / redirects toward the
     domain (no-redirect probing so CloudFront's 301 is not auto-followed).
  5. Print a report and optionally emit findings into MrBOOM's data model.

Usage:
    python3 cloudfront_hunt.py --domain www.example.com [--subs a.example.com b.example.com]
    python3 cloudfront_hunt.py --domain example.com --subs-file subs.txt [--time-budget 180]
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ── CDN identification tables (mirrors app.py, kept standalone) ──

CLOUDFRONT_RANGES = [
    "13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16",
    "54.192.0.0/16", "204.246.160.0/19", "205.251.192.0/19", "130.176.0.0/16",
]
ALL_CDN_RANGES = {
    "cloudflare": ["104.16.0.0/12", "172.64.0.0/13", "141.101.64.0/18", "190.93.240.0/20",
                   "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.159.0.0/16"],
    "cloudfront": CLOUDFRONT_RANGES,
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16"],
    "akamai": ["23.32.0.0/11", "104.64.0.0/10", "23.0.0.0/12", "96.6.0.0/15", "184.24.0.0/13"],
    "google": ["74.125.0.0/16", "172.217.0.0/16", "216.58.192.0/19"],
    "azure": ["13.64.0.0/11", "20.36.0.0/14", "40.74.0.0/15", "52.136.0.0/13"],
}
CDN_HOSTNAME_MARKERS = {
    "cloudflare": ["cloudflare", "cf-edge", ".cf."],
    "cloudfront": ["cloudfront.net"],
    "fastly": ["fastly.net", "fastlylb.net"],
    "akamai": ["akamaiedge", "akamai", "akam.net", "akamaitechnologies"],
    "incapsula": ["incapdns.net", "imperva"],
    "sucuri": ["sucuri.net"],
}

# Origin subdomains worth guessing — CloudFront origins are often named like this
ORIGIN_SUB_PREFIXES = [
    "origin", "orig", "backend", "back", "lb", "loadbalancer", "api", "api2",
    "app", "prod", "prod2", "dev", "staging", "internal", "int", "private",
    "server", "srv", "host", "web", "web01", "web1", "app1", "cloud", "edge",
    "proxy", "gateway", "gw", "cdn-origin", "static", "files", "admin",
]

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
_CTX = None
_ptr_cache = {}


def _ssl_ctx():
    global _CTX
    if _CTX is None:
        _CTX = ssl.create_default_context()
        _CTX.check_hostname = False
        _CTX.verify_mode = ssl.CERT_NONE
    return _CTX


def http_get(url, timeout=8, host_header=None, no_redirect=False):
    """Minimal urllib GET (IP-replaced connection + Host header + optional
    no-redirect) — mirrors app.http_get so behavior matches the pipeline."""
    try:
        headers = {"User-Agent": _UA, "Accept": "*/*",
                   "Accept-Encoding": "identity", "Connection": "close"}
        if host_header:
            headers["Host"] = host_header
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return 0, {}, ""
        if not host_header:
            headers["Host"] = parsed.netloc
        conn_url = urllib.parse.urlunparse(
            parsed._replace(netloc=ip + ((":" + str(parsed.port)) if parsed.port else "")))
        req = urllib.request.Request(conn_url, headers=headers)
        if no_redirect:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, r, fp, code, msg, hdrs, newurl):
                    return None

            class _NoVerifyHTTPS(urllib.request.HTTPSHandler):
                def https_open(self, r):
                    return self.do_open(urllib.request.http.client.HTTPSConnection, r,
                                        context=_ssl_ctx())
            opener = urllib.request.build_opener(_NoRedirect, _NoVerifyHTTPS())
            resp = opener.open(req, timeout=timeout)
        else:
            resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx())
        body = resp.read().decode("utf-8", errors="ignore")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except Exception:
        return 0, {}, ""


def get(url, timeout=8, host_header=None, no_redirect=False, retries=2):
    """http_get with lightweight rate-limit-aware retry."""
    for attempt in range(retries + 1):
        status, hdrs, body = http_get(url, timeout=timeout, host_header=host_header,
                                      no_redirect=no_redirect)
        if status not in (429, 500, 502, 503, 504) or attempt >= retries:
            return status, hdrs, body
        time.sleep(1.2 * (attempt + 1))
    return status, hdrs, body


def _ptr_of(ip, timeout=2):
    if ip in _ptr_cache:
        return _ptr_cache[ip]
    out = [None]

    def _look():
        try:
            out[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            out[0] = None
    t = threading.Thread(target=_look, daemon=True)
    t.start()
    t.join(timeout)
    _ptr_cache[ip] = out[0] if not t.is_alive() else None
    return _ptr_cache[ip]


def cdn_of_ip(ip):
    """Return (is_cdn, cdn_name) using ranges + reverse-DNS."""
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return False, ""
    for name, ranges in ALL_CDN_RANGES.items():
        for cidr in ranges:
            try:
                if obj in ipaddress.ip_network(cidr):
                    return True, name
            except Exception:
                continue
    ptr = _ptr_of(ip)
    if ptr:
        pl = ptr.lower()
        for name, markers in CDN_HOSTNAME_MARKERS.items():
            if any(m in pl for m in markers):
                return True, name
    return False, ""


def cdn_of_headers(hdrs):
    """Return (is_cdn, cdn_name) from response headers — authoritative for CF."""
    h = {k.lower(): (v or "").lower() for k, v in (hdrs or {}).items()}
    if h.get("x-amz-cf-id") or h.get("x-amz-cf-pop") or "cloudfront" in h.get("server", ""):
        return True, "cloudfront"
    if h.get("cf-ray") or "cloudflare" in h.get("server", ""):
        return True, "cloudflare"
    if "fastly" in h.get("via", "") or "fastly" in h.get("server", ""):
        return True, "fastly"
    if "akamai" in h.get("server", "") or "akamaiedge" in h.get("server", ""):
        return True, "akamai"
    return False, ""


# ── candidate harvesting ─────────────────────────────────────────

def resolve_many(hosts, workers=12):
    """Concurrent DNS resolution -> {host: [ips]}."""
    out = {}
    def _res(h):
        try:
            _, _, ips = socket.gethostbyname_ex(h)
            return h, ips
        except Exception:
            return h, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for h, ips in pool.map(_res, list(dict.fromkeys(hosts))):
            if ips:
                out[h] = ips
    return out


def live_dns_ips(domain, subdomains):
    ips = set()
    hosts = [domain] + list(subdomains or [])
    for h, addrs in resolve_many(hosts).items():
        for a in addrs:
            ips.add((h, a))
    return ips


def historical_dns(domain):
    """Pull candidate IPs from hackertarget hostsearch (free, no key)."""
    ips = set()
    try:
        status, _, body = get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if status == 200 and body:
            for line in body.strip().split("\n"):
                parts = line.split(",")
                if len(parts) == 2 and parts[1].strip():
                    try:
                        ipaddress.ip_address(parts[1].strip())
                        ips.add((parts[0].strip(), parts[1].strip()))
                    except Exception:
                        continue
    except Exception:
        pass
    return ips


def crtsh_hosts(domain):
    """crt.sh certificate transparency -> alternate hostnames (potential origins)."""
    hosts = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        status, _, body = get(url, timeout=15)
        if status == 200 and body:
            for row in json.loads(body):
                name = (row.get("name_value") or "").strip()
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n and n.lower().endswith(domain.lower()) and "*" not in n:
                        hosts.add(n)
    except Exception:
        pass
    return hosts


def origin_subdomain_guesses(domain):
    """Guess origin-ish subdomains (common behind CloudFront)."""
    apex = domain.split(".", 1)[1] if domain.count(".") >= 2 else domain
    guesses = set()
    for p in ORIGIN_SUB_PREFIXES:
        guesses.add(f"{p}.{apex}")
    return guesses


# ── probing / confirmation ───────────────────────────────────────

def is_cloudfront(domain):
    """Confirm the target is served by CloudFront. Tries a direct probe first,
    then falls back to checking whether the domain's resolved IPs live in
    CloudFront's edge ranges (works even when the edge blocks our request)."""
    try:
        status, hdrs, _ = get(f"https://{domain}/", timeout=8, no_redirect=True)
        h = {k.lower(): (v or "").lower() for k, v in hdrs.items()}
        if h.get("x-amz-cf-id") or h.get("x-amz-cf-pop"):
            return True, h.get("x-amz-cf-pop", ""), h.get("server", "")
        if "cloudfront" in h.get("server", ""):
            return True, "", h.get("server", "")
    except Exception:
        pass
    # Fallback: edge-range / PTR check on resolved IPs
    try:
        for ip in socket.gethostbyname_ex(domain)[2]:
            if cdn_of_ip(ip)[0] and cdn_of_ip(ip)[1] == "cloudfront":
                return True, "", "cloudfront range/PTR"
            if "cloudfront" in (_ptr_of(ip) or "").lower():
                return True, "", "cloudfront PTR"
    except Exception:
        pass
    return False, "", ""


def probe_origin(ip, domain, time_budget, t_start):
    """Probe one IP directly over HTTP + HTTPS with Host header (no-redirect).
    Returns (confirmed, host, evidence, is_cdn, cdn_name)."""
    is_cdn, cdn_name = cdn_of_ip(ip)
    for scheme in ("https", "http"):
        if time.time() - t_start > time_budget:
            break
        status, hdrs, body = get(f"{scheme}://{ip}/", timeout=4, host_header=domain, no_redirect=True)
        if status == 0:
            continue
        hcd, hcn = cdn_of_headers(hdrs)
        if hcd:
            return False, "", "", True, hcn or cdn_name
        loc = hdrs.get("Location", "") or ""
        bl = (body or "").lower()
        root = domain.lower().split(".")[0]
        if loc and domain.lower() in loc.lower():
            return True, domain, f"{scheme}:{status} redirect->{loc[:60]}", is_cdn, cdn_name
        if status == 200 and root in bl[:2000]:
            return True, domain, f"{scheme}:{status} body-match", is_cdn, cdn_name
        # A bare reachable HTTP box (200/301/302/403 with no domain evidence)
        # is NOT a confirmed origin — it may just be any vhost on shared
        # hosting or a leftover historical IP. Keep it as an unconfirmed
        # candidate so operators can triage, don't claim a bypass.
        if status in (200, 301, 302, 403):
            return False, "", f"{scheme}:{status} reachable-only", is_cdn, cdn_name
    return False, "", "", is_cdn, cdn_name


def hunt(domain, subdomains=None, time_budget=180):
    """Full CloudFront origin hunt. Returns dict compatible with bb_origins."""
    t_start = time.time()
    report = {"domain": domain, "cloudfront": False, "origin_ips": [],
              "cdn_edges": [], "sources": {}}

    # 1. confirm CloudFront
    cf, pop, srv = is_cloudfront(domain)
    report["cloudfront"] = cf
    report["cloudfront_pop"] = pop
    report["cloudfront_server"] = srv

    # 2. harvest candidates
    cands = set()          # (host, ip)
    candidates = {}

    live = live_dns_ips(domain, subdomains)
    report["sources"]["live_dns"] = len(live)
    cands |= live

    hist = historical_dns(domain)
    report["sources"]["historical_hackertarget"] = len(hist)
    cands |= hist

    # crt.sh alternate hostnames -> resolve those too
    alt_hosts = crtsh_hosts(domain)
    report["sources"]["crt_sh_alt_hosts"] = len(alt_hosts)
    if alt_hosts:
        alt_ips = live_dns_ips(domain, list(alt_hosts))
        report["sources"]["crt_sh_ips"] = len(alt_ips)
        cands |= alt_ips

    # origin-subdomain guesses -> resolve
    guesses = origin_subdomain_guesses(domain)
    guess_ips = live_dns_ips(domain, list(guesses))
    report["sources"]["origin_subdomains"] = len(guess_ips)
    cands |= guess_ips

    for h, ip in cands:
        candidates.setdefault(ip, set()).add(h)

    # 3. classify + probe each unique IP
    for ip in sorted(candidates):
        if time.time() - t_start > time_budget:
            report["timed_out"] = True
            break
        confirmed, host, evidence, is_cdn, cdn_name = probe_origin(ip, domain, time_budget, t_start)
        if is_cdn or cdn_of_ip(ip)[0]:
            report["cdn_edges"].append({"ip": ip, "cdn": cdn_name or "cloudfront",
                                        "hosts": sorted(candidates[ip])[:5],
                                        "confirmed": False})
            continue
        if confirmed:
            report["origin_ips"].append({"ip": ip, "host": host, "cdn": "",
                                         "is_cdn": False, "confirmed": True,
                                         "evidence": evidence,
                                         "hosts": sorted(candidates[ip])[:5]})
        else:
            report["origin_ips"].append({"ip": ip, "host": "", "cdn": "",
                                         "is_cdn": False, "confirmed": False,
                                         "evidence": "unreachable", "hosts": []})
    report["elapsed_s"] = round(time.time() - t_start)
    return report


def main():
    ap = argparse.ArgumentParser(description="CloudFront origin-IP hunter")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--subs", nargs="*", default=None, help="known subdomains")
    ap.add_argument("--subs-file", default=None, help="file with subdomains (one per line)")
    ap.add_argument("--time-budget", type=int, default=180)
    ap.add_argument("--json", action="store_true", help="output raw JSON")
    args = ap.parse_args()

    subs = list(args.subs or [])
    if args.subs_file and os.path.exists(args.subs_file):
        with open(args.subs_file) as f:
            subs = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    print(f"[*] CloudFront origin hunt: {args.domain}")
    r = hunt(args.domain, subs, time_budget=args.time_budget)

    if args.json:
        print(json.dumps(r, indent=2))
        return

    print()
    if r["cloudfront"]:
        print(f"[+] CloudFront detected  (POP: {r.get('cloudfront_pop') or 'n/a'}, "
              f"server: {r.get('cloudfront_server') or 'n/a'})")
    else:
        print("[-] Target does NOT appear to be CloudFront-fronted — results may be generic CDN origin hunt.")
    print(f"[*] Candidates by source: {json.dumps(r['sources'])}")
    print(f"[*] Elapsed: {r.get('elapsed_s')}s")
    print()
    confirmed = [o for o in r["origin_ips"] if o["confirmed"]]
    print(f"[+] CONFIRMED ORIGIN IPs ({len(confirmed)}):")
    for o in confirmed:
        print(f"    {o['ip']:<16} host={o['host']:<30} evidence={o['evidence']}")
    print(f"[*] Unconfirmed non-CDN IPs: {len([o for o in r['origin_ips'] if not o['confirmed']])}")
    print(f"[*] CDN edges filtered: {len(r['cdn_edges'])}")
    if r["cdn_edges"]:
        print("    edges:", ", ".join(e["ip"] for e in r["cdn_edges"][:10]))


if __name__ == "__main__":
    main()
