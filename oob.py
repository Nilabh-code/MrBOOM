"""
MRBOOM // OOB — Interactsh out-of-band blind-vuln verification.
Registers a unique correlation domain with an Interactsh server, hands
payloads the callback URL, then polls for DNS/HTTP callbacks that prove
a blind vulnerability actually fired.

Flow:
  1. register()          — POST /register -> {secret_key, correlation_id, private_key}
  2. poll()              — poll /poll with correlation id -> events []
  3. get_hits(marker)    — filter events for a payload marker (subdomain tag)
  4. wait_for(marker, t) — poll loop until hit or timeout

All traffic goes to user-configured/public Interactsh endpoints only.
Zero non-stdlib deps.
"""
import base64, json, os, ssl, time, urllib.request, urllib.parse, secrets, urllib.error

DEFAULT_SERVERS = [
    "https://oast.pro",
    "https://oast.live",
    "https://oast.site",
    "https://oast.online",
    "https://oast.fun",
    "https://oast.me",
    "https://interact.sh",
]

UA = "Mozilla/5.0 (X11; Linux x86_64) MrBOOM-OOB/1.0"

def _req(url, data=None, headers=None, timeout=10):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read().decode() or "{}")

def pick_server(server=None, timeout=8):
    """Return first reachable Interactsh server (or the one given)."""
    candidates = [server] if server else list(DEFAULT_SERVERS)
    for s in candidates:
        try:
            _req(s.rstrip("/") + "/", timeout=timeout)
            return s.rstrip("/")
        except Exception:
            try:
                _req(s.rstrip("/"), timeout=timeout)
                return s.rstrip("/")
            except Exception:
                continue
    return None

def register(server):
    """Register correlation id. Returns session dict or None."""
    url = server.rstrip("/") + "/register"
    try:
        r = _req(url, data={"secret-key": secrets.token_urlsafe(16)})
        if not r.get("correlation_id"):
            return None
        return {
            "server": server.rstrip("/"),
            "correlation_id": r["correlation_id"],
            "secret_key": r.get("secret_key", ""),
            "private_key": r.get("private_key", ""),
            "public_key": r.get("public_key", ""),
            "domain": r.get("domain", ""),
            "created": time.time(),
        }
    except Exception as e:
        return {"error": str(e)[:200], "server": server}

def callback_url(session, tag=""):
    """Unique callback URL for a payload: http(s)://<tag>.<correlation_id>.<domain>"""
    cid = session.get("correlation_id", "")
    dom = session.get("domain", "") or cid
    host = f"{tag}.{dom}" if tag else dom
    return f"http://{host}"

def poll(session, timeout=10):
    """Poll for OOB events. Returns list of event dicts (protocol, q_type, data...)."""
    url = session["server"].rstrip("/") + "/poll"
    qs = urllib.parse.urlencode({
        "id": session["correlation_id"],
        "secret_key": session.get("secret_key", ""),
    })
    try:
        r = _req(f"{url}?{qs}", timeout=timeout)
        return r.get("data", []) or []
    except Exception as e:
        return [{"error": str(e)[:200]}]

def get_hits(session, marker, events=None):
    """Filter events whose callback contains marker (subdomain tag)."""
    evs = events if events is not None else poll(session)
    hits = []
    m = (marker or "").lower()
    for e in evs:
        blob = json.dumps(e, default=str).lower()
        if m and m in blob:
            hits.append(e)
        elif not m:
            hits.append(e)
    return hits

def wait_for(session, marker, timeout=30, interval=3):
    """Poll loop until a callback tagged with marker arrives (or timeout).
    Returns the first matching event dict or None."""
    end = time.time() + timeout
    seen = set()
    while time.time() < end:
        events = poll(session)
        for e in events:
            key = json.dumps(e, default=str, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            if hits := get_hits(session, marker, [e]):
                return hits[0]
        time.sleep(interval)
    return None

def quick_probe(tag="probe", server=None, timeout=15):
    """One-shot helper: register, return callback url + session.
    Caller fires the payload at target, then calls wait_for()."""
    srv = pick_server(server)
    if not srv:
        return None
    sess = register(srv)
    if not sess or sess.get("error"):
        return None
    return {"session": sess, "callback": callback_url(sess, tag), "tag": tag}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="MrBOOM OOB (Interactsh) helper")
    ap.add_argument("--server", default=os.environ.get("INTERACTSH_SERVER", ""))
    ap.add_argument("--tag", default="probe")
    ap.add_argument("--wait", type=int, default=0, help="seconds to poll after register")
    a = ap.parse_args()
    res = quick_probe(tag=a.tag, server=a.server or None)
    if not res:
        print("NO_SERVER: all Interactsh endpoints unreachable")
        raise SystemExit(1)
    print(json.dumps({"callback": res["callback"], "tag": res["tag"],
                      "server": res["session"]["server"]}, indent=2))
    if a.wait > 0:
        print(f"polling {a.wait}s for '{a.tag}' ...")
        ev = wait_for(res["session"], a.tag, timeout=a.wait)
        print(json.dumps(ev, indent=2, default=str) if ev else "NO HIT")
