"""Intentionally-vulnerable local target for TRINITY testing.
ONLY binds 127.0.0.1. Never use outside testing."""
import http.server, re, urllib.parse, json, os

class Vun(http.server.BaseHTTPRequestHandler):
    def _html(self, body, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def _json(self, obj, code=200):
        self._html(json.dumps(obj), code, {"Content-Type": "application/json"})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if u.path == "/":
            self._html("""<html><body><h1>VulnLab</h1>
<form action="/search" method="GET"><input name="q" value=""><button>Go</button></form>
<a href="/profile?id=1">profile</a> <a href="/file?name=about.txt">file</a>
<a href="/api/v1/users">api</a> <a href="/go?next=/home">redirect link</a>
<a href="/render?tpl=hello">greeting</a> <a href="/ping?host=127.0.0.1">net-tool</a>
<a href="/crumb">docs</a>
</body></html>""")
        elif u.path == "/search":
            qq = (q.get("q") or [""])[0]
            # reflected XSS: q echoed raw into HTML
            self._html(f"<p>Results for: {qq}</p>no results found")
        elif u.path == "/profile":
            pid = (q.get("id") or ["1"])[0]
            # SQLi: arithmetic eval oracle — we emulate a DB doing math
            try:
                if re.match(r"^[\d\*\+\-\s]+$", pid) and "*" in pid:
                    val = eval(pid)
                    self._html(f"<div class='profile'>User #{val}</div>")
                    return
            except Exception:
                pass
            if pid == "4243":
                self._html("no such user")
            else:
                self._html(f"<div class='profile'>User #{pid} - some long bio text " + "x"*200 + "</div>")
        elif u.path == "/file":
            name = (q.get("name") or [""])[0]
            # path traversal
            if "etc/passwd" in name:
                self._html("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            elif "etc/hosts" in name:
                self._html("127.0.0.1 localhost\n::1 localhost\n")
            else:
                self._html(f"file {name} not found")
        elif u.path == "/go":
            nxt = (q.get("next") or ["/"])[0]
            # open redirect
            self._html("", 302, {"Location": nxt if nxt.startswith("http") else nxt})
        elif u.path == "/api/v1/users":
            self._json([{"id": 1, "name": "admin", "role": "superuser"},
                        {"id": 2, "name": "jane", "role": "user"}])
        elif u.path == "/render":
            tpl = (q.get("tpl") or [""])[0]
            # SSTI: arithmetic oracle
            m = re.findall(r"(\w+)\{\{(\d+)\*(\d+)\}\}", tpl)
            if m:
                marker, a, b = m[0]
                self._html(f"<p>{marker}{int(a)*int(b)}</p>")
            else:
                self._html(f"<p>{tpl}</p>")
        elif u.path == "/ping":
            host = (q.get("host") or [""])[0]
            # cmdi: echo marker oracle
            m = re.search(r";\s*echo\s+([A-Za-z0-9_]+)", host)
            if m:
                self._html(f"<pre>ping output:\n{m.group(1)}\n64 bytes from host</pre>")
            else:
                self._html(f"<pre>ping output: PING {host}</pre>")
        elif u.path == "/crumb":
            # control page that CONTAINS "49" to prove SKEPTIC doesn't
            # false-positive SSTI here
            self._html("<p>The answer is 49 and marker TBssti is reflected: TBssti</p>")
        else:
            self._html("not found", 404)

    def log_message(self, *a): pass

if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8777), Vun)
    print("VulnLab on http://127.0.0.1:8777 (intentionally vulnerable, loopback only)")
    srv.serve_forever()
