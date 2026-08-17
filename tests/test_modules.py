"""
MRBOOM // TESTS — offline unit tests for core modules.
Run:  .mrboom_venv/bin/pytest tests/ -q
No network, no live targets. Sandbox tests use docker/bwrap when present.
"""
import sys, os, json, threading, base64, http.server
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# ─── scope gate (exploit.py) ───────────────────────────────────────────
import exploit

@pytest.fixture(autouse=True)
def _reset_scope():
    exploit.set_scope(None, None, enforce=False)
    yield
    exploit.set_scope(None, None, enforce=False)

class TestScope:
    def test_enforcement_off_allows_all(self):
        assert exploit.in_scope("anything.example.com") is True

    def test_allow_exact_ip(self):
        exploit.set_scope(["127.0.0.1"], enforce=True)
        assert exploit.in_scope("127.0.0.1")
        assert not exploit.in_scope("10.0.0.1")

    def test_allow_cidr(self):
        exploit.set_scope(["192.168.1.0/24"], enforce=True)
        assert exploit.in_scope("192.168.1.46")
        assert not exploit.in_scope("192.168.2.1")

    def test_allow_wildcard_domain(self):
        exploit.set_scope(["*.lab.local"], enforce=True)
        assert exploit.in_scope("dvwa.lab.local")
        assert exploit.in_scope("lab.local")
        assert not exploit.in_scope("evil.com")

    def test_exclusion_wins(self):
        exploit.set_scope(["*.lab.local"], ["prod.lab.local"], enforce=True)
        assert exploit.in_scope("dvwa.lab.local")
        assert not exploit.in_scope("prod.lab.local")

    def test_empty_host_refused_when_enforced(self):
        exploit.set_scope(["*.lab.local"], enforce=True)
        assert not exploit.in_scope("")

    def test_dispatch_refuses_out_of_scope(self):
        exploit.set_scope(["127.0.0.1"], enforce=True)
        r = exploit.dispatch_exploit("redis", "evil.example.com", 6379)
        assert r[0]["success"] is False
        assert "SCOPE VIOLATION" in r[0]["reason"]

    def test_run_auto_exploit_skips_out_of_scope(self):
        exploit.set_scope(["127.0.0.1"], enforce=True)
        res = exploit.run_auto_exploit(
            [{"asset": "evil.example.com:6379", "service": "redis"}],
            lhost="127.0.0.1", lport=14444)
        assert res["shells"] == []
        assert any("SCOPE VIOLATION" in str(x.get("reason", "")) for x in res["results"])

# ─── cvemap ────────────────────────────────────────────────────────────
import cvemap

class TestCvemap:
    def test_apache_traversal_match(self):
        f = cvemap.match_cves([{"product": "httpd", "version": "2.4.49",
                                "asset": "1.2.3.4", "port": 80}])
        ids = {x["cwe"] for x in f}
        assert any("CVE-2021-41773" in x["title"] for x in f)

    def test_no_match_unaffected_version(self):
        f = cvemap.match_cves([{"product": "httpd", "version": "2.4.58",
                                "asset": "x", "port": 80}])
        assert not any("CVE-2021-41773" in x["title"] for x in f)

    def test_nginx_numeric_range(self):
        # CVE-2021-23017 range lt 1.21.0 — pure numeric boundaries
        f = cvemap.match_cves([{"product": "nginx", "version": "1.20.0",
                                "asset": "x", "port": 80}])
        assert any("CVE-2021-23017" in x["title"] for x in f)
        f2 = cvemap.match_cves([{"product": "nginx", "version": "1.21.0",
                                 "asset": "x", "port": 80}])
        assert not any("CVE-2021-23017" in x["title"] for x in f2)

    def test_missing_product_or_version_skipped(self):
        assert cvemap.match_cves([{"product": "", "version": "1"}]) == []
        assert cvemap.match_cves([{"product": "nginx"}]) == []

    def test_finding_shape(self):
        f = cvemap.match_cves([{"product": "nginx", "version": "1.20.0",
                                "asset": "x", "port": 80}])
        assert f
        for k in ("id", "severity", "score", "title", "asset", "tool", "cwe", "evidence", "fix"):
            assert k in f[0]

# ─── disclosure (CVSS math) ────────────────────────────────────────────
import disclosure

class TestDisclosure:
    def test_cvss_critical_rce(self):
        score, sev, _ = disclosure.cvss3(
            "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert abs(score - 10.0) < 0.001
        assert sev == "Critical"

    def test_cvss_log4shell(self):
        score, sev, _ = disclosure.cvss3(
            "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0

    def test_cvss_medium(self):
        score, sev, _ = disclosure.cvss3(
            "AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N")
        assert 4.0 <= score < 7.0
        assert sev == "Medium"

    def test_invalid_vector(self):
        score, sev, _ = disclosure.cvss3("nonsense")
        assert score is None

    def test_severity_for(self):
        assert disclosure.severity_for(10.0) == "critical"
        assert disclosure.severity_for(7.5) == "high"
        assert disclosure.severity_for(5.0) == "medium"
        assert disclosure.severity_for(1.0) == "low"
        assert disclosure.severity_for(0) == "none"

# ─── payloads ──────────────────────────────────────────────────────────
import payloads

class TestPayloads:
    def test_registry_nonempty(self):
        assert len(payloads.classes()) >= 10
        for c in payloads.classes():
            ps = payloads.get(c)
            assert isinstance(ps, list) and len(ps) > 0

    def test_unknown_class_empty(self):
        assert payloads.get("not-a-class") == []

    def test_markers_unique_and_findable(self):
        p1 = payloads.get("xss")[0]
        found = payloads.markers_in(f"prefix {p1} suffix")
        assert len(found) >= 1
        assert found[0].startswith(payloads.MARKER_PREFIX)

    def test_markers_dedupe(self):
        txt = "MRBM_1_x MRBM_1_x MRBM_2_y"
        assert payloads.markers_in(txt) == ["MRBM_1_x", "MRBM_2_y"]

    def test_oob_host_injected(self):
        for cls in ("cmdi", "xxe", "ssrf", "deserialization"):
            ps = payloads.get(cls, oob_host="http://cb.example.com")
            assert any("cb.example.com" in p for p in ps), cls

    def test_custom_marker_used(self):
        ps = payloads.get("xss", marker="MRBM_999_custom")
        assert any("MRBM_999_custom" in p for p in ps)

# ─── oob (offline logic) ───────────────────────────────────────────────
import oob

class TestOob:
    def test_callback_url(self):
        sess = {"correlation_id": "cid123", "domain": "oast.example",
                "server": "https://oast.example"}
        assert oob.callback_url(sess, "tag1") == "http://tag1.oast.example"
        assert oob.callback_url(sess) == "http://oast.example"

    def test_get_hits_filters_marker(self):
        sess = {"correlation_id": "cid", "domain": "x", "server": "s"}
        events = [
            {"protocol": "dns", "full-id": "cid.tag1.host"},
            {"protocol": "http", "full-id": "cid.other.host"},
        ]
        hits = oob.get_hits(sess, "tag1", events)
        assert len(hits) == 1 and hits[0]["protocol"] == "dns"

# ─── nuclei_gen ────────────────────────────────────────────────────────
import nuclei_gen

class TestNucleiGen:
    def test_generate_writes_yaml(self, tmp_path):
        findings = [
            {"title": "Path Traversal", "asset": "127.0.0.1:8080",
             "severity": "CRITICAL", "evidence": "root:x:0:0", "cwe": "CVE-2021-41773"},
        ]
        paths = nuclei_gen.generate(findings, str(tmp_path))
        assert len(paths) == 1
        content = open(paths[0]).read()
        assert "{{BaseURL}}\"" in content
        assert "severity: \"critical\"" in content

    def test_path_extracted_from_url_asset(self, tmp_path):
        findings = [
            {"title": "Git Config", "asset": "http://h:8080/.git/config",
             "severity": "HIGH", "evidence": "repositoryformatversion"},
        ]
        paths = nuclei_gen.generate(findings, str(tmp_path))
        assert "{{BaseURL}}/.git/config" in open(paths[0]).read()

    def test_yaml_parses(self, tmp_path):
        yaml = pytest.importorskip("yaml")
        findings = [{"title": "T", "asset": "http://h/x", "severity": "LOW",
                     "evidence": "zzzz", "cwe": "CVE-1"}]
        paths = nuclei_gen.generate(findings, str(tmp_path))
        doc = yaml.safe_load(open(paths[0]))
        assert doc["info"]["severity"] == "low"

    def test_dedupe(self, tmp_path):
        f = {"title": "Dup", "asset": "h", "severity": "LOW", "evidence": "e"}
        paths = nuclei_gen.generate([f, dict(f)], str(tmp_path))
        assert len(paths) == 1

# ─── cred_spray (scope gate + localhost http-basic) ────────────────────
import cred_spray

class _BasicHandler(http.server.BaseHTTPRequestHandler):
    ok_creds = b"admin:Password1"
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth == "Basic " + base64.b64encode(self.ok_creds).decode():
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        else:
            self.send_response(401); self.end_headers()
    def log_message(self, *a): pass

class TestCredSpray:
    @staticmethod
    def _serve():
        srv = http.server.HTTPServer(("127.0.0.1", 0), _BasicHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    def test_sprays_and_hits(self):
        exploit.set_scope(["127.0.0.1"], enforce=True)
        srv, port = self._serve()
        try:
            res = cred_spray.spray(f"127.0.0.1:{port}", proto="http-basic",
                                   usernames=["root", "admin"],
                                   passwords=["wrong1", "Password1"], delay=0)
            assert any(h["user"] == "admin" and h["password"] == "Password1"
                       for h in res["hits"])
        finally:
            srv.shutdown()

    def test_scope_refused(self):
        exploit.set_scope(["127.0.0.1"], enforce=True)
        with pytest.raises(RuntimeError, match="SCOPE VIOLATION"):
            cred_spray.spray("evil.example.com")

    def test_lockout_cap(self):
        exploit.set_scope(["127.0.0.1"], enforce=True)
        srv, port = self._serve()
        try:
            res = cred_spray.spray(f"127.0.0.1:{port}", proto="http-basic",
                                   usernames=["u1"],
                                   passwords=["a", "b", "c", "d", "e", "f"],
                                   delay=0, lockout_threshold=4)
            # capped at threshold-1 passwords per user
            assert res["passwords_per_user"] == 3
        finally:
            srv.shutdown()

# ─── research_agent sandbox ────────────────────────────────────────────
import research_agent as ra

class TestSandbox:
    def test_select_auto_prefers_docker_or_bwrap(self):
        mode = ra.select_sandbox("auto")
        assert mode in ("docker", "bwrap", "local")

    def test_execute_marker(self):
        import shutil as _sh
        if not (_sh.which("docker") or _sh.which("bwrap")):
            pytest.skip("no sandbox backend installed")
        r = ra.execute_poc('print("TRIGGERED:TRUE")', sandbox="auto")
        assert r["triggered"] is True
        assert r["sandbox"] in ("docker", "bwrap")

    def test_execute_fs_isolation(self):
        import shutil as _sh
        if not _sh.which("docker"):
            pytest.skip("docker not installed")
        r = ra.execute_poc(
            'import os; print("ESCAPED" if os.path.exists("/home/nil/.ssh") else "TRIGGERED:TRUE")',
            sandbox="docker")
        assert "TRIGGERED:TRUE" in r["output_tail"]
        assert "ESCAPED" not in r["output_tail"]

    def test_local_mode_still_works(self):
        r = ra.execute_poc('print("TRIGGERED:TRUE")', sandbox="local")
        assert r["triggered"] is True

# ─── source_scan (semgrep optional) ────────────────────────────────────
import source_scan as ss

class TestSourceScan:
    def test_heuristic_sink_found(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import os\ndef f(c):\n    os.system(c)\n")
        fs = ss.scan_repo(str(tmp_path), top=5)
        assert any("os.system" in f["title"] for f in fs)

    def test_semgrep_fallback_no_crash(self, tmp_path):
        # must never raise even if semgrep absent
        res = ss.semgrep_scan(str(tmp_path), timeout=60)
        assert isinstance(res, list)

    def test_semgrep_taint_when_available(self, tmp_path):
        if not ss.semgrep_bin():
            pytest.skip("semgrep not installed")
        (tmp_path / "x.py").write_text(
            'import os, flask\ndef f():\n'
            '    cmd = flask.request.args.get("c")\n    os.system(cmd)\n')
        cands = ss.semgrep_scan(str(tmp_path), timeout=120)
        assert len(cands) >= 1
        assert cands[0].get("semgrep") is True

# ─── app.py bind/auth helpers ──────────────────────────────────────────
class TestAppBind:
    def test_is_loopback(self):
        import app
        assert app._is_loopback("127.0.0.1")
        assert app._is_loopback("localhost")
        assert app._is_loopback("::1")
        assert not app._is_loopback("0.0.0.0")
        assert not app._is_loopback("192.168.1.5")

# ─── TRINITY 3-agent pipeline (offline, against loopback lab) ─────────
class TestTrinity:
    @staticmethod
    def _lab():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "vuln_lab", os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "lab", "vuln_lab.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), m.Vun)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    def test_full_triad_confirms_and_rejects(self):
        import trinity
        srv, port = self._lab()
        try:
            r = trinity.run_triad(f"http://127.0.0.1:{port}", budget=60, timeout=6)
            classes = {f["class"] for f in r["findings"]}
            assert "xss" in classes
            assert "sqli" in classes
            assert "traversal" in classes
            assert r["skeptic"]["confirmed"] >= 3
            # every finding must have a cvss or have been demoted — and the
            # decoy /crumb page (contains '49') must NOT produce a finding
            for f in r["findings"]:
                assert "/crumb" not in f["url"]
        finally:
            srv.shutdown()

    def test_scope_gate_blocks_foreign_hosts(self):
        import trinity
        # SKEPTIC/STRIKER fetch helpers must never follow a forged url off-scope
        s = trinity.Skeptic("example.com", timeout=2)
        assert s._get("http://169.254.169.254/latest/meta-data/")[0] == 0
        k = trinity.Striker("example.com", timeout=2)
        assert k._get("http://10.0.0.1/")[0] == 0
