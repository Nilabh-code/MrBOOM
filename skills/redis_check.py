"""
Check if a Redis server is accessible without authentication (no-auth misconfiguration).
Works on Redis servers (port 6379 default) that have no AUTH password set.
Sends PING, INFO, and KEYS * commands to enumerate the database.
Returns all readable keys and server info if no auth is required.
"""
import socket
import json

def run(host: str, port: int = 6379, timeout: int = 15) -> dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        def redis_cmd(*args):
            msg = "*" + str(len(args)) + "\r\n"
            for a in args:
                a_bytes = a.encode() if isinstance(a, str) else a
                msg += "$" + str(len(a_bytes)) + "\r\n" + a_bytes.decode(errors="replace") + "\r\n"
            s.sendall(msg.encode())
            return s.recv(65536).decode(errors="replace")
        resp = redis_cmd("PING")
        if "+PONG" not in resp:
            s.close()
            return {"success": False, "data": "", "evidence": "PING failed"}
        info_raw = redis_cmd("INFO")
        keys_raw = redis_cmd("KEYS", "*")
        s.close()
        evidence_parts = []
        if "NOAUTH" not in info_raw and "NOAUTH" not in keys_raw:
            evidence_parts.append("NO_AUTH_REQUIRED")
        for line in info_raw.split("\r\n"):
            if line.startswith("redis_version:"):
                evidence_parts.append(line.strip())
            if line.startswith("os:"):
                evidence_parts.append(line.strip())
        key_count = len([k for k in keys_raw.split("\r\n") if k and not k.startswith("$") and not k.startswith("*")])
        evidence_parts.append(f"keys_found:{key_count}")
        return {
            "success": True,
            "data": json.dumps({"info": info_raw[:2000], "keys_preview": keys_raw[:2000]}),
            "evidence": ", ".join(evidence_parts)
        }
    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}
