import subprocess, json

proc = subprocess.Popen(
    ['/home/nil/DrDOOM/DrDoom-master/.venv/bin/python', '/home/nil/DrDOOM/DrDoom-master/mcp_server.py'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

init_req = json.dumps({
    'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
    'params': {
        'protocolVersion': '2024-11-05',
        'capabilities': {},
        'clientInfo': {'name': 'test', 'version': '1.0'}
    }
}) + '\n'
proc.stdin.write(init_req.encode())
proc.stdin.flush()

response = proc.stdout.readline()
tools = json.loads(response.decode())
print('Tool count:', len(tools.get('result', {}).get('tools', [])))

proc.terminate()
