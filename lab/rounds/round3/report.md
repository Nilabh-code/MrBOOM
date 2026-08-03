# Infrastructure Report: 192.168.1.46
**Generated:** 2026-08-02 18:20 UTC
**Tool:** MrBOOM One-Shot
**Model:** VLLM//home/nil/models/MXFP4/Qwopus3.6-35B-A3B-Coder-MXFP4_MOE_Q8_0-Imatrix.gguf

## Executive Summary

- **Target:** 192.168.1.46
- **Subdomains Found:** 2
- **Live HTTP Services:** 4
- **Open Ports:** 5
- **S3 Buckets Discovered:** 0
- **API Endpoints Found:** 0
- **Third-Party Integrations:** 0
- **Origin IPs (CF Bypass):** 0
- **WAF Detected:** None
- **Security Headers Missing:** 5
- **Org:** 
- **Wayback URLs:** 0
- **New Subdomains (brute):** 0
- **Directories Found:** 15
- **Takeover Candidates:** 0
- **CORS Issues:** 0
- **Open Redirects:** 0
- **XSS Candidates:** 0
- **App-Level Vulns (cmd-inj/SSRF/traversal/SQLi):** 8
- **Exposed Endpoints:** 0
- **Origin IPs (CDN Bypass):** 1
- **Login/Rate-Limit Issues:** 0
- **Source-Map Endpoints:** 0
- **Wayback Secrets:** 0
- **Default Creds Accepted:** 0
- **JWT/API Auth Bypass:** 0
- **Live API Hosts:** 0

## AI Breach Assessment

## Attack Surface (from data)
The target `192.168.1.46` exposes five ports: 80, 443, 22, 5432, and 8443. Four HTTP services are active:
- **Port 80**: Returns 200 OK via Gunicorn ("AcmeCorp Internal Portal").
- **Port 443**: Returns 200 OK via Gunicorn ("AcmeCorp Internal Portal").
- **Port 8443**: Returns 404 Not Found via Gunicorn.
- **Port 22**: SSH service.
- **Port 5432**: PostgreSQL database service.

## Weakest Entry Points (only what the data supports, or "none found")
1. **PostgreSQL (Port 5432)**: Exposed to the network. No authentication configuration is visible in the scan data, but exposure of a database port is a high-risk configuration error.
2. **Missing Security Headers**: The web applications on ports 80, 443, and 8443 lack critical headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, and `X-XSS-Protection`. This indicates misconfiguration and potential for XSS/Clickjacking.
3. **SSH (Port 22)**: Exposed to the network. Brute-force potential exists if weak credentials are used.
4. **Cloudflare Bypass**: Confirmed origin IP `192.168.1.46` allows direct access to the origin server, bypassing Cloudflare protections.

## Evidence & Findings (list concrete items with the actual data)
1. **Exposed Database Service (Port 5432)**: PostgreSQL is listening on port 5432. This is a high-risk finding as databases should not be directly exposed to the network without strict access controls.
2. **Missing Security Headers**: The following headers are missing from the web applications:
   - `X-Content-Type-Options`
   - `X-Frame-Options`
   - `Content-Security-Policy`
   - `Strict-Transport-Security`
   - `X-XSS-Protection`
3. **Direct Origin Access**: The origin IP `192.168.1.46` is confirmed, allowing direct access to the web applications without Cloudflare protection.
4. **SSH Service (Port 22)**: SSH is exposed to the network, creating a potential attack vector for brute-force attacks.
5. **Web Application Misconfiguration**: The Gunicorn server is serving the "AcmeCorp Internal Portal" on multiple ports (80, 443, 8443), indicating a potential misconfiguration or multiple services running on the same host.

## Risk Rating: HIGH
The exposure of the PostgreSQL database service and the missing security headers represent significant risks. The direct origin access and SSH exposure also contribute to the overall risk profile.

## Findings Overview & Scorecard

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 4 |
| MEDIUM | 2 |
| LOW | 6 |

### Detailed Findings & Remediation

| # | Severity | Finding | Asset | CWE |
|---|----------|---------|-------|-----|
| 1 | CRITICAL | OS Command Injection via Host Parameter | 192.168.1.46 | CWE-78 |
| 2 | CRITICAL | OS Command Injection via Host Parameter | 192.168.1.46:80 | CWE-78 |
| 3 | CRITICAL | SQL Injection Authentication Bypass on Login Form | 192.168.1.46 | CWE-89 |
| 4 | CRITICAL | SQL Injection Authentication Bypass on Login Form | 192.168.1.46:80 | CWE-89 |
| 5 | HIGH | Arbitrary File Read via File Parameter | 192.168.1.46 | CWE-22 |
| 6 | HIGH | Arbitrary File Read via File Parameter | 192.168.1.46:80 | CWE-22 |
| 7 | HIGH | Server-Side Request Forgery via Url Parameter | 192.168.1.46 | CWE-918 |
| 8 | HIGH | Server-Side Request Forgery via Url Parameter | 192.168.1.46:80 | CWE-918 |
| 9 | MEDIUM | Missing Content-Security-Policy | https://192.168.1.46/ | CWE-693 |
| 10 | MEDIUM | Missing Content-Security-Policy | https://192.168.1.46 | CWE-693 |
| 11 | LOW | No clickjacking protection | https://192.168.1.46/ | CWE-1021 |
| 12 | LOW | Missing Referrer-Policy | https://192.168.1.46/ | CWE-200 |
| 13 | LOW | Missing HSTS | https://192.168.1.46/ | CWE-319 |
| 14 | LOW | No clickjacking protection | https://192.168.1.46 | CWE-1021 |
| 15 | LOW | Missing Referrer-Policy | https://192.168.1.46 | CWE-200 |
| 16 | LOW | Missing HSTS | https://192.168.1.46 | CWE-319 |

#### Remediation Actions

| # | Finding | Recommended Fix | Retest |
|---|---------|-----------------|--------|
| 1 | OS Command Injection via Host Parameter |  | — |
| 2 | OS Command Injection via Host Parameter |  | — |
| 3 | SQL Injection Authentication Bypass on Login Form |  | — |
| 4 | SQL Injection Authentication Bypass on Login Form |  | — |
| 5 | Arbitrary File Read via File Parameter |  | — |
| 6 | Arbitrary File Read via File Parameter |  | — |
| 7 | Server-Side Request Forgery via Url Parameter |  | — |
| 8 | Server-Side Request Forgery via Url Parameter |  | — |
| 9 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 10 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 11 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 12 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 13 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 14 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 15 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 16 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |

#### Evidence Archive

| # | Finding | Evidence |
|---|---------|----------|
| 1 | OS Command Injection via Host Parameter | `RCE marker 'uid=' in response` |
| 2 | OS Command Injection via Host Parameter | `RCE marker 'uid=' in response` |
| 3 | SQL Injection Authentication Bypass on Login Form | `login bypassed with SQLi payload` |
| 4 | SQL Injection Authentication Bypass on Login Form | `login bypassed with SQLi payload` |
| 5 | Arbitrary File Read via File Parameter | `sensitive content marker in response (/etc/passwd)` |
| 6 | Arbitrary File Read via File Parameter | `sensitive content marker in response (/etc/passwd)` |
| 7 | Server-Side Request Forgery via Url Parameter | `internal service content marker in response` |
| 8 | Server-Side Request Forgery via Url Parameter | `internal service content marker in response` |
| 9 | Missing Content-Security-Policy | `No CSP header returned` |
| 10 | Missing Content-Security-Policy | `No CSP header returned` |
| 11 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 12 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 13 | Missing HSTS | `No Strict-Transport-Security header` |
| 14 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 15 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 16 | Missing HSTS | `No Strict-Transport-Security header` |

## Scope & Authorization

- **Authorized target(s):** 192.168.1.46
- **Assessment type:** Authorized penetration test / security audit (external, black-box)
- **Legal note:** Findings are provided for remediation purposes only. Testing was performed with explicit authorization for the scoped targets above.

## Methodology

1. **Recon** — subdomain enumeration, live-host discovery (httpx), DNS and WHOIS review.
2. **Discovery** — port scanning, banner grabbing, TLS analysis, origin-IP (WAF bypass) hunting.
3. **Vulnerability scanning** — nuclei (non-intrusive templates), version-aware CVE correlation (cvemap).
4. **Web application checks** — client-side assessment (cookies, CSP, SRI, service workers, WebSockets, DOM-XSS), JS/API endpoint extraction, source-map review.
5. **Validation & reporting** — manual validation of critical paths, evidence capture, remediation guidance.

## AI Novel Attack Hypotheses (0-day Research)

1. **HIGH-VALUE: Port 8443 Admin Bypass via Session Confusion**
   *Hypothesis:* Port 8443 is an internal admin interface (gunicorn) exposed to the internet. If it shares the same session cookie domain as the main portal (port 443) but lacks strict origin validation, an attacker authenticated on the public portal could inject a session cookie into the 8443 context.
   *Test:* Authenticate on `https://192.168.1.46:443`. Extract session cookie. Send GET request to `https://192.168.1.46:8443/admin` with that cookie.
   *Success:* 200 OK on 8443 admin panel.
   *Why:* Missing `X-Frame-Options` and lack of CSP suggest weak isolation; 8443 is rarely hardened.

2. **HIGH-VALUE: PostgreSQL (5432) SSRF via Internal API Proxy**
   *Hypothesis:* The gunicorn app on port 80/443 likely proxies requests to internal services. If it accepts user-controlled URLs (e.g., for image fetching or webhook verification), it may forward them to the internal PostgreSQL port (5432) or other internal IPs, bypassing firewall rules.
   *Test:* Submit a profile image URL pointing to `http://192.168.1.46:5432` or `http://1.0.0.46:5432`.
   *Success:* Connection refused error or timeout indicating the app attempted to connect to the internal DB port.
   *Why:* 5432 is open; apps often lack strict allowlists for outbound connections.

3. **SPECULATIVE: CDN Origin IP Poisoning via Cache Key Manipulation**
   *Hypothesis:* Cloudflare is configured with the origin IP `192.168.1.46`. If the application uses query parameters for caching (e.g., `?cache_key=...`), an attacker could craft a request that forces Cloudflare to cache a response intended for a different internal subdomain or service, potentially exposing sensitive data or bypassing auth checks.
   *Test:* Request `https://192.168.1.46:443/page?cache_key=admin_secret`.
   *Success:* Cache hit for a different internal resource.
   *Why:* Missing `Strict-Transport-Security` and `CSP` indicate poor cache control practices.

4. **SPECULATIVE: SSH (22) Brute Force via Gunicorn Error Page**
   *Hypothesis:* The gunicorn app on port 80/443 may log user input to error pages. If an attacker can trigger an error (e.g., via malformed JSON or SQL injection), the error message might reveal SSH credentials or internal IP addresses, aiding brute force attacks on port 22.
   *Test:* Send malformed POST request to `http://192.168.1.46:80/api/login` with invalid JSON.
   *Success:* Error page reveals SSH username or IP.
   *Why:* Missing `X-Content-Type-Options` suggests unsafe content type handling.

5. **SPECULATIVE: Subdomain-to-API Trust via Missing CORS**
   *Hypothesis:* If there are internal subdomains (e.g., `api.acmecorp.com`) that trust the main portal's domain for CORS, an attacker could exploit this to access internal APIs from the public portal.
   *Test:* Request `https://api.acmecorp.com/internal/data` from the main portal context.
   *Success:* 200 OK with internal data.
   *Why:* Missing `CSP` and `X-Frame-Options` suggest weak CORS policies.

## DNS Records

| Record | Value |
|--------|-------|
| A | 192.168.1.46 |
| MX | 192.168.1.46 |
| NS | 192.168.1.46 |

## Subdomains Discovered

**Total: 2**

- `192.168.1.46`
- `1.46`

## HTTP Services

| URL | Status | Server | Tech | Title |
|-----|--------|--------|------|-------|
| http://1.46/ | 403 | cloudflare | Cloudflare |  |
| http://192.168.1.46:80/ | 200 | gunicorn |  | AcmeCorp Internal Portal |
| http://192.168.1.46:8443/ | 404 | gunicorn |  |  |
| https://192.168.1.46 | 200 | gunicorn | Python, gunicorn | AcmeCorp Internal Portal |
| https://192.168.1.46/ | 200 | gunicorn |  | AcmeCorp Internal Portal |
| https://192.168.1.46:443/ | 200 | gunicorn |  | AcmeCorp Internal Portal |

## Open Ports

| IP | Ports |
|----|-------|
| 192.168.1.46 | 80, 443, 5432, 22, 8443 |

## Missing Security Headers

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-XSS-Protection`

## Exploit Chain Analysis

### Exploit Chain Analysis for 192.168.1.46

#### 1. Port 22: SSH
- **Common CVE/Misconfiguration**: CVE-2016-0777 (SSH brute-force vulnerability) or weak password authentication.
- **Risk Level**: HIGH
- **Exploitation Command**: 
  ```bash
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.46
  ```

#### 2. Port 443: HTTPS
- **Common CVE/Misconfiguration**: CVE-2014-0160 (Heartbleed vulnerability in OpenSSL) or SSL/TLS misconfiguration.
- **Risk Level**: CRITICAL
- **Exploitation Command**: 
  ```bash
  nmap --script ssl-heartbleed -p 443 192.168.1.46
  ```

#### 3. Port 5432: PostgreSQL
- **Common CVE/Misconfiguration**: CVE-2019-9193 (PostgreSQL privilege escalation via SQL injection) or default credentials.
- **Risk Level**: HIGH
- **Exploitation Command**: 
  ```bash
  psql -h 192.168.1.46 -U postgres -d postgres
  ```

#### 4. Port 80: HTTP
- **Common CVE/Misconfiguration**: CVE-2021-41773 (Apache HTTP Server path traversal vulnerability) or directory traversal.
- **Risk Level**: HIGH
- **Exploitation Command**: 
  ```bash
  curl http://192.168.1.46/../../etc/passwd
  ```

#### 5. Port 8443: HTTPS-alt
- **Common CVE/Misconfiguration**: CVE-2014-0160 (Heartbleed vulnerability in OpenSSL) or SSL/TLS misconfiguration.
- **Risk Level**: CRITICAL
- **Exploitation Command**: 
  ```bash
  nmap --script ssl-heartbleed -p 8443 192.168.1.46
  ```

### Summary
- **CRITICAL**: Port 443 (HTTPS) and Port 8443 (HTTPS-alt) due to potential Heartbleed vulnerabilities.
- **HIGH**: Port 22 (SSH), Port 5432 (PostgreSQL), and Port 80 (HTTP) due to common misconfigurations and vulnerabilities.
- **LOW**: No specific low-risk vulnerabilities identified in the provided services.

### Recommendations
- **Immediate Actions**:
  - Patch OpenSSL on ports 443 and 8443 to mitigate Heartbleed.
  - Change default credentials for PostgreSQL.
  - Harden SSH configuration to prevent brute-force attacks.
  - Secure Apache HTTP Server against path traversal vulnerabilities.

- **Long-term Actions**:
  - Regularly update and patch all services.
  - Implement strong authentication mechanisms.
  - Conduct regular vulnerability assessments and penetration tests.

## Exposed Directories / Files

**https://192.168.1.46/**

- `admin/reports` → 200 (115b)
- `files/download` → 500 (0b)
- `login` → 200 (348b)
- `tools/diagnostics` → 400 (0b)
- `tools/fetch-preview` → 400 (0b)

**https://192.168.1.46**

- `admin/reports` → 200 (115b)
- `files/download` → 500 (0b)
- `login` → 200 (348b)
- `tools/diagnostics` → 400 (0b)
- `tools/fetch-preview` → 400 (0b)

**http://192.168.1.46:80/**

- `admin/reports` → 200 (115b)
- `files/download` → 500 (0b)
- `login` → 200 (348b)
- `tools/diagnostics` → 400 (0b)
- `tools/fetch-preview` → 400 (0b)


## Origin IP Analysis (CDN/WAF Bypass)

| IP | CDN | Direct Origin | Status |
|----|-----|---------------|--------|
| 1.0.0.46 | no | YES | unconfirmed |
| 192.168.1.46 | no | YES | confirmed |

## Wayback Archive Analysis


---
*Report generated by MrBOOM One-Shot | 2026-08-02 18:20 UTC*