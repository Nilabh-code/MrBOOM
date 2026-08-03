# Infrastructure Report: 192.168.1.46
**Generated:** 2026-08-03 08:08 UTC
**Tool:** MrBOOM One-Shot
**Model:** VLLM//home/nil/models/MXFP4/Qwopus3.6-35B-A3B-Coder-MXFP4_MOE_Q8_0-Imatrix.gguf

## Executive Summary

- **Target:** 192.168.1.46
- **Subdomains Found:** 2
- **Live HTTP Services:** 2
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
- **Directories Found:** 5
- **Takeover Candidates:** 0
- **CORS Issues:** 0
- **Open Redirects:** 0
- **XSS Candidates:** 0
- **App-Level Vulns (cmd-inj/SSRF/traversal/SQLi):** 4
- **Exposed Endpoints:** 0
- **Origin IPs (CDN Bypass):** 1
- **Login/Rate-Limit Issues:** 0
- **Source-Map Endpoints:** 0
- **Wayback Secrets:** 0
- **Default Creds Accepted:** 0
- **JWT/API Auth Bypass:** 0
- **Live API Hosts:** 0

## AI Breach Assessment

AI_ERROR: HTTP Error 530: <none>

## Findings Overview & Scorecard

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 3 |

### Detailed Findings & Remediation

| # | Severity | Finding | Asset | CWE |
|---|----------|---------|-------|-----|
| 1 | CRITICAL | OS Command Injection via Host Parameter | 192.168.1.46 | CWE-78 |
| 2 | CRITICAL | SQL Injection Authentication Bypass on Login Form | 192.168.1.46 | CWE-89 |
| 3 | HIGH | Arbitrary File Read via File Parameter | 192.168.1.46 | CWE-22 |
| 4 | HIGH | Server-Side Request Forgery via Url Parameter | 192.168.1.46 | CWE-918 |
| 5 | MEDIUM | Missing Content-Security-Policy | https://192.168.1.46 | CWE-693 |
| 6 | LOW | No clickjacking protection | https://192.168.1.46 | CWE-1021 |
| 7 | LOW | Missing Referrer-Policy | https://192.168.1.46 | CWE-200 |
| 8 | LOW | Missing HSTS | https://192.168.1.46 | CWE-319 |

#### Remediation Actions

| # | Finding | Recommended Fix | Retest |
|---|---------|-----------------|--------|
| 1 | OS Command Injection via Host Parameter |  | — |
| 2 | SQL Injection Authentication Bypass on Login Form |  | — |
| 3 | Arbitrary File Read via File Parameter |  | — |
| 4 | Server-Side Request Forgery via Url Parameter |  | — |
| 5 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 6 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 7 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 8 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |

#### Evidence Archive

| # | Finding | Evidence |
|---|---------|----------|
| 1 | OS Command Injection via Host Parameter | `RCE marker 'uid=' in response` |
| 2 | SQL Injection Authentication Bypass on Login Form | `login bypassed with SQLi payload` |
| 3 | Arbitrary File Read via File Parameter | `sensitive content marker in response (/etc/passwd)` |
| 4 | Server-Side Request Forgery via Url Parameter | `internal service content marker in response` |
| 5 | Missing Content-Security-Policy | `No CSP header returned` |
| 6 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 7 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 8 | Missing HSTS | `No Strict-Transport-Security header` |

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
| http://192.168.1.46/ | 200 | gunicorn |  | AcmeCorp Internal Portal |
| https://192.168.1.46 | 200 | gunicorn | Python, gunicorn | AcmeCorp Internal Portal |

## Open Ports

| IP | Ports |
|----|-------|
| 192.168.1.46 | 8443, 22, 5432, 443, 80 |

## Missing Security Headers

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-XSS-Protection`

## Exposed Directories / Files

**http://192.168.1.46/**

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
*Report generated by MrBOOM One-Shot | 2026-08-03 08:08 UTC*