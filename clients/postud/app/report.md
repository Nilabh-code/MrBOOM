# Infrastructure Report: app.postud.io
**Generated:** 2026-08-03 08:00 UTC
**Tool:** MrBOOM One-Shot
**Model:** VLLM//home/nil/models/MXFP4/Qwopus3.6-35B-A3B-Coder-MXFP4_MOE_Q8_0-Imatrix.gguf

## Executive Summary

- **Target:** app.postud.io
- **Subdomains Found:** 5
- **Live HTTP Services:** 6
- **Open Ports:** 2
- **S3 Buckets Discovered:** 0
- **API Endpoints Found:** 0
- **Third-Party Integrations:** 0
- **Origin IPs (CF Bypass):** 3
- **WAF Detected:** None
- **Security Headers Missing:** 5
- **Org:** 
- **Wayback URLs:** 0
- **New Subdomains (brute):** 0
- **Directories Found:** 0
- **Takeover Candidates:** 0
- **CORS Issues:** 0
- **Open Redirects:** 0
- **XSS Candidates:** 0
- **App-Level Vulns (cmd-inj/SSRF/traversal/SQLi):** 0
- **Exposed Endpoints:** 0
- **Origin IPs (CDN Bypass):** 9
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
| MEDIUM | 5 |
| LOW | 28 |

### Detailed Findings & Remediation

| # | Severity | Finding | Asset | CWE |
|---|----------|---------|-------|-----|
| 1 | MEDIUM | Missing Content-Security-Policy | https://13.233.60.142/login/ | CWE-693 |
| 2 | MEDIUM | Cookie hardening: AWSALB | https://13.126.75.174/login/ | CWE-614 |
| 3 | MEDIUM | Missing Content-Security-Policy | https://13.126.75.174/login/ | CWE-693 |
| 4 | MEDIUM | Missing Content-Security-Policy | https://13.127.18.72/ | CWE-693 |
| 5 | MEDIUM | Missing Content-Security-Policy | https://13.127.18.72 | CWE-693 |
| 6 | LOW | No clickjacking protection | https://13.233.60.142/login/ | CWE-1021 |
| 7 | LOW | Missing Referrer-Policy | https://13.233.60.142/login/ | CWE-200 |
| 8 | LOW | Missing HSTS | https://13.233.60.142/login/ | CWE-319 |
| 9 | LOW | No clickjacking protection | https://13.126.75.174/login/ | CWE-1021 |
| 10 | LOW | Missing Referrer-Policy | https://13.126.75.174/login/ | CWE-200 |
| 11 | LOW | Missing HSTS | https://13.126.75.174/login/ | CWE-319 |
| 12 | LOW | No clickjacking protection | https://13.127.18.72/ | CWE-1021 |
| 13 | LOW | Missing Referrer-Policy | https://13.127.18.72/ | CWE-200 |
| 14 | LOW | Missing HSTS | https://13.127.18.72/ | CWE-319 |
| 15 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 16 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 17 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 18 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 19 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 20 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 21 | LOW | Third-party resource loaded | https://13.127.18.72/ | CWE-829 |
| 22 | LOW | Scripts loaded without SRI | https://13.127.18.72/ | CWE-353 |
| 23 | LOW | No clickjacking protection | https://13.127.18.72 | CWE-1021 |
| 24 | LOW | Missing Referrer-Policy | https://13.127.18.72 | CWE-200 |
| 25 | LOW | Missing HSTS | https://13.127.18.72 | CWE-319 |
| 26 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 27 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 28 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 29 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 30 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 31 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 32 | LOW | Third-party resource loaded | https://13.127.18.72 | CWE-829 |
| 33 | LOW | Scripts loaded without SRI | https://13.127.18.72 | CWE-353 |

#### Remediation Actions

| # | Finding | Recommended Fix | Retest |
|---|---------|-----------------|--------|
| 1 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 2 | Cookie hardening: AWSALB | Set AWSALB with Secure; HttpOnly; SameSite=Lax (or Strict). | — |
| 3 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 4 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 5 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 6 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 7 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 8 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 9 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 10 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 11 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 12 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 13 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 14 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 15 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 16 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 17 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 18 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 19 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 20 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 21 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 22 | Scripts loaded without SRI | Add integrity+SRI to all third-party scripts. | — |
| 23 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 24 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 25 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 26 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 27 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 28 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 29 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 30 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 31 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 32 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 33 | Scripts loaded without SRI | Add integrity+SRI to all third-party scripts. | — |

#### Evidence Archive

| # | Finding | Evidence |
|---|---------|----------|
| 1 | Missing Content-Security-Policy | `No CSP header returned` |
| 2 | Cookie hardening: AWSALB | `AWSALB=j1+MZseUExxJiECeJqo2ifkocK5iTPKwJM7pq8IN3wi6M4B5tMrXkalHI1QXOQuZ+/ZhJGPhxa4eNEwl9ooKOSdxj2Vje` |
| 3 | Missing Content-Security-Policy | `No CSP header returned` |
| 4 | Missing Content-Security-Policy | `No CSP header returned` |
| 5 | Missing Content-Security-Policy | `No CSP header returned` |
| 6 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 7 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 8 | Missing HSTS | `No Strict-Transport-Security header` |
| 9 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 10 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 11 | Missing HSTS | `No Strict-Transport-Security header` |
| 12 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 13 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 14 | Missing HSTS | `No Strict-Transport-Security header` |
| 15 | Third-party resource loaded | `https://assets.calendly.com/assets/external/widget.css` |
| 16 | Third-party resource loaded | `https://assets.calendly.com/assets/external/widget.js` |
| 17 | Third-party resource loaded | `https://cdn.tailwindcss.com` |
| 18 | Third-party resource loaded | `https://dev.postud.io/images/auth/logo-lg-left.svg` |
| 19 | Third-party resource loaded | `https://dev.postud.io/images/common/sidebar-logo.svg` |
| 20 | Third-party resource loaded | `https://fonts.googleapis.com/css2` |
| 21 | Third-party resource loaded | `https://www.postud.io/` |
| 22 | Scripts loaded without SRI | `2/2 external scripts lack integrity= (e.g. https://cdn.tailwindcss.com)` |
| 23 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 24 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 25 | Missing HSTS | `No Strict-Transport-Security header` |
| 26 | Third-party resource loaded | `https://assets.calendly.com/assets/external/widget.css` |
| 27 | Third-party resource loaded | `https://assets.calendly.com/assets/external/widget.js` |
| 28 | Third-party resource loaded | `https://cdn.tailwindcss.com` |
| 29 | Third-party resource loaded | `https://dev.postud.io/images/auth/logo-lg-left.svg` |
| 30 | Third-party resource loaded | `https://dev.postud.io/images/common/sidebar-logo.svg` |
| 31 | Third-party resource loaded | `https://fonts.googleapis.com/css2` |
| 32 | Third-party resource loaded | `https://www.postud.io/` |
| 33 | Scripts loaded without SRI | `2/2 external scripts lack integrity= (e.g. https://cdn.tailwindcss.com)` |

## Scope & Authorization

- **Authorized target(s):** app.postud.io
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
| A | 13.234.181.18, 3.111.6.3, 13.233.60.142 |
| MX | 13.234.181.18, 3.111.6.3, 13.233.60.142 |
| NS | 13.234.181.18, 3.111.6.3, 13.233.60.142 |

## Subdomains Discovered

**Total: 5**

- `app.postud.io`
- `dev.postud.io`
- `postud.io`
- `support.postud.io`
- `www.postud.io`

## HTTP Services

| URL | Status | Server | Tech | Title |
|-----|--------|--------|------|-------|
| http://app.postud.io:80/ | 200 |  |  |  |
| http://postud.io/ | 301 | AmazonS3 | AWS S3 |  |
| http://support.postud.io/ | 404 | cloudflare | Cloudflare |  |
| https://app.postud.io | 307 |  |  |  |
| https://app.postud.io/ | 200 |  |  |  |
| https://app.postud.io:443/ | 200 |  |  |  |
| https://dev.postud.io | 307 |  | Amazon ALB, Amazon Web Service |  |
| https://dev.postud.io/ | 200 |  | Has XCTO |  |
| https://postud.io | 301 | AmazonS3 | Amazon CloudFront, Amazon S3,  |  |
| https://support.postud.io | 404 | cloudflare | Amazon S3, Amazon Web Services | - |
| https://www.postud.io | 200 | nginx/1.29.8 | Drift, nginx, Tawk.to, Tailwin | Postudio — AI-Powered Post-Production OS |
| https://www.postud.io/ | 200 | nginx/1.29.8 | Tawk.to, nginx, Drift | Postudio — AI-Powered Post-Production OS |

## Open Ports

| IP | Ports |
|----|-------|
| app.postud.io | 443, 80 |

## Missing Security Headers

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-XSS-Protection`

## Origin IPs (Cloudflare Bypass)

| Subdomain | IP |
|-----------|-----|
| app.postud.io | 13.233.60.142 |
| v1.app.postud.io | 35.154.156.6 |
| v2.app.postud.io | 65.1.252.165 |

## Origin IP Analysis (CDN/WAF Bypass)

| IP | CDN | Direct Origin | Status |
|----|-----|---------------|--------|
| 13.126.75.174 | no | YES | confirmed |
| 13.127.18.72 | no | YES | confirmed |
| 13.203.115.171 | no | YES | confirmed |
| 13.206.10.220 | no | YES | confirmed |
| 13.206.224.72 | no | YES | confirmed |
| 13.233.60.142 | no | YES | confirmed |
| 13.234.181.18 | no | YES | confirmed |
| 13.234.97.23 | no | YES | confirmed |
| 162.159.140.147 | cloudflare | no | unconfirmed |
| 172.66.0.145 | cloudflare | no | unconfirmed |
| 3.111.6.3 | no | YES | confirmed |
| 99.86.18.104 | no | YES | unconfirmed |
| 99.86.18.13 | no | YES | unconfirmed |
| 99.86.18.39 | no | YES | unconfirmed |
| 99.86.18.79 | no | YES | unconfirmed |

## Technology Stack

- **https://dev.postud.io/**: Has XCTO
- **https://www.postud.io**: Drift, Tawk.to, nginx
- **https://www.postud.io/**: Drift, Tawk.to, nginx

---
*Report generated by MrBOOM One-Shot | 2026-08-03 08:00 UTC*