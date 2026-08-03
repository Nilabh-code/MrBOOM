# Infrastructure Report: www.postud.io
**Generated:** 2026-08-02 18:55 UTC
**Tool:** MrBOOM One-Shot
**Model:** VLLM//home/nil/models/MXFP4/Qwopus3.6-35B-A3B-Coder-MXFP4_MOE_Q8_0-Imatrix.gguf

## Executive Summary

- **Target:** www.postud.io
- **Subdomains Found:** 5
- **Live HTTP Services:** 6
- **Open Ports:** 2
- **S3 Buckets Discovered:** 0
- **API Endpoints Found:** 0
- **Third-Party Integrations:** 0
- **Origin IPs (CF Bypass):** 0
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

## Attack Surface (from data)
- **Primary Domain**: `www.postud.io` (HTTP/HTTPS)
- **Subdomains**: `app.postud.io` (HTTPS), `dev.postud.io` (HTTPS), `support.postud.io` (HTTPS)
- **Infrastructure**: AWS S3 (redirects for `postud.io`), Cloudflare (CDN for `support.postud.io`), Nginx (origin for `www.postud.io`)
- **Ports**: 80, 443
- **Origin IPs**: 9 AWS IPs identified (potential for CDN bypass testing)

## Weakest Entry Points (only what the data supports, or "none found")
- **Development Environment**: `dev.postud.io` is live and accessible. Development environments often contain debug tools, exposed APIs, or less hardened configurations than production.
- **Support Subdomain**: `support.postud.io` returns a 404. While not directly exploitable, it indicates an active subdomain that may have been misconfigured or abandoned, potentially leaking information about the infrastructure.
- **Missing Security Headers**: The main site (`www.postud.io`) lacks critical headers (CSP, HSTS, X-Frame-Options), increasing susceptibility to XSS and clickjacking.

## Evidence & Findings (list concrete items with the actual data)
1. **Missing Security Headers (MEDIUM)**:
   - **Evidence**: `www.postud.io` returns 200 OK but lacks `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, and `X-XSS-Protection`.
   - **Impact**: Enables XSS attacks (no CSP), clickjacking (no X-Frame-Options), and MIME-type sniffing (no X-Content-Type-Options).

2. **Development Environment Exposure (MEDIUM)**:
   - **Evidence**: `dev.postud.io` is live, returns 200 OK, and is served by Nginx.
   - **Impact**: Development environments may expose internal APIs, debug endpoints, or sensitive configuration files not present in production.

3. **CDN Bypass Potential (LOW)**:
   - **Evidence**: 9 origin IPs identified (e.g., `13.126.75.174`).
   - **Impact**: If the CDN is misconfigured, direct access to origin IPs could bypass security controls or expose internal services.

4. **Subdomain Misconfiguration (LOW)**:
   - **Evidence**: `support.postud.io` returns 404.
   - **Impact**: Indicates an active but non-functional subdomain, potentially exposing infrastructure details or indicating incomplete security hardening.

5. **S3 Redirects (LOW)**:
   - **Evidence**: `postud.io` redirects to AmazonS3.
   - **Impact**: If S3 bucket permissions are misconfigured, it could lead to data exposure.

## Risk Rating: MEDIUM
The primary risk stems from the lack of security headers on the main domain and the exposure of a development environment. These are actionable findings that require immediate remediation.

## Findings Overview & Scorecard

| Severity | Count |
|----------|-------|
| MEDIUM | 5 |
| LOW | 28 |

### Detailed Findings & Remediation

| # | Severity | Finding | Asset | CWE |
|---|----------|---------|-------|-----|
| 1 | MEDIUM | Missing Content-Security-Policy | https://13.234.97.23/ | CWE-693 |
| 2 | MEDIUM | Missing Content-Security-Policy | https://13.234.181.18/login/ | CWE-693 |
| 3 | MEDIUM | Cookie hardening: AWSALB | https://13.126.75.174/login/ | CWE-614 |
| 4 | MEDIUM | Missing Content-Security-Policy | https://13.126.75.174/login/ | CWE-693 |
| 5 | MEDIUM | Missing Content-Security-Policy | https://13.234.97.23 | CWE-693 |
| 6 | LOW | No clickjacking protection | https://13.234.97.23/ | CWE-1021 |
| 7 | LOW | Missing Referrer-Policy | https://13.234.97.23/ | CWE-200 |
| 8 | LOW | Missing HSTS | https://13.234.97.23/ | CWE-319 |
| 9 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 10 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 11 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 12 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 13 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 14 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 15 | LOW | Third-party resource loaded | https://13.234.97.23/ | CWE-829 |
| 16 | LOW | Scripts loaded without SRI | https://13.234.97.23/ | CWE-353 |
| 17 | LOW | No clickjacking protection | https://13.234.181.18/login/ | CWE-1021 |
| 18 | LOW | Missing Referrer-Policy | https://13.234.181.18/login/ | CWE-200 |
| 19 | LOW | Missing HSTS | https://13.234.181.18/login/ | CWE-319 |
| 20 | LOW | No clickjacking protection | https://13.126.75.174/login/ | CWE-1021 |
| 21 | LOW | Missing Referrer-Policy | https://13.126.75.174/login/ | CWE-200 |
| 22 | LOW | Missing HSTS | https://13.126.75.174/login/ | CWE-319 |
| 23 | LOW | No clickjacking protection | https://13.234.97.23 | CWE-1021 |
| 24 | LOW | Missing Referrer-Policy | https://13.234.97.23 | CWE-200 |
| 25 | LOW | Missing HSTS | https://13.234.97.23 | CWE-319 |
| 26 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 27 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 28 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 29 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 30 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 31 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 32 | LOW | Third-party resource loaded | https://13.234.97.23 | CWE-829 |
| 33 | LOW | Scripts loaded without SRI | https://13.234.97.23 | CWE-353 |

#### Remediation Actions

| # | Finding | Recommended Fix | Retest |
|---|---------|-----------------|--------|
| 1 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 2 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 3 | Cookie hardening: AWSALB | Set AWSALB with Secure; HttpOnly; SameSite=Lax (or Strict). | — |
| 4 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 5 | Missing Content-Security-Policy | Set a Content-Security-Policy restricting script-src and object-src. | — |
| 6 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 7 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 8 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 9 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 10 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 11 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 12 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 13 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 14 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 15 | Third-party resource loaded | Inventory external dependencies; pin + integrity-check and review their supply chain. | — |
| 16 | Scripts loaded without SRI | Add integrity+SRI to all third-party scripts. | — |
| 17 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 18 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 19 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
| 20 | No clickjacking protection | Set X-Frame-Options: DENY or CSP frame-ancestors 'none'. | — |
| 21 | Missing Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin. | — |
| 22 | Missing HSTS | Set Strict-Transport-Security with a long max-age. | — |
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
| 2 | Missing Content-Security-Policy | `No CSP header returned` |
| 3 | Cookie hardening: AWSALB | `AWSALB=7P9QiEHl4+Toh5leb2g685L2d2qK1SQXfkn/vUxbj3g8PlKT3VicSvBXpFqdqcmnyKi+L0Deb7FYrz5rX+SEwEpj6R4uc` |
| 4 | Missing Content-Security-Policy | `No CSP header returned` |
| 5 | Missing Content-Security-Policy | `No CSP header returned` |
| 6 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 7 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 8 | Missing HSTS | `No Strict-Transport-Security header` |
| 9 | Third-party resource loaded | `https://assets.calendly.com/assets/external/widget.css` |
| 10 | Third-party resource loaded | `https://assets.calendly.com/assets/external/widget.js` |
| 11 | Third-party resource loaded | `https://cdn.tailwindcss.com` |
| 12 | Third-party resource loaded | `https://dev.postud.io/images/auth/logo-lg-left.svg` |
| 13 | Third-party resource loaded | `https://dev.postud.io/images/common/sidebar-logo.svg` |
| 14 | Third-party resource loaded | `https://fonts.googleapis.com/css2` |
| 15 | Third-party resource loaded | `https://www.postud.io/` |
| 16 | Scripts loaded without SRI | `2/2 external scripts lack integrity= (e.g. https://cdn.tailwindcss.com)` |
| 17 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 18 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 19 | Missing HSTS | `No Strict-Transport-Security header` |
| 20 | No clickjacking protection | `Missing X-Frame-Options / frame-ancestors` |
| 21 | Missing Referrer-Policy | `No Referrer-Policy header` |
| 22 | Missing HSTS | `No Strict-Transport-Security header` |
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

- **Authorized target(s):** www.postud.io
- **Assessment type:** Authorized penetration test / security audit (external, black-box)
- **Legal note:** Findings are provided for remediation purposes only. Testing was performed with explicit authorization for the scoped targets above.

## Methodology

1. **Recon** — subdomain enumeration, live-host discovery (httpx), DNS and WHOIS review.
2. **Discovery** — port scanning, banner grabbing, TLS analysis, origin-IP (WAF bypass) hunting.
3. **Vulnerability scanning** — nuclei (non-intrusive templates), version-aware CVE correlation (cvemap).
4. **Web application checks** — client-side assessment (cookies, CSP, SRI, service workers, WebSockets, DOM-XSS), JS/API endpoint extraction, source-map review.
5. **Validation & reporting** — manual validation of critical paths, evidence capture, remediation guidance.

## AI Novel Attack Hypotheses (0-day Research)

1. **HIGH-VALUE: Dev Environment Session Confusion via Origin IP Bypass**
The `dev.postud.io` subdomain is live and accessible. If the dev environment shares the same authentication backend or session cookie domain (e.g., `.postud.io`) as the production `app.postud.io`, an attacker could exploit session fixation.
*Test:* Register a user on `dev.postud.io`, capture the session cookie, and inject it into `app.postud.io`.
*Success:* If the cookie is accepted on prod, the attacker gains access to production data using dev credentials.
*Why:* Dev environments often have weaker auth controls and share infrastructure with prod. The missing HSTS header on `www.postud.io` facilitates cookie theft via MITM, making this chain viable.

2. **HIGH-VALUE: SSRF via CDN Origin IP Bypass to Internal Metadata**
The scan confirms non-CDN origin IPs (e.g., `13.126.75.174`). If the application has any endpoint that fetches external resources (e.g., image processing, webhook verification), an attacker could bypass the CDN and request internal AWS metadata.
*Test:* Submit a request to a hypothetical image-processing endpoint with the URL `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
*Success:* If the server responds with IAM credentials, the attacker can pivot to AWS services.
*Why:* The presence of origin IPs suggests a direct connection to AWS infrastructure. Missing security headers indicate a lack of strict input validation, increasing the risk of SSRF.

3. **SPECULATIVE: IDOR via Subdomain Trust Boundary**
If `app.postud.io` and `dev.postud.io` share the same database schema but have different access controls, an attacker could exploit IDOR.
*Test:* Create a project on `dev.postud.io`, note the project ID, and attempt to access it via `app.postud.io` using the same ID.
*Success:* If the project is accessible on prod, the attacker gains access to production data.
*Why:* Subdomains often share backend logic. The lack of HSTS and missing security headers suggest a less secure configuration, increasing the risk of IDOR.

4. **SPECULATIVE: Cache Poisoning via Missing CSP**
The missing Content-Security-Policy header allows for potential cache poisoning.
*Test:* Inject a script tag into a vulnerable endpoint (e.g., a comment section) and observe if the script is executed in the browser.
*Success:* If the script is executed, the attacker can steal user data.
*Why:* The absence of CSP indicates a lack of strict content delivery policies, increasing the risk of XSS and cache poisoning.

## DNS Records

| Record | Value |
|--------|-------|
| A | 13.206.224.72, 13.234.97.23, 13.127.18.72 |
| MX | 13.127.18.72, 13.234.97.23, 13.206.224.72 |
| NS | 13.206.224.72, 13.234.97.23, 13.127.18.72 |

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
| http://postud.io/ | 301 | AmazonS3 | AWS S3 |  |
| http://support.postud.io/ | 404 | cloudflare | Cloudflare |  |
| http://www.postud.io:80/ | 200 | nginx/1.29.8 | Tawk.to, Drift, nginx | Postudio — AI-Powered Post-Production OS |
| https://app.postud.io | 307 |  |  |  |
| https://app.postud.io/ | 200 |  |  |  |
| https://dev.postud.io | 307 |  | Amazon ALB, Amazon Web Service |  |
| https://dev.postud.io/ | 200 |  | Has XCTO |  |
| https://postud.io | 301 | AmazonS3 | Amazon CloudFront, Amazon S3,  |  |
| https://support.postud.io | 404 | cloudflare | Amazon S3, Amazon Web Services | - |
| https://www.postud.io | 200 | nginx/1.29.8 | nginx, Nginx:1.29.8, Tawk.to,  | Postudio — AI-Powered Post-Production OS |
| https://www.postud.io/ | 200 | nginx/1.29.8 | Tawk.to, Drift, nginx | Postudio — AI-Powered Post-Production OS |
| https://www.postud.io:443/ | 200 | nginx/1.29.8 | Tawk.to, Drift, nginx | Postudio — AI-Powered Post-Production OS |

## Open Ports

| IP | Ports |
|----|-------|
| www.postud.io | 80, 443 |

## Missing Security Headers

- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-XSS-Protection`

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
| 54.192.142.115 | cloudfront | no | unconfirmed |
| 54.192.142.26 | cloudfront | no | unconfirmed |
| 54.192.142.30 | cloudfront | no | unconfirmed |
| 54.192.142.78 | cloudfront | no | unconfirmed |

## Technology Stack

- **http://www.postud.io:80/**: Drift, Tawk.to, nginx
- **https://dev.postud.io/**: Has XCTO
- **https://www.postud.io**: Drift, Tawk.to, nginx
- **https://www.postud.io/**: Drift, Tawk.to, nginx
- **https://www.postud.io:443/**: Drift, Tawk.to, nginx

---
*Report generated by MrBOOM One-Shot | 2026-08-02 18:55 UTC*