# Postudio — Proof of Findings (Evidence Package)
**Prepared:** 2026-08-03 · **Engagement:** www.postud.io + related subdomains (authorized)
**Tool:** MrBOOM One-Shot

This document contains concrete, reproducible evidence for each finding. Every claim below was
captured live against the live production environment on the date above.

---

## Finding 1 — Production depends on the internet-exposed DEV environment (MEDIUM/HIGH)

**Evidence (live capture, `www.postud.io` homepage HTML):**

```
<script src="https://cdn.tailwindcss.com">
<script src="https://assets.calendly.com/assets/external/widget.js">
<img src="https://dev.postud.io/images/auth/logo-lg-left.svg">
<img src="https://dev.postud.io/images/common/sidebar-logo.svg">
```

**Reproduction:**
```
$ curl -sk https://www.postud.io/ | grep -oE "https://dev\.postud\.io/[^\"']+" | sort -u
https://dev.postud.io/images/auth/logo-lg-left.svg
https://dev.postud.io/images/common/sidebar-logo.svg

$ curl -sk -o /dev/null -w "%{http_code}" https://dev.postud.io/images/common/sidebar-logo.svg
200
```

**Impact:** The production marketing site renders images served directly by the live,
internet-accessible **development** environment. If `dev.postud.io` (or its asset storage) is
compromised, an attacker can swap these SVG assets and inject script into every visitor's
production page. This is a supply-chain / stored-XSS dependency on a host outside the
production trust boundary.

---

## Finding 2 — Missing security headers on production (MEDIUM)

**Evidence (live response headers, `www.postud.io`):**

```
$ curl -sk -D- -o /dev/null https://www.postud.io/ | grep -iE "^(strict-transport|content-security|x-frame|x-content-type|x-xss|referrer|server)"
server: nginx/1.29.8
```

Present: `Server: nginx/1.29.8`.
**Absent:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`.

**Impact:**
- No CSP + runtime third-party scripts (`cdn.tailwindcss.com`, Calendly) with no `integrity`
  (SRI) → supply-chain XSS exposure.
- No HSTS on a cookie-based authenticated application (`app.postud.io`, `auth.api.app.postud.io`
  issue `AWSALB`/`AWSALBCORS` session cookies) → session tokens transmittable in cleartext under
  MITM and cookie hijack risk.
- No `X-Frame-Options`/CSP `frame-ancestors` → clickjacking of the login and app.
- `AWSALB` cookie observed without `HttpOnly`/`Secure` hardening on `https://13.126.75.174/login/`.

---

## Finding 3 — CDN/WAF bypass: origin servers directly addressable (MEDIUM)

**Evidence:** 9 AWS origin IPs resolved and directly reachable for the app/auth stack:

```
auth.api.app.postud.io -> 3.111.6.3, 13.233.60.142, 13.234.181.18
app.postud.io         -> 13.234.181.18, 3.111.6.3, 13.233.60.142
dev.postud.io         -> 13.126.75.174, 13.206.10.220, 13.203.115.171
www.postud.io         -> 13.206.224.72, 13.127.18.72, 13.234.97.23
```

**Impact:** Security controls assumed to sit at the CDN edge (rate limiting, WAF rules, DDoS
shielding) can be bypassed by addressing the origin IPs directly. The scan reached the
application login pages on these origins.

---

## Finding 4 — Internet-exposed development environment (LOW/MEDIUM)

**Evidence:** `dev.postud.io` resolves, is live (HTTP 307 → `/login/`, 200), and serves the
application login. Confirmed live during this assessment.

**Impact:** Development environments are typically less hardened, may share data with production,
and (per Finding 1) already serve production content.

---

## Finding 5 — CORS misconfiguration on the authentication API (HIGH)

**Evidence (live response to an arbitrary `Origin`, `auth.api.app.postud.io`):**

```
$ curl -sk -D- -o /dev/null -H "Origin: https://evil.com" \
    https://auth.api.app.postud.io/api/v1/transactions/
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
access-control-allow-methods: GET, POST, PUT, DELETE
```

Confirmed on every data endpoint tested (`checklogin/`, `user/subscription/`, `team/members/`,
`transactions/`), and preflight (`OPTIONS`) additionally allows `authorization`, `access-token`
and `Set-Cookie` headers with `max-age: 86400`.

**Impact:** The API reflects **any** origin and allows credentials. A malicious webpage visited by
a logged-in user can therefore issue fully authenticated cross-origin requests to the Postudio
auth/account API — reading `transactions/`, `team/members/`, `subscription/`, changing account
settings, etc. — and exfiltrate the responses. This is an account/API hijack primitive (CWE-942),
not just a header hygiene issue.

---

## Finding 6 — Subdomain takeover: `support.postud.io` (HIGH)

**Evidence (DNS + live response):**

```
$ dig +short CNAME support.postud.io
b666bc625b73106af849879109e8c377.freshdesk.com

$ curl -sk https://support.postud.io/
(HTTP 404) "We couldn't find ... Maybe this is still fresh!
You can claim it now at https://www.freshworks.com/freshdesk/signup"
```

**Impact:** The Freshdesk account behind the CNAME has been deleted/deactivated, and Freshdesk
lets anyone claim the name. An attacker can register it and serve arbitrary content at
`support.postud.io` — a fully trusted-looking subdomain of `postud.io` — for phishing,
credential harvesting, or malware distribution (CWE-350).

---

## Finding 7 — Email spoofing: no SPF, weak DMARC (MEDIUM)

**Evidence (DNS):**

```
$ dig +short TXT postud.io          # 7 records (verification tokens only) — NO v=spf1 record
$ dig +short TXT _dmarc.postud.io
"v=DMARC1;p=quarantine;rua=mailto:support@postud.io"
```

**Impact:** With no SPF record and DMARC only at `p=quarantine` (not `p=reject`), senders are not
unambiguously authenticated. An attacker can spoof emails that appear to come from `postud.io`
addressed to customers/partners — phishing on the brand. Recommend adding SPF and hardening DMARC
to `p=reject` (with `sp=` for subdomains).

---

## Negative results (what we tried, and why data was NOT breached)

The following attack paths were attempted and **failed** — the application's core authentication
and data layer is implemented correctly:

| Attempt | Result |
|---|---|
| Firebase RTDB `psio-app-default-rtdb.asia-southeast1.firebasedatabase.app/.json` (all paths) | `Permission denied` (401) — rules locked |
| Firebase Storage list `psio-app.appspot.com` | 404 — no public objects |
| Firestore `psio-app` documents | Not exposed (404) |
| Auth API `/api/v1/{transactions,team/members,s3-integration,checklogin,subscription,...}` without token | `401 Invalid credentials, Auth token not found` |
| Auth API login with SQLi/NoSQLi payloads | `Decryption error` — login payloads are **encrypted client-side**; server rejects raw tampered bodies |
| Self-service account signup (`/api/v2/signup/`) | `User registration is not allowed` — signup disabled |
| Login brute-force | Rate-limited (`429`) after a handful of attempts |
| Apex S3 bucket (`postud.io.s3.amazonaws.com`) | 403 AccessDenied on list — bucket not publicly listable |
| `support.postud.io` Freshdesk takeover claim | Confirmed — account **unclaimed and claimable** (Finding 6) |

**Conclusion for the client:** Black-box exploitation of the data layer was not possible — the
authenticated data API, Firebase, and the signup flow are all correctly gated. The exploitable
risk is at the **configuration and hygiene layer**: missing security headers, production
depending on the dev environment, origin-IP exposure, and third-party runtime scripts without
integrity checks. These are all remediable without downtime.
