# AcmeCorp Lab — SSH Bypass Evidence
**Date:** 2026-08-03 · **Target:** Pi lab (`backup-ssh`, port 2222) — authorized engagement

## Finding — Weak/Default SSH credentials on the backup service (HIGH)

**Summary:** The `backup-ssh` service (port 2222) accepts the documented default credentials
`backup:backup123`. The resulting shell exposes a credential dump in the backup script.

**Reproduction:**
```
$ sshpass -p backup123 ssh -p 2222 -o StrictHostKeyChecking=no backup@<lab-host> 'whoami; id'
LOGIN_OK
backup
uid=1000(backup) gid=1000(backup) groups=1000(backup)
```

**Post-exploitation — credential leak (`/home/backup/scripts/backup.sh`):**
```bash
#!/bin/bash
# Nightly DB backup to S3. Key kept local for cron.
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://admin:admin@db:5432/acmecorp
BUCKET=acmecorp-prod-backups
echo "backing up ${DATABASE_URL} to s3://${BUCKET}/"
```

**Impact:**
- A low-privilege backup account authenticates with a well-known default password (no MFA, no
  rate-limit / fail2ban observed on this service).
- That account can read the backup job, which contains **hardcoded AWS Access Key/Secret** and the
  **plaintext database credential** (`admin:admin@db`), enabling pivot to the postgres database
  (`acmecorp`) and any S3 bucket configured with those keys.

## Positive control — host SSH is correctly hardened
A password-auth attempt against the Pi's primary SSH (port 22) is rejected (`Permission denied,
please try again`), i.e. host SSH is key-only. The weakness is specific to the exposed `backup-ssh`
service and its default credentials + secret-in-script.