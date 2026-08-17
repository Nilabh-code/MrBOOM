"""
STEALTH // MrBOOM stealth & OPSEC layer.
- Configurable scan profiles (stealth / default / aggressive)
- Rotating realistic User-Agent pool (no self-fingerprinting)
- Request jitter + inter-request delays
- WAF-friendly rate limits for PD tools (naabu/nuclei/httpx)

Set MRBOOM_PROFILE=stealth|default|aggressive (default: default).
Set MRBOOM_JITTER=0 to disable jitter entirely.
"""
import os
import random
import time

# ── Scan profiles ──────────────────────────────────────────────────────
# Each profile tunes every noisy primitive the harness owns.
PROFILES = {
    "stealth": {
        "naabu_rate": 50,
        "nuclei_rl": 10,
        "httpx_threads": 5,
        "katana_threads": 5,
        "dirbust_workers": 5,
        "subdomain_workers": 15,
        "port_workers": 15,
        "jitter_ms": (900, 2800),
        "concurrency_delay_ms": 120,
        "max_urls_phase": 3,
    },
    "default": {
        "naabu_rate": 150,
        "nuclei_rl": 60,
        "httpx_threads": 10,
        "katana_threads": 10,
        "dirbust_workers": 20,
        "subdomain_workers": 40,
        "port_workers": 25,
        "jitter_ms": (200, 800),
        "concurrency_delay_ms": 25,
        "max_urls_phase": 5,
    },
    "aggressive": {
        "naabu_rate": 800,
        "nuclei_rl": 300,
        "httpx_threads": 30,
        "katana_threads": 30,
        "dirbust_workers": 60,
        "subdomain_workers": 100,
        "port_workers": 60,
        "jitter_ms": (0, 120),
        "concurrency_delay_ms": 0,
        "max_urls_phase": 10,
    },
}

VALID_PROFILES = tuple(PROFILES.keys())

# ── Realistic User-Agent pool ─────────────────────────────────────────
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]
# NOTE: curl/wget UAs intentionally REMOVED — they trip honeypot UA traps
# and WAF fingerprinting on hardened targets. All traffic looks like a
# real browser session.

_ACTIVE_PROFILE = "default"


def set_profile(name):
    """Switch active scan profile. Unknown names fall back to default."""
    global _ACTIVE_PROFILE
    _ACTIVE_PROFILE = name if name in VALID_PROFILES else "default"


def get_profile():
    return _ACTIVE_PROFILE


def profile():
    """Return the active profile dict (copy)."""
    return dict(PROFILES.get(_ACTIVE_PROFILE, PROFILES["default"]))


def _env_profile():
    return os.environ.get("MRBOOM_PROFILE", "default")


# ── Helpers ────────────────────────────────────────────────────────────

def ua():
    """Return a randomized realistic User-Agent string."""
    return random.choice(UA_POOL)


def jitter_enabled():
    try:
        return os.environ.get("MRBOOM_JITTER", "1") != "0"
    except Exception:
        return True


def sleep():
    """Sleep a random amount per active profile's jitter window."""
    if not jitter_enabled():
        return
    p = profile()
    lo, hi = p["jitter_ms"]
    if hi <= 0:
        return
    time.sleep(random.uniform(lo, hi) / 1000.0)


def small_sleep():
    """Tiny in-loop delay for concurrent worker pools."""
    p = profile()
    if p["concurrency_delay_ms"] > 0:
        time.sleep(p["concurrency_delay_ms"] / 1000.0)


def headers(extra=None):
    """Build a stealthy header set with a rotated UA + browser-ish headers."""
    h = {
        "User-Agent": ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
    }
    if extra:
        h.update(extra)
    return h


def http_headers(extra=None):
    """Alias kept for compatibility with existing call sites."""
    return headers(extra)


def pd_flags(kind):
    """Return WAF-friendly flags for a PD tool based on the active profile."""
    p = profile()
    if kind == "naabu":
        return ["-rate", str(p["naabu_rate"])]
    if kind == "nuclei":
        return ["-rl", str(p["nuclei_rl"])]
    if kind == "httpx":
        return ["-threads", str(p["httpx_threads"])]
    if kind == "katana":
        return ["-jc"]
    return []


def max_urls_phase():
    """How many URLs to chew on per phase (lower in stealth)."""
    return profile()["max_urls_phase"]


def workers(kind):
    """Concurrency for internal thread pools by phase kind."""
    p = profile()
    return {
        "dirbust": p["dirbust_workers"],
        "subdomain": p["subdomain_workers"],
        "port": p["port_workers"],
    }.get(kind, 10)


def init():
    """Call once at startup — read profile from env."""
    set_profile(_env_profile())


init()
