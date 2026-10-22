"""
link_extract.py
Pulls URLs out of an email body and runs offline, no-internet-needed
heuristics on each one. Never visits/opens any link -- only inspects the
URL text itself.

Standalone test:
    python3 link_extract.py
"""

import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}

# A tiny reference list of commonly-impersonated brand domains, purely for
# the "does this look like a lookalike" offline check below. Not a
# blocklist -- just a comparison set.
COMMONLY_IMPERSONATED = {
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "office.com", "bankofamerica.com", "chase.com",
}


def extract_urls(body_text: str) -> list[str]:
    return URL_PATTERN.findall(body_text or "")


def _looks_like_ip(hostname: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname or ""))


def _levenshtein(a: str, b: str) -> int:
    """Simple edit distance, used to catch near-miss lookalike domains."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _closest_impersonated_domain(hostname: str) -> tuple[str, int] | None:
    best = None
    for known in COMMONLY_IMPERSONATED:
        dist = _levenshtein(hostname, known)
        if dist <= 2 and hostname != known:  # close but not exact = suspicious
            if best is None or dist < best[1]:
                best = (known, dist)
    return best


def analyze_url(url: str) -> dict:
    """
    Offline-only analysis. Returns a dict of flags plus a 0.0-1.0 suspicion
    score. Never makes a network request -- safe to run with no internet.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    flags = []
    score = 0.0

    if hostname in KNOWN_SHORTENERS:
        flags.append("uses a link-shortening service (hides real destination)")
        score += 0.45

    if _looks_like_ip(hostname):
        flags.append("destination is a raw IP address, not a domain name (high-risk evasion technique)")
        score += 0.60

    lookalike = _closest_impersonated_domain(hostname)
    if lookalike:
        flags.append(f"domain closely resembles '{lookalike[0]}' (possible lookalike)")
        score += 0.4

    if parsed.scheme == "http":
        flags.append("uses unencrypted http:// instead of https://")
        score += 0.1

    if len(url) > 120:
        flags.append("unusually long URL (can hide the real destination)")
        score += 0.1

    return {
        "url": url,
        "hostname": hostname,
        "suspicion_score": min(1.0, score),
        "flags": flags,
    }


def analyze_body_links(body_text: str) -> list[dict]:
    return [analyze_url(u) for u in extract_urls(body_text)]


def analyze_all_links(body_text: str) -> dict:
    """
    Report-shaped wrapper around analyze_body_links(), for run_pipeline.py
    and score_and_report.py to consume directly.
    Returns: {"links_found": int, "highest_risk": float, "details": [...]}
    """
    details = analyze_body_links(body_text)
    highest_risk = max((d["suspicion_score"] for d in details), default=0.0)
    return {"links_found": len(details), "highest_risk": highest_risk, "details": details}


if __name__ == "__main__":
    sample = (
        "Please verify your account at http://paypa1-secure.com/login "
        "or use this shortened link: https://bit.ly/3xample for the full policy."
    )
    for result in analyze_body_links(sample):
        print(result)
