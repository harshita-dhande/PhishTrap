"""
Behavioral layer — sender reputation

Not a hardcoded blocklist. Tracks how many times we've seen a given
sender domain across pipeline runs, and gives first-seen senders a
small risk bump. This is meant to loosely mirror how real anti-phishing
platforms weigh sender history alongside content analysis.

Run standalone:
    python reputation.py
"""

import json
import os

from config import REPUTATION_FILE


def load_reputation() -> dict:
    if os.path.exists(REPUTATION_FILE):
        try:
            with open(REPUTATION_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def check_sender(sender_domain: str) -> dict:
    """
    Returns a small risk signal for this sender domain.
    First-time senders get a mild risk bump; senders seen many times
    before get progressively less of one (trust builds up).
    """
    if not sender_domain:
        return {"known": False, "risk_bump": 0.10, "reason": "no sender domain available"}

    rep = load_reputation()
    if sender_domain not in rep:
        return {"known": False, "risk_bump": 0.15, "reason": "first time seen"}

    seen_count = rep[sender_domain].get("count", 0)
    risk_bump = max(0.0, 0.10 - seen_count * 0.02)
    return {
        "known": True,
        "risk_bump": round(risk_bump, 3),
        "reason": f"seen {seen_count} time(s) before",
    }


def update_reputation(sender_domain: str) -> None:
    """Call this once per processed email to record that we saw this sender."""
    if not sender_domain:
        return

    rep = load_reputation()
    rep.setdefault(sender_domain, {"count": 0})
    rep[sender_domain]["count"] += 1

    with open(REPUTATION_FILE, "w") as f:
        json.dump(rep, f, indent=2)


if __name__ == "__main__":
    print("Before:", check_sender("fake-vendor-demo.test"))
    update_reputation("fake-vendor-demo.test")
    update_reputation("fake-vendor-demo.test")
    print("After 2 updates:", check_sender("fake-vendor-demo.test"))
    print("Never-seen domain:", check_sender("brand-new-domain.test"))
