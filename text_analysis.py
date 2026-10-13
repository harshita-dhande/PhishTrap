"""
text_analysis.py
Scores the email body text itself for common phishing-language patterns --
urgency, generic greetings, credential/payment requests. This is separate
from ai_brain.py's job (which only looks for a hidden password) -- this
stage judges whether the WRITING ITSELF reads like social engineering.

Fully offline, no network calls, just pattern matching -- so it's safe to
run on absolutely anything, including real suspicious mail if you ever
need to.

Standalone test:
    python3 text_analysis.py
"""

import re

URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "final notice", "24 hours",
    "expire", "suspended", "verify your account", "confirm your password",
    "unusual activity", "click here", "limited time", "as soon as possible",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "verify your account", "update your payment",
    "confirm your identity", "login to continue", "reset your password",
    "provide your card", "social security number",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear sir/madam"]


def analyze_text(body: str) -> dict:
    """
    Returns:
        {
            "urgency_hits": [str, ...],
            "credential_request_hits": [str, ...],
            "generic_greeting": bool,
            "risk_score": float,
        }
    Every hit is a literal phrase match -- fully explainable, nothing hidden
    in a black-box model for this particular check.
    """
    lowered = (body or "").lower()

    urgency_hits = [p for p in URGENCY_PHRASES if p in lowered]
    credential_hits = [p for p in CREDENTIAL_REQUEST_PHRASES if p in lowered]
    generic_greeting = any(g in lowered for g in GENERIC_GREETINGS)

    risk_score = min(
        1.0,
        len(urgency_hits) * 0.15
        + len(credential_hits) * 0.25
        + (0.1 if generic_greeting else 0.0),
    )

    return {
        "urgency_hits": urgency_hits,
        "credential_request_hits": credential_hits,
        "generic_greeting": generic_greeting,
        "risk_score": round(risk_score, 2),
    }


if __name__ == "__main__":
    malicious_sample = (
        "Dear Customer, your account has shown unusual activity. Please "
        "verify your account immediately to avoid suspension within 24 hours."
    )
    benign_sample = (
        "Hi team, quick reminder the sprint retro moved to 3pm tomorrow."
    )

    import json
    print("=== Malicious-style sample ===")
    print(json.dumps(analyze_text(malicious_sample), indent=2))
    print("\n=== Benign sample ===")
    print(json.dumps(analyze_text(benign_sample), indent=2))
