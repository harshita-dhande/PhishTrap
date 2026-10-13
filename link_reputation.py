"""
link_reputation.py
Optional online layer: checks a URL against abuse.ch's URLhaus, a free,
no-API-key-required threat-intelligence lookup for known-malicious URLs.

IMPORTANT — safety notes:
  - This sends only the URL text to the lookup API. It never visits,
    opens, or renders the link itself.
  - This requires the Ubuntu Controller to briefly reach the internet
    (the same way you already do for installing packages). The Windows
    Victim VM stays fully airgapped -- this has nothing to do with it.
  - Only run this with the Controller's network mode temporarily set to
    Shared (same pattern as setup_controller.sh), then switch back to
    Host Only afterward.
  - If you don't want the Controller to touch the internet at all, skip
    this file entirely -- link_extract.py's offline heuristics alone are
    a legitimate, safe feature on their own.

Standalone test (requires temporary internet access):
    python3 link_reputation.py
"""

import requests

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"


def check_reputation(url: str, timeout: int = 8) -> dict:
    """
    Returns:
        {"checked": bool, "known_malicious": bool, "threat_type": str|None, "error": str|None}
    Fails safe: if the API is unreachable (e.g. Controller is Host-Only
    right now), returns checked=False rather than raising.
    """
    try:
        response = requests.post(URLHAUS_API, data={"url": url}, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return {"checked": False, "known_malicious": False, "threat_type": None,
                "error": f"lookup unavailable: {e}"}

    if data.get("query_status") == "ok":
        return {
            "checked": True,
            "known_malicious": True,
            "threat_type": data.get("threat", "unknown"),
            "error": None,
        }

    return {"checked": True, "known_malicious": False, "threat_type": None, "error": None}


if __name__ == "__main__":
    test_url = "http://example.com"
    print(check_reputation(test_url))
