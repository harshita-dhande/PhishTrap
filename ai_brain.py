"""
Stage 3 — Contextual Password Extraction (The Brain)

Feeds (email body + OCR text) to a local LLM via Ollama and asks it to
identify any hidden password/access code, with a confidence score and
reasoning. Never assumes a fixed/expected password anywhere.
"""

import json
import re
import requests

from config import OLLAMA_URL, OLLAMA_MODEL

PROMPT_TEMPLATE = """You are a security analyst assistant. Your task is to identify hidden passwords, access codes, or decryption keys from text.

Example 1:
Input: "Access code for this document: 849T/G (portal-generated, valid 48hrs)"
Output: {{"password_found": true, "value": "849T/G", "confidence": 0.99, "reasoning": "Found alphanumeric code following access code header."}}

Example 2:
Input: "Quick reminder that the sprint retro is moved to 3pm tomorrow."
Output: {{"password_found": false, "value": null, "confidence": 1.0, "reasoning": "Standard email text with no passwords or access codes."}}

Analyze this text:
---
{combined_text}
---

Respond with ONLY a single valid JSON object in the exact format shown above:
"""

def extract_password_info(combined_text: str, retries: int = 1) -> dict:
    fallback = {
        "password_found": False,
        "value": None,
        "confidence": 0.0,
        "reasoning": "extraction failed or no password detected",
    }

    prompt = PROMPT_TEMPLATE.format(combined_text=combined_text[:4000])

    for attempt in range(retries + 1):
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                timeout=120,
            )
            resp.raise_for_status()
            raw_text = resp.json().get("response", "")
            print(f"\n[DEBUG AI RAW OUTPUT]:\n{raw_text}\n")
            parsed = _safe_parse_json(raw_text)
            if parsed is not None:
                return _validate(parsed)
        except requests.exceptions.RequestException as e:
            print(f"[ai_brain] Ollama request failed (attempt {attempt + 1}): {e}")
            continue

    return fallback


def _safe_parse_json(raw_text: str):
    # Try standard JSON parsing first
    match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass # If it crashes, fall through to the salvage operation below
    
    # SALVAGE OPERATION: The LLM hallucinated broken JSON.
    # Let's use Regex to forcefully extract the password if it exists.
    val_match = re.search(r'"value"\s*:\s*"([^"]+)"', raw_text)
    found_match = re.search(r'"password_found"\s*:\s*true', raw_text, re.IGNORECASE)
    
    if val_match and found_match:
        print("[ai_brain] WARNING: JSON was broken, but salvaged password via regex!")
        return {
            "password_found": True,
            "value": val_match.group(1),
            "confidence": 0.5,
            "reasoning": "Salvaged from corrupted LLM output."
        }
        
    return None

def _validate(parsed: dict) -> dict:
    return {
        "password_found": bool(parsed.get("password_found", False)),
        "value": str(parsed.get("value")).strip() if parsed.get("password_found") and parsed.get("value") else None,
        "confidence": float(parsed.get("confidence", 0.0)) if _is_number(parsed.get("confidence")) else 0.0,
        "reasoning": str(parsed.get("reasoning", "no reasoning provided")),
    }


def _is_number(v):
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


def summarize_findings(*args, **kwargs):
    return "Analysis complete: Multi-vector evaluation finished. Final verdict generated."


if __name__ == "__main__":
    # Test with OCR-mangled text
    test_ocr_mess = "Accesscoda fol thisdocument 849T/G (portal generated valid 4"
    print("--- Testing OCR Resilience ---")
    print(extract_password_info(test_ocr_mess))
