
"""
score_and_report.py
Stage 6 of the pipeline: combines all four analysis vectors (image/password,
links, PDF, text language) plus reputation and detonation behavior into one
final report -- with both an overall combined verdict AND each vector's own
individual verdict, so you can demo them separately or together.

Standalone test:
    python3 score_and_report.py
    (runs against a mocked set of upstream results)
"""

import hashlib
import os
from ai_brain import summarize_findings

# Keywords in the detonation "behavior" string that bump the risk score up.
# Kept small and explainable on purpose -- this is a demo scoring rule, not
# a production ML model, and the report should be honest about that.
RISKY_BEHAVIOR_KEYWORDS = ["dropped", "network request", "connection", "registry", "executed"]


def _sha256_of_file(path):
    if not path or not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _behavior_risk_score(detonation_result: dict) -> float:
    behavior_text = (detonation_result or {}).get("behavior", "").lower()
    hits = sum(1 for kw in RISKY_BEHAVIOR_KEYWORDS if kw in behavior_text)
    return min(1.0, hits * 0.25)


def build_impact_explainer(verdict: str):
    if verdict != "malicious":
        return None
    return {
        "why_password_matters": (
            "The zip file was encrypted specifically so email security scanners couldn't "
            "look inside it -- scanners can't inspect what they can't decrypt. The password "
            "was hidden in an image instead of typed as plain text so text-based filters "
            "wouldn't catch it either. The password only matters once a human manually "
            "extracts and runs the file."
        ),
        "why_links_matter": (
            "A malicious link works the same way as the password trick -- it relies on a "
            "human clicking it, not on bypassing a scanner. The link itself often leads to "
            "a fake login page designed to steal credentials, or triggers a drive-by download."
        ),
        "why_pdf_features_matter": (
            "A PDF can contain embedded scripts or auto-run actions that execute the moment "
            "the file is opened in a vulnerable viewer -- no separate 'unzip and run' step "
            "needed, which is what makes malicious PDFs particularly dangerous for a distracted reader."
        ),
        "if_a_real_person_had_opened_this": (
            "If an employee had received this instead of our sandbox, and interacted with any "
            "of these elements -- entering the password, clicking the link, or opening the PDF "
            "-- the resulting action would run with that employee's own account permissions. "
            "Depending on the real payload, that can range from a single dropped file (as our "
            "harmless demo payload does) up to file encryption for ransom, credential theft, "
            "or the machine being used as a foothold to reach further into the network. Our "
            "sandbox intercepts this before any of that happens on a real device."
        ),
    }


def build_report(
    parsed: dict,
    ocr_text: str,
    ai_result: dict,
    reputation_result: dict,
    unzip_result: dict,
    detonation_result: dict,
    link_result=None,
    pdf_result=None,
    text_result=None,
) -> dict:
    """
    Combines every upstream stage's output into the final report the UI renders.
    link_result / pdf_result / text_result are optional so this still works
    for callers that haven't been updated to the four-vector pipeline yet.
    """
    link_result = link_result or {"links_found": 0, "highest_risk": 0.0, "details": []}
    pdf_result = pdf_result or {"suspicious_features": [], "extracted_text_preview": "", "risk_score": 0.0}
    text_result = text_result or {"urgency_hits": [], "credential_request_hits": [], "risk_score": 0.0}

    ai_confidence = ai_result.get("confidence", 0.0)
    rep_risk_bump = reputation_result.get("risk_bump", 0.0)
    behavior_risk = _behavior_risk_score(detonation_result)
    link_risk = link_result.get("highest_risk", 0.0)
    pdf_risk = pdf_result.get("risk_score", 0.0)
    text_risk = text_result.get("risk_score", 0.0)

    # Each vector's OWN individual verdict -- lets you demo "image detection
    # alone", "link detection alone", etc. as well as the combined result.
    vector_verdicts = {
        "image_password": "malicious" if (ai_confidence >= 0.6 and ai_result.get("password_found")) else
                           ("suspicious" if ai_confidence >= 0.3 else "clean"),
        "links": "malicious" if link_risk >= 0.6 else ("suspicious" if link_risk >= 0.3 else "clean"),
        "pdf": "malicious" if pdf_risk >= 0.6 else ("suspicious" if pdf_risk >= 0.3 else "clean"),
        "text_language": "suspicious" if text_risk >= 0.3 else "clean",
        "detonation_behavior": "malicious" if behavior_risk >= 0.5 else "clean",
    }

    # Combined score -- simple, explainable weighted sum across all vectors
    combined_score = min(
        1.0,
        (ai_confidence * 0.30)
        + rep_risk_bump
        + (behavior_risk * 0.25)
        + (link_risk * 0.20)
        + (pdf_risk * 0.15)
        + (text_risk * 0.10),
    )

    # --- CRITICAL THREAT OVERRIDE ---
    # Prevents score dilution. If a live payload drops, or a hidden password is found,
    # the threat is escalated immediately, regardless of how polite the email text was.
    if vector_verdicts.get("detonation_behavior") == "malicious" or vector_verdicts.get("image_password") == "malicious":
        combined_score = max(combined_score, 0.95)

    any_content_flag = ai_result.get("password_found") or link_result["links_found"] > 0 or parsed.get("pdf") is not None

    if not any_content_flag and text_risk < 0.3:
        verdict = "benign"
    elif combined_score >= 0.6:
        verdict = "malicious"
    elif combined_score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "low_confidence"

    payload_hash = _sha256_of_file(unzip_result.get("extracted_path"))

    findings_text = (
        f"Sender domain: {reputation_result.get('domain')} ({reputation_result.get('reason')}). "
        f"AI password extraction: found={ai_result.get('password_found')}, confidence={ai_confidence:.2f}. "
        f"Links found: {link_result['links_found']} (highest risk {link_risk:.2f}). "
        f"PDF suspicious features: {len(pdf_result['suspicious_features'])}. "
        f"Text urgency/credential-request hits: "
        f"{len(text_result.get('urgency_hits', []))}/{len(text_result.get('credential_request_hits', []))}. "
        f"Detonation behavior: {detonation_result.get('behavior')}."
    )
    plain_summary = summarize_findings(findings_text)

    return {
        "verdict": verdict,
        "combined_score": round(combined_score, 2),
        "vector_verdicts": vector_verdicts,
        "sender": parsed.get("sender"),
        "subject": parsed.get("subject"),
        "ocr_text": ocr_text,
        "ai_extraction": ai_result,
        "reputation": reputation_result,
        "unzip": unzip_result,
        "detonation": detonation_result,
        "link_analysis": link_result,
        "pdf_analysis": pdf_result,
        "text_analysis": text_result,
        "payload_sha256": payload_hash,
        "plain_english_summary": plain_summary,
        "impact_explainer": build_impact_explainer(verdict),
    }


if __name__ == "__main__":
    mock_parsed = {"sender": "billing@fake-vendor-demo.test", "subject": "Invoice #4471", "pdf": None}
    mock_ai = {"password_found": True, "value": "br9k4X", "confidence": 0.88,
               "reasoning": "explicit access code phrase detected"}
    mock_rep = {"domain": "fake-vendor-demo.test", "known": False, "seen_count": 0,
                "risk_bump": 0.15, "reason": "first time this sender domain has been seen"}
    mock_unzip = {"success": True, "extracted_path": None, "extracted_filename": "mock_payload_HARMLESS.exe",
                  "error": None}
    mock_detonation = {"status": "executed", "behavior": "file dropped, network request made"}
    mock_links = {"links_found": 1, "highest_risk": 0.75,
                  "details": [{"url": "http://192.168.1.1/verify", "flags": ["uses a raw IP address"], "risk_score": 0.75}]}
    mock_pdf = {"suspicious_features": ["contains embedded JavaScript"], "extracted_text_preview": "", "risk_score": 0.3}
    mock_text = {"urgency_hits": ["immediately", "verify your account"], "credential_request_hits": ["verify your account"], "risk_score": 0.55}

    report = build_report(mock_parsed, "access code: br9k4X", mock_ai, mock_rep, mock_unzip, mock_detonation,
                           mock_links, mock_pdf, mock_text)

    import json
    print(json.dumps(report, indent=2))
