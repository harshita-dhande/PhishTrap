"""
run_pipeline.py
Chains every stage together into one pipeline run:
    parse -> OCR -> AI password extraction -> reputation check
          -> unzip -> detonate -> score & report

Standalone test:
    python3 run_pipeline.py
    (runs against every .eml file in demo_artifacts/ and prints a verdict for each)
"""

import glob
import time

from parse_eml import parse_eml
from ocr_extract import run_ocr
from ai_brain import extract_password_info
from reputation import check_sender, update_reputation
from unzip_payload import try_unzip
from detonate import detonate
from score_and_report import build_report
from link_extract import analyze_all_links
from pdf_analysis import analyze_pdf
from text_analysis import analyze_text

MAX_RETRIES = 2


def _retry(fn, *args, retries=MAX_RETRIES, **kwargs):
    """Small generic retry wrapper for the flakier stages (OCR, detonation)."""
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_error = e
            if attempt < retries:
                time.sleep(1)
    raise last_error


def run_pipeline(eml_path: str, on_stage=None) -> dict:
    """
    Runs the full pipeline against a single .eml file.
    on_stage: optional callback(stage_name: str, status: str, detail: str = "")
              -- this is the hook Phase 5's WebSocket layer will use later
              to stream live status updates to the UI. Safe to leave as None
              for standalone/CLI use.
    """
    def notify(stage, status, detail=""):
        if on_stage:
            on_stage(stage, status, detail)

    notify("ingest", "running")
    parsed = parse_eml(eml_path)
    notify("ingest", "done", f"sender={parsed.get('sender', 'unknown')}")

    # ==========================================
    # 1. IMAGE & PASSWORD EXTRACTION (Dynamic)
    # ==========================================
    ocr_text = ""
    ai_result = {
        "password_found": False,
        "value": None,
        "confidence": 0.0,
        "reasoning": "Skipped: No image or zip found."
    }

    # Trigger AI if there is an image OR a zip. 
    # This preserves the anti-hallucination fix for plain text emails.
    if parsed.get("image") or parsed.get("zip"):
        if parsed.get("image"):
            notify("ocr", "running")
            try:
                ocr_text = _retry(run_ocr, parsed["image"]["bytes"])
                notify("ocr", "done", ocr_text[:60])
            except Exception as e:
                notify("ocr", "failed", str(e))
        else:
            notify("ocr", "skipped", "No image to scan")

        notify("ai_extraction", "running")
        combined_text = f"{parsed.get('body', '')}\n{ocr_text}".strip()
        ai_result = extract_password_info(combined_text)
        notify("ai_extraction", "done", f"password_found={ai_result.get('password_found', False)}")
    else:
        notify("ocr", "skipped", "No image to scan")
        notify("ai_extraction", "skipped", "No image or zip to scan")

    # ==========================================
    # 2. PDF ANALYSIS (Dynamic)
    # ==========================================
    if parsed.get("pdf"):
        notify("pdf_analysis", "running")
        pdf_result = analyze_pdf(parsed["pdf"]["bytes"])
        notify("pdf_analysis", "done", pdf_result.get("status", "unknown"))
    else:
        pdf_result = {"suspicious_features": [], "extracted_text_preview": "", "links": []}
        notify("pdf_analysis", "skipped", "No PDF attachment")

    # ==========================================
    # 3. LINK ANALYSIS (Dynamic)
    # ==========================================
    if parsed.get("links") or "http" in parsed.get("body", ""):
        notify("link_analysis", "running")
        link_result = analyze_all_links(parsed.get("body", ""))
        notify("link_analysis", "done", f"{link_result.get('links_found', 0)} link(s) found")
    else:
        link_result = {"links_found": 0, "highest_risk": 0.0, "details": []}
        notify("link_analysis", "skipped", "No links in email")

    # ==========================================
    # 4. TEXT & REPUTATION (Always Runs)
    # ==========================================
    notify("text_analysis", "running")
    text_result = analyze_text(parsed.get("body", ""))
    notify("text_analysis", "done", f"risk_score={text_result.get('risk_score', 0)}")

    notify("reputation", "running")
    reputation_result = check_sender(parsed.get("sender", ""))
    notify("reputation", "done", reputation_result.get("reason", ""))
    
    # ==========================================
    # 5. UNZIP & DETONATION
    # ==========================================
    unzip_result = {
        "success": False, 
        "extracted_path": None, 
        "extracted_filename": None,
        "error": "no zip attachment"
    }
    
    if parsed.get("zip"):
        notify("unzip", "running")
        unzip_result = try_unzip(parsed["zip"]["bytes"], ai_result.get("value"))
        notify("unzip", "done" if unzip_result.get("success") else "failed", unzip_result.get("error") or "")
    else:
        notify("unzip", "skipped", "no zip attachment")

    detonation_result = {"status": "skipped", "behavior": "no executable extracted"}
    if unzip_result.get("success"):
        notify("detonate", "running")
        try:
            detonation_result = _retry(detonate, unzip_result["extracted_path"])
        except Exception as e:
            detonation_result = {"status": "error", "behavior": str(e)}
        notify("detonate", "done", str(detonation_result))
    else:
        notify("detonate", "skipped", "nothing to detonate")

    # ==========================================
    # 6. SCORE & REPORT
    # ==========================================
    notify("report", "running")
    report = build_report(
        parsed, ocr_text, ai_result, reputation_result, 
        unzip_result, detonation_result, link_result, pdf_result, text_result
    )
    update_reputation(parsed.get("sender", ""))
    notify("report", "done", f"verdict={report.get('verdict', 'unknown')}")

    return report


if __name__ == "__main__":
    def print_stage(stage, status, detail=""):
        print(f"  [{stage}] {status} {('- ' + detail) if detail else ''}")

    eml_files = sorted(glob.glob("demo_artifacts/*.eml"))
    if not eml_files:
        print("No .eml files found in demo_artifacts/. Generate some with generate_lure.py / generate_benign.py first.")

    for path in eml_files:
        print(f"\n=== Running pipeline on {path} ===")
        result = run_pipeline(path, on_stage=print_stage)
        print(f"  --> Individual vectors: {result.get('vector_verdicts', {})}")
        print(f"  --> COMBINED VERDICT: {result.get('verdict', 'unknown')} (score: {result.get('combined_score', 0)})")
        print(f"  --> Summary: {result.get('plain_english_summary', '')}")
