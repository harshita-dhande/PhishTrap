"""
pdf_analysis.py
Passive, static analysis of a PDF attachment. This NEVER opens the PDF in
a viewer and never renders it -- it just reads the raw bytes and extracted
text to look for red flags (embedded JavaScript, auto-launch actions,
embedded files) and pulls out any URLs found inside for link_analysis.py
to score.

Requires: pip install pypdf --break-system-packages

Standalone test:
    python3 pdf_analysis.py demo_artifacts/some_attachment.pdf
"""

import sys
import io

from link_extract import extract_urls

# Raw byte-level markers that indicate potentially active/dangerous PDF
# features. Checking for these strings directly in the file bytes is a
# standard, safe first-pass triage technique -- it doesn't require
# executing anything, just reading text.
SUSPICIOUS_MARKERS = {
    b"/JavaScript": "contains embedded JavaScript",
    b"/JS": "contains embedded JavaScript",
    b"/Launch": "contains an auto-launch action (can run external programs)",
    b"/OpenAction": "has an action set to run automatically on open",
    b"/EmbeddedFile": "has an embedded file inside the PDF",
    b"/RichMedia": "contains embedded rich media (Flash/video, historically abused)",
}


def _scan_raw_bytes(pdf_bytes: bytes) -> list[str]:
    findings = []
    for marker, description in SUSPICIOUS_MARKERS.items():
        if marker == b"/OpenAction":
            # A bare /OpenAction that just navigates to a page (e.g. fpdf2's
            # default "[page /FitH null]") is normal and harmless -- only
            # flag it when paired with something that actually runs code,
            # so ordinary PDFs don't false-positive on this alone.
            if marker in pdf_bytes and (b"/JavaScript" in pdf_bytes or b"/JS" in pdf_bytes or b"/Launch" in pdf_bytes):
                findings.append("has an auto-run action combined with active content -- runs something on open")
            continue
        if marker in pdf_bytes:
            findings.append(description)
    return findings


def _extract_text(pdf_bytes: bytes) -> str:
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(pdf_bytes))
        text_parts = []
        for page in reader.pages:
            try:
                text_parts.append(page.extract_text() or "")
            except Exception:
                continue  # a single malformed page shouldn't kill the whole scan
        return "\n".join(text_parts)
    except Exception as e:
        return f"(text extraction failed: {e})"


def analyze_pdf(pdf_bytes: bytes) -> dict:
    """
    Returns:
        {
            "suspicious_features": [str, ...],
            "extracted_text_preview": str,
            "links_in_pdf": {...same shape as link_analysis.analyze_all_links...},
            "risk_score": float,
        }
    """
    suspicious_features = _scan_raw_bytes(pdf_bytes)
    extracted_text = _extract_text(pdf_bytes)
    links_in_pdf = extract_urls(extracted_text)

    risk_score = min(1.0, len(suspicious_features) * 0.3 + (0.2 if links_in_pdf else 0.0))

    return {
        "suspicious_features": suspicious_features,
        "extracted_text_preview": extracted_text[:300],
        "links_found_in_pdf": links_in_pdf,
        "risk_score": risk_score,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pdf_analysis.py <path_to_pdf>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    import json
    print(json.dumps(analyze_pdf(data), indent=2))
