"""
Stage 2 — Image-to-Text Processing

Runs EasyOCR on an image attachment to pull out any hidden text
(e.g. a password embedded in a screenshot).

Run standalone:
    python ocr_extract.py parsed_output/lure_C_invoice_note.png
"""

import sys

_reader = None  # lazy-loaded, EasyOCR init is slow


def _get_reader():
    global _reader
    if _reader is None:
        import ssl
        try:
            ssl._create_default_https_context = ssl._create_unverified_context
        except Exception:
            pass
        import easyocr
        _reader = easyocr.Reader(["en"], gpu=False)
    return _reader


def run_ocr(image_input, retries: int = 1) -> str:
    """
    Returns extracted text as a single string. Retries once on failure
    since OCR occasionally chokes on the "weird" (blurred/compressed) demo images.
    Supports both file paths and raw image bytes.
    """
    last_error = None
    for attempt in range(retries + 1):
        try:
            reader = _get_reader()
            target = image_input
            if isinstance(image_input, (bytes, bytearray)):
                import io
                from PIL import Image
                import numpy as np
                img = Image.open(io.BytesIO(image_input)).convert("RGB")
                target = np.array(img)
            results = reader.readtext(target, detail=0)
            return " ".join(results).strip()
        except Exception as e:
            last_error = e
            continue

    print(f"[ocr_extract] OCR failed after {retries + 1} attempt(s): {last_error}")
    return ""


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ocr_extract.py <path-to-image>")
        sys.exit(1)

    text = run_ocr(sys.argv[1])
    print("--- OCR Result ---")
    print(text if text else "(no text extracted)")
