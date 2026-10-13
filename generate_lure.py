"""
generate_lure.py
Generates a fresh malicious .eml each run. Supports turning each of the
four detection vectors on/off, so you can demo them individually
(one flag at a time) or all combined (the default).

Prereq: mock_payload_HARMLESS.exe must already exist (compiled on the
Windows VM via PyInstaller, then copied back to this Ubuntu Controller).

Usage:
    python3 generate_lure.py                       # all four vectors combined
    python3 generate_lure.py --image-only
    python3 generate_lure.py --link-only
    python3 generate_lure.py --pdf-only
    python3 generate_lure.py --text-only
"""

import os
import sys
import time
from email.message import EmailMessage

import pyzipper

from generators import build_malicious_body, make_weird_lure_image, make_pdf_attachment, DECOY_MALICIOUS_LINKS

EXE_PATH = "mock_payload_HARMLESS.exe"   # copied over from the Windows VM after compiling
OUTPUT_DIR = "demo_artifacts"


def generate_lure(include_image=True, include_link=True, include_pdf=True, tag="combined") -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    body, password = build_malicious_body()
    timestamp = int(time.time())

    if include_link:
        body += f"\n\nYou can also verify directly here: {DECOY_MALICIOUS_LINKS[0]}"

    msg = EmailMessage()
    msg["Subject"] = "Invoice / Document — Action Required"
    msg["From"] = "billing@fake-vendor-demo.test"
    msg["To"] = "you@yourcompany.test"
    msg.set_content(body)

    if include_image:
        if not os.path.exists(EXE_PATH):
            raise FileNotFoundError(
                f"{EXE_PATH} not found. Compile mock_payload_HARMLESS.py on the "
                f"Windows VM with PyInstaller and copy the .exe here first."
            )

        image_path = os.path.join(OUTPUT_DIR, f"lure_{timestamp}_image.png")
        make_weird_lure_image(password, image_path)

        zip_path = os.path.join(OUTPUT_DIR, f"lure_{timestamp}_invoice.zip")
        with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_LZMA,
                                  encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode("utf-8"))
            zf.write(EXE_PATH, arcname="mock_payload_HARMLESS.exe")

        with open(image_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="image", subtype="png",
                                filename="portal_screenshot.png")
        with open(zip_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="zip",
                                filename="document.zip")
        os.remove(image_path)
        os.remove(zip_path)

    if include_pdf:
        pdf_path = os.path.join(OUTPUT_DIR, f"lure_{timestamp}_doc.pdf")
        make_pdf_attachment(
            "Confidential Document\n\nPlease review the attached terms and "
            "sign where indicated. Contact billing for questions.",
            pdf_path,
            add_demo_marker=True,
        )
        with open(pdf_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                                filename="terms_and_conditions.pdf")
        os.remove(pdf_path)

    eml_path = os.path.join(OUTPUT_DIR, f"lure_{tag}_{timestamp}.eml")
    with open(eml_path, "wb") as f:
        f.write(bytes(msg))

    print(f"Generated: {eml_path}")
    if include_image:
        print(f"(password used: {password} -- for your own testing reference only)")
    return eml_path


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--image-only" in args:
        generate_lure(include_image=True, include_link=False, include_pdf=False, tag="image_only")
    elif "--link-only" in args:
        generate_lure(include_image=False, include_link=True, include_pdf=False, tag="link_only")
    elif "--pdf-only" in args:
        generate_lure(include_image=False, include_link=False, include_pdf=True, tag="pdf_only")
    elif "--text-only" in args:
        generate_lure(include_image=False, include_link=False, include_pdf=False, tag="text_only")
    else:
        generate_lure(include_image=True, include_link=True, include_pdf=True, tag="combined")
