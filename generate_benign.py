"""
generate_benign.py
Generates a genuinely benign email -- no attachment, no password, no
urgency trick. This is the pipeline's control case, proving it doesn't
false-positive on normal mail.

Usage:
    python3 generate_benign.py
"""

import os
import time
from email.message import EmailMessage

from generators import build_benign_body

OUTPUT_DIR = "demo_artifacts"


def generate_benign() -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    body = build_benign_body()
    timestamp = int(time.time())

    msg = EmailMessage()
    msg["Subject"] = "Quick update"
    msg["From"] = "teammate@internal-company-demo.test"
    msg["To"] = "you@yourcompany.test"
    msg.set_content(body)

    eml_path = os.path.join(OUTPUT_DIR, f"benign_{timestamp}.eml")
    with open(eml_path, "wb") as f:
        f.write(bytes(msg))

    print(f"Generated: {eml_path}")
    return eml_path


if __name__ == "__main__":
    generate_benign()
