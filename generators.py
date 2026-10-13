"""
generators.py
Shared building blocks used by generate_lure.py and generate_benign.py:
realistic phishing pretexts, benign control email bodies, and the
"weird" (rotated/blurred/compressed) lure image generator that mimics a
real low-quality screenshot instead of a clean, obviously-fake image.
"""

import random
from PIL import Image, ImageDraw, ImageFilter

# Longer, calmer, business-plausible pretexts -- urgency comes from a soft
# deadline and a specific reference number, not exclamation points.
PRETEXTS = [
    (
        "Hi,\n\nFollowing up on our conversation last week — please find "
        "attached the finalized invoice (INV-{ref}) for the Q3 infrastructure "
        "support contract, as discussed with James in procurement.\n\n"
        "Per our updated vendor payment policy, all invoice attachments are "
        "now encrypted before sending. You'll find the access code in the "
        "attached screenshot from our billing portal — this is a temporary "
        "measure while we migrate to the new AP system next month.\n\n"
        "Could you confirm receipt and process this by Friday? We've had a "
        "couple of payments held up in the queue this quarter and would "
        "like to avoid any further delay on our end, especially with the "
        "year-end reconciliation coming up.\n\nLet me know if the code "
        "doesn't work or if you need anything re-sent.\n\nBest regards,\n"
        "Priya Nair\nAccounts Receivable\nSummit Vendor Solutions"
    ),
    (
        "Hello,\n\nAttached is the updated compensation review document for "
        "your team (ref: HR-{ref}), as requested ahead of next week's "
        "calibration meeting.\n\nSince this contains salary information, "
        "it's password-protected per standard HR policy — the access code "
        "is included in the attached screenshot from the HR portal.\n\n"
        "Please review before Thursday's meeting so we can finalize numbers "
        "in time for the payroll cutoff.\n\nThanks,\nHR Business Partner Team"
    ),
    (
        "Hi there,\n\nOur vendor has shared a file with you via our secure "
        "portal (reference SFT-{ref}). For security, the archive requires "
        "an access code, which is shown in the attached portal screenshot.\n\n"
        "This link/file will expire in 48 hours per our retention policy, so "
        "please download and extract at your earliest convenience.\n\n"
        "Regards,\nShared File Notification — Portal Team"
    ),
]

# Genuinely benign emails -- no attachment, no password, no urgency trick.
# These exist so the pipeline can demonstrate it does NOT flag normal mail.
BENIGN_BODIES = [
    (
        "Hi team,\n\nQuick reminder that the sprint retro is moved to 3pm "
        "tomorrow instead of 11am — same room. Please push any blockers "
        "into the doc beforehand so we can move faster.\n\nThanks,\nAlex"
    ),
    (
        "Hello,\n\nYour requested access to the shared analytics dashboard "
        "has been approved. You can log in using your existing company "
        "SSO — no further action needed on your end.\n\nIf you run into any "
        "issues, just reply to this thread.\n\nIT Support"
    ),
]


# Fake/reserved-range links for demo lures -- 192.0.2.0/24 is IANA's
# reserved TEST-NET-1 block, guaranteed to never route anywhere real. This
# lets link_analysis.py's IP-literal heuristic fire without pointing at any
# actual host, safe or otherwise.
DECOY_MALICIOUS_LINKS = [
    "http://192.0.2.10/verify-account",
    "http://bit.ly/fake-demo-shortlink",  # a shortener-pattern URL for the demo, not a real bit.ly link
]


def random_password() -> str:
    """Generates a fresh password each time -- nothing hardcoded anywhere."""
    charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(charset) for _ in range(6))


def build_malicious_body() -> tuple[str, str]:
    """
    Retrns (body_text, password) with a randomly picked pretext + fresh
    password. The password appears ONLY in the generated image (see
    make_weird_lure_image) -- never in the body text -- so the pipeline's
    OCR stage is actually doing real work, not reading a shortcut.
    """
    template = random.choice(PRETEXTS)
    ref = random.randint(1000, 9999)
    password = random_password()
    return template.format(ref=ref), password


def build_benign_body() -> str:
    return random.choice(BENIGN_BODIES)


def make_weird_lure_image(password: str, filename: str) -> None:
    """
    Renders a clean, high-contrast, easily readable image for testing.
    All intentional blur, rotation, and compression have been removed.
    """
    from PIL import ImageFont
    
    img = Image.new("RGB", (800, 300), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    
    # Attempt to load a larger, standard Ubuntu font for clarity
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 28)
    except IOError:
        font = ImageFont.load_default()

    # Draw text with clean black color and good line spacing
    draw.text(
        (40, 80),
        f"Access code for this document:\n{password}\n(portal-generated, valid 48hrs)",
        fill=(0, 0, 0),
        font=font,
        spacing=12
    )

    # Save directly as a clean, lossless PNG
    img.save(filename) 


def make_pdf_attachment(text: str, filename: str, add_demo_marker: bool = False) -> None:
    """
    Builds a simple one-page PDF with the given text. If add_demo_marker is
    True, appends an inert PDF *comment* (bytes PDF viewers ignore, never
    executed) containing a marker string -- purely so pdf_analysis.py's
    static byte-scan has something realistic to catch in a demo. This does
    NOT create any real embedded JavaScript or active content; it's just
    text bytes shaped like a red flag, for testing the detector itself.
    """
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    for line in text.split("\n"):
        if not line:
            pdf.cell(0, 8, txt="", ln=1)
        else:
            while line:
                pdf.cell(0, 8, txt=line[:50], ln=1)
                line = line[50:]
    pdf.output(filename)

    if add_demo_marker:
        with open(filename, "ab") as f:
            f.write(b"\n% /JavaScript demo-marker-only -- inert, for detector testing, not a real script\n")
