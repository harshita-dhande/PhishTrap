"""
parse_eml.py
Stage 1 of the pipeline: pull the body text and attachments out of a raw .eml file.

Standalone test:
    python3 parse_eml.py demo_artifacts/lure_001.eml
"""

import sys
import email
from email import policy
from email.parser import BytesParser


def parse_eml(eml_path: str) -> dict:
    """
    Returns:
        {
            "sender": str,
            "subject": str,
            "body": str,
            "image": {"filename": str, "bytes": bytes} | None,
            "zip":   {"filename": str, "bytes": bytes} | None,
        }
    """
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    result = {
        "sender": msg.get("From", "unknown"),
        "subject": msg.get("Subject", ""),
        "body": "",
        "image": None,
        "zip": None,
        "pdf": None,
    }

    # Walk the message; get_body() pulls the plain-text part, iter_attachments() the rest
    body_part = msg.get_body(preferencelist=("plain",))
    if body_part is not None:
        result["body"] = body_part.get_content()

    for attachment in msg.iter_attachments():
        content_type = attachment.get_content_type()
        filename = attachment.get_filename() or "unnamed"
        payload = attachment.get_content()

        # get_content() for images/binary already returns bytes; for some
        # subtypes it can return str, so normalize defensively.
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="ignore")

        if content_type.startswith("image/"):
            result["image"] = {"filename": filename, "bytes": payload}
        elif content_type in ("application/zip", "application/x-zip-compressed"):
            result["zip"] = {"filename": filename, "bytes": payload}
        elif content_type == "application/pdf":
            result["pdf"] = {"filename": filename, "bytes": payload}

    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_eml.py <path_to_eml>")
        sys.exit(1)

    parsed = parse_eml(sys.argv[1])

    print("=== Parsed Email ===")
    print(f"From:    {parsed['sender']}")
    print(f"Subject: {parsed['subject']}")
    print(f"Body ({len(parsed['body'])} chars):")
    print(parsed["body"])
    print()
    print(f"Image attachment: {parsed['image']['filename'] if parsed['image'] else 'none'}")
    print(f"Zip attachment:   {parsed['zip']['filename'] if parsed['zip'] else 'none'}")
    print(f"PDF attachment:   {parsed['pdf']['filename'] if parsed['pdf'] else 'none'}")
