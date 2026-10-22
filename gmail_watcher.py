"""
gmail_watcher.py
PhishTrap Gmail Integration — Background Email Monitor

Polls your Gmail Inbox every POLL_INTERVAL_SECONDS for unread messages,
runs each through the full PhishTrap pipeline, and writes a verdict label
back to Gmail.

Usage:
    # One-time browser authorization (run this first):
    python3 gmail_watcher.py --auth-only

    # Start the live watcher:
    python3 gmail_watcher.py

    # Scan only the last N unread emails (for testing):
    python3 gmail_watcher.py --scan-last 5

    # Dry run (analyze but don't apply labels):
    python3 gmail_watcher.py --dry-run

Safety guarantees:
    - Only reads and labels emails — never sends, deletes, or modifies content.
    - Detonation is controlled by config.DISABLE_DETONATION (True by default on Mac).
    - No payload is ever executed on this machine.
"""

import argparse
import base64
import json
import logging
import os
import sys
import tempfile
import time

from googleapiclient.errors import HttpError

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = 15       # check for new mail every 15s for fast response
SEEN_FILE             = "gmail_seen.json"   # tracks already-scanned message IDs
MAX_MESSAGES_PER_POLL = 20       # safety cap per poll cycle


# ─── Seen-ID persistence ──────────────────────────────────────────────────────
def _load_seen() -> set[str]:
    if os.path.exists(SEEN_FILE):
        try:
            return set(json.load(open(SEEN_FILE)))
        except Exception:
            pass
    return set()


def _save_seen(seen: set[str]) -> None:
    # Keep only the last 5000 IDs to prevent unbounded growth
    seen_list = list(seen)[-5000:]
    try:
        json.dump(seen_list, open(SEEN_FILE, "w"))
    except Exception as e:
        log.warning("Could not save seen IDs: %s", e)


# ─── Gmail helpers ────────────────────────────────────────────────────────────
def _get_recent_message_ids(service, max_results: int = MAX_MESSAGES_PER_POLL) -> list[str]:
    """Returns a list of recent Inbox and Spam message IDs, excluding our own bot reports."""
    try:
        result = service.users().messages().list(
            userId="me",
            q='(in:inbox OR in:spam) -subject:"[PhishTrap Report]"',
            maxResults=max_results,
        ).execute()
        return [m["id"] for m in result.get("messages", [])]
    except Exception as e:
        log.error("Failed to list messages: %s", e)
        return []


def _get_all_inbox_ids(service, max_results: int) -> list[str]:
    """Returns the latest N Inbox and Spam message IDs (for --scan-last mode)."""
    return _get_recent_message_ids(service, max_results=max_results)


def _fetch_raw_eml(service, message_id: str) -> bytes | None:
    """Downloads the raw RFC-2822 bytes of a Gmail message."""
    try:
        msg = service.users().messages().get(
            userId="me",
            id=message_id,
            format="raw",
        ).execute()
        raw = msg.get("raw", "")
        return base64.urlsafe_b64decode(raw + "==")   # pad to be safe
    except Exception as e:
        log.error("Could not fetch message %s: %s", message_id, e)
        return None


def _get_snippet(service, message_id: str) -> tuple[str, str]:
    """Returns (subject, snippet) from a message metadata fetch."""
    try:
        msg = service.users().messages().get(
            userId="me",
            id=message_id,
            format="metadata",
            metadataHeaders=["Subject", "From"],
        ).execute()
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        subject = headers.get("Subject", "(no subject)")
        sender = headers.get("From", "unknown")
        return sender, subject
    except Exception:
        return "unknown", "(no subject)"


def _record_scan(run_id: str, message_id: str, report: dict, sender: str, subject: str):
    """Saves full report and appends to history.json so web dashboard reflects it."""
    os.makedirs("reports", exist_ok=True)
    report_copy = dict(report)
    report_copy["run_id"] = run_id
    report_copy["message_id"] = message_id
    report_copy["sender"] = sender
    report_copy["subject"] = subject
    report_copy["source"] = "gmail"

    try:
        with open(f"reports/{run_id}.json", "w") as f:
            json.dump(report_copy, f, indent=2)
        with open(f"reports/msg_{message_id}.json", "w") as f:
            json.dump(report_copy, f, indent=2)
    except Exception as e:
        log.warning("Could not save full report file: %s", e)

    history = []
    if os.path.exists("history.json"):
        try:
            history = json.load(open("history.json"))
        except Exception:
            history = []
    history.append({
        "run_id": run_id,
        "message_id": message_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "filename": f"gmail_{message_id[:8]}.eml",
        "sender": sender,
        "subject": subject,
        "verdict": report.get("verdict"),
        "combined_score": report.get("combined_score"),
        "vector_verdicts": report.get("vector_verdicts"),
        "source": "gmail",
    })
    try:
        json.dump(history[-50:], open("history.json", "w"), indent=2)
    except Exception as e:
        log.warning("Could not save history: %s", e)


def _send_thread_report_note(service, message_id: str, report: dict, run_id: str):
    """
    Sends a private security analysis note directly into the email thread.
    Sent from user -> user so only you see it (never sent to the external sender).
    Renders as a rich HTML card with a live, 1-click button to the interactive report.
    """
    try:
        msg = service.users().messages().get(
            userId="me", id=message_id, format="metadata",
            metadataHeaders=["Subject", "Message-ID", "From"]
        ).execute()
        thread_id = msg.get("threadId", message_id)
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        orig_subject = headers.get("Subject", "(no subject)")
        orig_msg_id = headers.get("Message-ID", "")

        profile = service.users().getProfile(userId="me").execute()
        my_email = profile.get("emailAddress", "me")

        verdict = report.get("verdict", "unknown").upper()
        verdict_color = {
            "MALICIOUS": "#cc3a21",
            "SUSPICIOUS": "#e07218",
            "BENIGN": "#0d804d",
            "LOW_CONFIDENCE": "#e07218",
        }.get(verdict, "#58a6ff")
        verdict_icon = {
            "MALICIOUS": "🔴",
            "SUSPICIOUS": "🟠",
            "BENIGN": "✅",
            "LOW_CONFIDENCE": "⚪",
        }.get(verdict, "🔍")
        score = int((report.get("combined_score", 0.0)) * 100)
        report_url = f"http://127.0.0.1:8080/?run={run_id}"

        summary = report.get("plain_english_summary", "Multi-vector security scan finished.")

        html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background:#0d1117; color:#e6edf3; padding:16px; border-radius:8px; margin:8px 0; border: 1px solid #30363d;">
  <div style="font-size:13px; font-weight:bold; color:#8b949e; text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">
    🛡️ PhishTrap Threat Analysis Report
  </div>
  <div style="background:{verdict_color}; color:#ffffff; padding:10px 14px; border-radius:6px; font-weight:bold; font-size:15px; margin-bottom:12px;">
    {verdict_icon} VERDICT: {verdict} &nbsp;&nbsp;|&nbsp;&nbsp; RISK SCORE: {score} / 100
  </div>
  <p style="color:#c9d1d9; font-size:13px; line-height:1.5; margin-bottom:16px;">
    <strong>Summary:</strong> {summary}
  </p>
  <div style="margin: 16px 0;">
    <a href="{report_url}" target="_blank" style="background:#238636; color:#ffffff; padding:10px 18px; text-decoration:none; border-radius:6px; font-weight:bold; font-size:13px; display:inline-block;">
      👉 Open Full Interactive Report in Dashboard →
    </a>
  </div>
  <div style="font-size:11px; color:#8b949e; border-top:1px solid #21262d; padding-top:8px; margin-top:12px;">
    Report Link: <a href="{report_url}" style="color:#58a6ff;">{report_url}</a><br>
    <em>(Private local analysis — visible only in your inbox)</em>
  </div>
</body>
</html>"""

        plain_text = f"""🛡️ PhishTrap Threat Analysis Report
Verdict: {verdict_icon} {verdict} (Risk Score: {score}/100)
Summary: {summary}

👉 Open Full Interactive Report:
{report_url}
"""

        from email.message import EmailMessage
        email_msg = EmailMessage()
        email_msg["To"] = my_email
        email_msg["From"] = f"PhishTrap Security <{my_email}>"
        sub = orig_subject
        if not sub.lower().startswith("re:"):
            sub = "Re: " + sub
        email_msg["Subject"] = f"[PhishTrap Report] {sub}"
        if orig_msg_id:
            email_msg["In-Reply-To"] = orig_msg_id
            email_msg["References"] = orig_msg_id
        email_msg.set_content(plain_text)
        email_msg.add_alternative(html_body, subtype="html")

        raw = base64.urlsafe_b64encode(email_msg.as_bytes()).decode()
        sent = service.users().messages().send(
            userId="me",
            body={"raw": raw, "threadId": thread_id}
        ).execute()
        log.info("  ✉  Security analysis note sent into thread (ID: %s).", sent.get("id"))
    except Exception as e:
        log.warning("Could not send thread report note: %s", e)


# ─── Core scan loop ───────────────────────────────────────────────────────────
def scan_message(service, message_id: str, verdict_to_label_id: dict,
                 dry_run: bool = False) -> dict | None:
    """
    Downloads, scans, and labels a single Gmail message.
    Returns the pipeline report dict, or None on failure.
    """
    import uuid
    from run_pipeline import run_pipeline

    sender, subject = _get_snippet(service, message_id)
    run_id = f"g_{message_id[:8]}"
    log.info("Scanning  [%s]  From: %s  |  Subject: %s", message_id[:8], sender, subject)

    # Download raw email bytes
    raw_bytes = _fetch_raw_eml(service, message_id)
    if not raw_bytes:
        log.warning("Could not download message %s — skipping.", message_id)
        return None

    # Write to a temp .eml file (run_pipeline expects a file path)
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, dir="uploads") as tmp:
        tmp.write(raw_bytes)
        tmp_path = tmp.name

    try:
        def _stage_cb(stage, status, detail=""):
            if status not in ("running",):   # only log completions to avoid noise
                log.info("    [%s] %s %s", stage, status, f"— {detail}" if detail else "")

        report = run_pipeline(tmp_path, on_stage=_stage_cb)
    except Exception as e:
        log.error("Pipeline error on %s: %s", message_id, e)
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    verdict = report.get("verdict", "low_confidence")
    score   = report.get("combined_score", 0.0)

    # Pretty log line
    verdict_display = {
        "malicious":      "🔴 MALICIOUS",
        "suspicious":     "🟠 SUSPICIOUS",
        "benign":         "✅ CLEAN",
        "low_confidence": "⚪ LOW CONFIDENCE",
    }.get(verdict, verdict.upper())

    log.info("  ➜ Verdict: %s  (score: %.2f)  —  %s", verdict_display, score, subject)

    # Apply Gmail label & unspam so it shows under user's sidebar label filters
    label_id = verdict_to_label_id.get(verdict)
    if label_id and not dry_run:
        from gmail_labels import apply_label
        apply_label(service, message_id, label_id, list(verdict_to_label_id.values()), unspam=True)
        log.info("  ✉  Label applied to message in Gmail (unspammed if in SPAM).")
        # Send thread note with clickable HTML report link
        _send_thread_report_note(service, message_id, report, run_id)
    elif dry_run:
        log.info("  [dry-run] Would apply label '%s'", verdict_to_label_id.get(verdict, "none"))

    # Record scan in reports/ and history.json
    _record_scan(run_id, message_id, report, sender, subject)

    return report


def run_watcher(dry_run: bool = False):
    """Main poll loop. Runs indefinitely until Ctrl+C."""
    from gmail_auth import build_service
    from gmail_labels import ensure_labels

    log.info("═" * 60)
    log.info("  PhishTrap Gmail Watcher starting...")
    log.info("  Poll interval : %ds", POLL_INTERVAL_SECONDS)
    log.info("  Dry run       : %s", dry_run)
    log.info("═" * 60)

    service = build_service()

    # Get the authenticated user's email address
    profile = service.users().getProfile(userId="me").execute()
    log.info("Authenticated as: %s", profile.get("emailAddress"))

    # Ensure PhishTrap labels exist in Gmail
    log.info("Ensuring Gmail labels exist...")
    verdict_to_label_id = ensure_labels(service)
    label_ids_set = set(verdict_to_label_id.values())
    log.info("Labels ready: %s", verdict_to_label_id)

    # Load the set of already-scanned message IDs
    seen = _load_seen()
    log.info("Loaded %d previously seen message IDs.", len(seen))

    log.info("Watching Inbox & Spam folders for new emails... (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                ids = _get_recent_message_ids(service)
                new_ids = [mid for mid in ids if mid not in seen]

                to_scan = []
                for mid in new_ids:
                    try:
                        meta = service.users().messages().get(
                            userId="me", id=mid, format="minimal"
                        ).execute()
                        m_labels = set(meta.get("labelIds", []))
                        if m_labels.intersection(label_ids_set):
                            # Message already has a PhishTrap label
                            seen.add(mid)
                        else:
                            to_scan.append(mid)
                    except Exception as e:
                        log.warning("Could not check labels for %s: %s", mid, e)
                        to_scan.append(mid)

                if to_scan:
                    log.info("Found %d unscanned message(s) to process.", len(to_scan))
                    for mid in to_scan:
                        scan_message(service, mid, verdict_to_label_id, dry_run=dry_run)
                        seen.add(mid)
                        _save_seen(seen)
                else:
                    log.info("Inbox up to date. Next check in %ds.", POLL_INTERVAL_SECONDS)

            except Exception as e:
                log.warning("Error during poll cycle: %s. Reconnecting in %ds...", e, POLL_INTERVAL_SECONDS)
                try:
                    service = build_service()
                except Exception as reb_err:
                    log.warning("Could not rebuild Gmail service: %s", reb_err)

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        log.info("\nWatcher stopped by user.")


def run_scan_last(n: int, dry_run: bool = False):
    """Scans the last N messages in Inbox (for testing, ignores seen list)."""
    from gmail_auth import build_service
    from gmail_labels import ensure_labels

    log.info("═" * 60)
    log.info("  PhishTrap: scanning last %d inbox messages (test mode)", n)
    log.info("═" * 60)

    service = build_service()
    verdict_to_label_id = ensure_labels(service)
    ids = _get_all_inbox_ids(service, max_results=n)

    if not ids:
        log.info("No messages found.")
        return

    for mid in ids:
        scan_message(service, mid, verdict_to_label_id, dry_run=dry_run)

    log.info("Done. Scanned %d message(s).", len(ids))


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishTrap Gmail Watcher")
    parser.add_argument(
        "--auth-only", action="store_true",
        help="Just do the browser OAuth login flow and exit."
    )
    parser.add_argument(
        "--scan-last", type=int, default=0, metavar="N",
        help="Scan the last N inbox messages and exit (for testing)."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Analyze but don't apply labels to Gmail."
    )
    args = parser.parse_args()

    os.makedirs("uploads", exist_ok=True)

    if args.auth_only:
        from gmail_auth import get_credentials
        get_credentials(auth_only=True)
        sys.exit(0)

    if args.scan_last > 0:
        run_scan_last(args.scan_last, dry_run=args.dry_run)
    else:
        run_watcher(dry_run=args.dry_run)
