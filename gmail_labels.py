"""
gmail_labels.py
Creates and manages the PhishTrap label hierarchy in Gmail.

Labels created:
    PhishTrap/🔴 Malicious   — verdict=malicious
    PhishTrap/🟠 Suspicious  — verdict=suspicious
    PhishTrap/✅ Clean        — verdict=benign or low_confidence

Called automatically by gmail_watcher.py on startup.
Safe to run multiple times — won't duplicate existing labels.
"""

import logging

log = logging.getLogger(__name__)

# Map from pipeline verdict -> Gmail label name
VERDICT_LABEL_MAP = {
    "malicious":       "PhishTrap/🔴 Malicious",
    "suspicious":      "PhishTrap/🟠 Suspicious",
    "benign":          "PhishTrap/✅ Clean",
    "low_confidence":  "PhishTrap/🟠 Suspicious",
}

# Background colors for each label (Gmail label color hex codes)
LABEL_COLORS = {
    "PhishTrap/🔴 Malicious":  {"backgroundColor": "#cc3a21", "textColor": "#ffffff"},
    "PhishTrap/🟠 Suspicious": {"backgroundColor": "#e07218", "textColor": "#ffffff"},
    "PhishTrap/✅ Clean":       {"backgroundColor": "#0d804d", "textColor": "#ffffff"},
}


def _get_existing_labels(service) -> dict[str, str]:
    """Returns {label_name: label_id} for all existing labels."""
    result = service.users().labels().list(userId="me").execute()
    return {lbl["name"]: lbl["id"] for lbl in result.get("labels", [])}


def ensure_labels(service) -> dict[str, str]:
    """
    Creates PhishTrap labels in Gmail if they don't already exist.
    Returns {verdict -> label_id} dict used by the watcher to apply labels.
    """
    existing = _get_existing_labels(service)
    verdict_to_id: dict[str, str] = {}

    # Build the set of unique label names we need
    needed_labels = set(VERDICT_LABEL_MAP.values())

    for label_name in needed_labels:
        if label_name in existing:
            label_id = existing[label_name]
            log.info("Label already exists: '%s' (%s)", label_name, label_id)
        else:
            # Create it
            body = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }
            color = LABEL_COLORS.get(label_name)
            if color:
                body["color"] = color

            try:
                created = service.users().labels().create(userId="me", body=body).execute()
                label_id = created["id"]
                log.info("Created label: '%s' (%s)", label_name, label_id)
                print(f"  [labels] Created Gmail label: {label_name}")
            except Exception as e:
                log.warning("Could not create label '%s': %s", label_name, e)
                continue

        # Map every verdict string that points to this label
        for verdict, target_name in VERDICT_LABEL_MAP.items():
            if target_name == label_name:
                verdict_to_id[verdict] = label_id

    return verdict_to_id


def apply_label(service, message_id: str, label_id: str, all_label_ids: list[str] = None, unspam: bool = True) -> None:
    """
    Applies a verdict label to a Gmail message, removes conflicting PhishTrap labels,
    and if the email is in SPAM, removes the SPAM label so it is visible in Gmail's label views.
    """
    try:
        add_ids = [label_id]
        remove_ids = []
        if all_label_ids:
            remove_ids.extend([lid for lid in all_label_ids if lid != label_id])

        if unspam:
            # Check if message has SPAM label
            meta = service.users().messages().get(userId="me", id=message_id, format="minimal").execute()
            if "SPAM" in meta.get("labelIds", []):
                remove_ids.append("SPAM")
                add_ids.append("INBOX")

        body = {"addLabelIds": add_ids}
        if remove_ids:
            body["removeLabelIds"] = list(set(remove_ids))

        service.users().messages().modify(
            userId="me",
            id=message_id,
            body=body,
        ).execute()
    except Exception as e:
        log.warning("Could not apply label %s to message %s: %s", label_id, message_id, e)


if __name__ == "__main__":
    # Quick standalone test — just lists existing labels
    from gmail_auth import build_service
    svc = build_service()
    existing = _get_existing_labels(svc)
    print("Existing Gmail labels:")
    for name, lid in sorted(existing.items()):
        print(f"  {lid}  {name}")
