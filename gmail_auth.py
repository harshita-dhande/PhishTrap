"""
gmail_auth.py
Handles OAuth2 authentication with the Gmail API.

On first run: opens a browser window for you to log in and grant permissions.
On subsequent runs: silently reuses the saved token.json.

Scopes requested:
    gmail.readonly       — read emails and fetch attachments
    gmail.modify         — apply/create labels on messages
    gmail.labels         — list and manage labels
"""

import os
import logging

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

log = logging.getLogger(__name__)

# The exact scopes PhishTrap needs.
# If you change these, delete token.json and re-authorize.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.json"


def _load_or_refresh_creds() -> Credentials | None:
    """Loads token.json if it exists and refreshes if expired."""
    if not os.path.exists(TOKEN_FILE):
        return None
    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if creds.valid:
        return creds
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save_token(creds)
            return creds
        except Exception as e:
            log.warning("Token refresh failed: %s — will re-authorize", e)
    return None


def _save_token(creds: Credentials) -> None:
    with open(TOKEN_FILE, "w") as f:
        f.write(creds.to_json())
    log.info("Saved token to %s", TOKEN_FILE)


def get_credentials(auth_only: bool = False) -> Credentials:
    """
    Returns valid OAuth2 credentials. Opens browser if needed.
    Set auth_only=True to just do the login flow and exit.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        raise FileNotFoundError(
            f"'{CREDENTIALS_FILE}' not found in {os.getcwd()}.\n"
            "Download it from Google Cloud Console → APIs & Services → Credentials."
        )

    creds = _load_or_refresh_creds()

    if not creds:
        print("\n[gmail_auth] Opening browser for Gmail authorization...")
        print("[gmail_auth] Select your Gmail account and click 'Allow'.\n")
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0, open_browser=True)
        _save_token(creds)
        print(f"[gmail_auth] ✅ Authorization successful! Saved to {TOKEN_FILE}\n")

    return creds


def build_service():
    """Returns an authorized Gmail API service object."""
    creds = get_credentials()
    service = build("gmail", "v1", credentials=creds)
    return service


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    auth_only = "--auth-only" in sys.argv
    creds = get_credentials(auth_only=auth_only)
    if auth_only:
        print("Authorization complete. You can now run: python3 gmail_watcher.py")
        sys.exit(0)
    svc = build("gmail", "v1", credentials=creds)
    profile = svc.users().getProfile(userId="me").execute()
    print(f"✅ Authenticated as: {profile.get('emailAddress')}")
    print(f"   Total messages: {profile.get('messagesTotal')}")
