"""
Stage 4 — Dynamic Unpacking

Attempts to unlock a password-protected zip using whatever password
the AI extraction stage returned. Never checks against a fixed/expected
value — a wrong or missing password is a legitimate outcome (extraction
failed), not something to work around.

Run standalone:
    python unzip_payload.py demo_artifacts/invoice.zip hacked2026
"""

import os
import sys
import pyzipper

from config import EXTRACT_DIR


def unlock_zip(zip_path: str, password: str | None, extract_dir: str = EXTRACT_DIR) -> dict:
    """
    Returns {"success": bool, "extracted_files": [...], "error": str or None}
    """
    if not password:
        return {"success": False, "extracted_files": [], "error": "no password provided"}

    if not os.path.exists(zip_path):
        return {"success": False, "extracted_files": [], "error": f"zip not found: {zip_path}"}

    os.makedirs(extract_dir, exist_ok=True)

    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.setpassword(password.encode())
            names = zf.namelist()
            zf.extractall(path=extract_dir)
        extracted_paths = [os.path.join(extract_dir, n) for n in names]
        return {"success": True, "extracted_files": extracted_paths, "error": None}
    except RuntimeError as e:
        # pyzipper raises RuntimeError on bad password
        return {"success": False, "extracted_files": [], "error": f"unlock failed: {e}"}
    except Exception as e:
        return {"success": False, "extracted_files": [], "error": f"unexpected error: {e}"}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python unzip_payload.py <zip-path> <password>")
        sys.exit(1)

    result = unlock_zip(sys.argv[1], sys.argv[2])
#    print(result)
# try_unzip = unlock_zip
def try_unzip(zip_bytes, password):
    import os
    # 1. Save the raw bytes to a physical file
    temp_path = "temp_payload.zip"
    with open(temp_path, "wb") as f:
        f.write(zip_bytes)
        
    # 2. Call your original function with the correct file path
    res = unlock_zip(temp_path, password)
    
    # 3. Format the results exactly how the orchestrator expects
    if res.get("success"):
        files = res.get("extracted_files", [])
        extracted_path = files[0] if files else None
        return {"success": True, "extracted_path": extracted_path, "error": None}
    else:
        return {"success": False, "extracted_path": None, "error": res.get("error")}
