      
"""
detonate.py
Stage 5: sends the extracted .exe to the Windows agent and gets behavior back.

FINAL FIX: read timeout raised from 20s to 35s.
Agent subprocess takes up to 8s + 0.5s sleep + Flask overhead.
20s was too tight. 35s gives comfortable headroom.
"""
import sys
import time
import requests

WINDOWS_AGENT_URL = "http://192.168.128.3:5000/execute"  # update to your Windows VM IP


def detonate(exe_path: str,
             agent_url: str = WINDOWS_AGENT_URL,
             retries: int = 2,
             timeout: int = 40) -> dict:          # was 20, now 35
    try:
        from config import DISABLE_DETONATION
        if DISABLE_DETONATION:
            return {
                "status": "skipped",
                "behavior": "detonation skipped (local Mac safe mode - no payload executed)"
            }
    except Exception:
        pass

    last_error = None
    for attempt in range(1, retries + 1):
        try:
            with open(exe_path, "rb") as f:
                response = requests.post(
                    agent_url,
                    files={"file": f},
                    timeout=timeout,
                )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            last_error = str(e)
            if attempt < retries:
                time.sleep(2)

    return {
        "status":   "error",
        "behavior": f"could not reach Windows agent after {retries} attempt(s): {last_error}"
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detonate.py <path_to_exe>")
        sys.exit(1)
    print(detonate(sys.argv[1]))
