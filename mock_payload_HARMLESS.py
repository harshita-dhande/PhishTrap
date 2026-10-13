"""
mock_payload_HARMLESS.py
The demo "malware" -- entirely harmless. Writes one flag file to the
Desktop and makes one outbound HTTP request to a real, safe test endpoint
(NOT a raw ping to a DNS resolver, which won't complete an HTTP request).

Compile this into an .exe on the Windows Victim VM:
    pip install pyinstaller requests
    pyinstaller --onefile mock_payload_HARMLESS.py

The resulting dist/mock_payload_HARMLESS.exe is what gets zipped and
password-protected by generate_lure.py.
"""

import os
import urllib.request

desktop = os.path.join(os.environ["USERPROFILE"], "Desktop")
flag_file = os.path.join(desktop, "YOU_HAVE_BEEN_COMPROMISED.txt")

with open(flag_file, "w") as f:
    f.write("PhishTrap Execution Successful. This is a harmless test payload.")

try:
    # httpbin.org/get is a real, safe test endpoint that just echoes the
    # request back -- this actually completes (or times out safely if the
    # Victim VM is airgapped, which is expected and fine for the demo).
    urllib.request.urlopen("http://httpbin.org/get", timeout=2)
except Exception:
    pass  # airgapped network blocking this is expected behavior, not a bug
