"""
Shared configuration for the PhishTrap pipeline.
Edit these values to match your VM setup.
"""

# --- Ollama (running locally on Mac / Ubuntu Controller) ---
OLLAMA_URL = "http://localhost:11434/api/generate"
# On this Mac, llama3 is installed and running. If on Ubuntu VM, change to phi3 or desired model.
OLLAMA_MODEL = "llama3:latest"

# --- Safe Local Testing (Bypass VM Sandbox Detonation) ---
# When True, detonate() will safely skip calling the Windows VM sandbox.
# Absolutely NO payload is executed and NO compromise files are dropped on your Mac.
DISABLE_DETONATION = True

# --- Windows Victim VM execution agent ---
# Replace with the actual IP of your Windows VM (find via `ipconfig` on Windows)
WINDOWS_AGENT_URL = "http://192.168.64.5:5000/execute"

# --- Working directories ---
EXTRACT_DIR = "extracted"          # where unzipped payloads go
REPUTATION_FILE = "sender_reputation.json"
HISTORY_FILE = "history.json"

# --- Thresholds ---
CONFIDENCE_ESCALATION_THRESHOLD = 0.6   # below this -> "escalate to analyst" instead of hard verdict
RISK_SCORE_MALICIOUS_THRESHOLD = 60     # 0-100 scale
