"""
Shared configuration for the PhishTrap pipeline.
Edit these values to match your VM setup.
"""

# --- Ollama (running on the Ubuntu Controller VM) ---
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3"

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
