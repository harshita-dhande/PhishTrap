#!/bin/bash
# setup_controller.sh
# Run this ONCE on the Ubuntu Controller VM, only while its network mode
# is temporarily set to "Shared Network" in UTM (see PHASE0_SETUP.md).
# Switch back to "Host Only" as soon as this finishes.

set -e  # stop immediately if any command fails, rather than limping onward

echo "=== Updating apt and installing base packages ==="
sudo apt update
sudo apt install -y python3-pip python3-venv git curl

echo "=== Installing Ollama (local LLM runtime) ==="
curl -fsSL https://ollama.com/install.sh | sh

echo "=== Pulling the phi3 model (this may take a while) ==="
ollama pull phi3

echo "=== Installing Python dependencies ==="
pip install --break-system-packages \
    easyocr \
    pyzipper \
    requests \
    fastapi \
    uvicorn \
    "websockets<12" \
    Pillow \
    pypdf \
    fpdf2

echo ""
echo "=== Done. ==="
echo "Now switch UTM's Network mode for this VM back to 'Host Only',"
echo "reboot, and confirm 'ping 8.8.8.8' fails before continuing."
