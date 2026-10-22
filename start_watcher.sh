#!/bin/bash
# start_watcher.sh
# Starts PhishTrap web dashboard + Gmail watcher in one shot.
# Usage: ./start_watcher.sh
#
# To stop: press Ctrl+C in each terminal, or `kill $(cat .phishtrap.pids)`

set -e
cd "$(dirname "$0")"   # always run from the PhishTrap directory

echo "╔══════════════════════════════════════╗"
echo "║       PhishTrap — Starting Up        ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Check credentials ──────────────────────────────────────────
if [ ! -f "credentials.json" ]; then
  echo "❌  credentials.json not found!"
  echo "    Download it from Google Cloud Console and place it here."
  exit 1
fi

if [ ! -f "token.json" ]; then
  echo "⚠️   token.json not found — running one-time browser auth first..."
  python3 gmail_watcher.py --auth-only
  echo ""
fi

# ── 2. Clean up any stale instances & start FastAPI dashboard ─────
if [ -f ".phishtrap.pids" ]; then
  kill $(cat .phishtrap.pids) 2>/dev/null || true
  rm -f .phishtrap.pids
fi
lsof -ti:8080 | xargs kill -9 2>/dev/null || true

echo "🌐  Starting PhishTrap web dashboard on http://127.0.0.1:8080 ..."
python3 -m uvicorn app:app --host 127.0.0.1 --port 8080 --log-level warning &
UVICORN_PID=$!
echo "    PID: $UVICORN_PID"
sleep 1

# ── 3. Start Gmail watcher in background ─────────────────────────
echo "📧  Starting Gmail watcher (polling every 60s)..."
python3 gmail_watcher.py &
WATCHER_PID=$!
echo "    PID: $WATCHER_PID"

# ── 4. Save PIDs for easy kill ─────────────────────────────────────
echo "$UVICORN_PID $WATCHER_PID" > .phishtrap.pids

echo ""
echo "══════════════════════════════════════════"
echo "✅  PhishTrap is running!"
echo "    Dashboard : http://127.0.0.1:8080"
echo "    Gmail     : watching Inbox every 60s"
echo ""
echo "    To stop   : kill \$(cat .phishtrap.pids)"
echo "    Or press  : Ctrl+C"
echo "══════════════════════════════════════════"

# Keep the script alive so Ctrl+C kills both children
wait $UVICORN_PID $WATCHER_PID
