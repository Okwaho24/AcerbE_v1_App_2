#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$HOME/AcerbE_repo"
PID_FILE="$REPO_DIR/data/acerbe_pipeline.pid"
DAEMON_SCRIPT="$REPO_DIR/scripts/run_background_daemon.sh"

# Acquire Android wake lock to prevent CPU suspension
if command -v termux-wake-lock &> /dev/null; then
    termux-wake-lock
    echo "[*] Termux wake lock acquired."
fi

while true; do
    if [ -f "$PID_FILE" ]; then
        PID="$(cat "$PID_FILE")"
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "[!] Watchdog detected pipeline crash (PID $PID dead). Restarting..."
            rm -f "$PID_FILE"
            bash "$DAEMON_SCRIPT"
        fi
    else
        echo "[!] Watchdog detected missing PID file. Starting pipeline..."
        bash "$DAEMON_SCRIPT"
    fi
    sleep 30
done
