#!/usr/bin/env bash
set -euo pipefail

# Zero Trust: Enforce strict umask so all created logs/stamps are user-private (0600/0700)
umask 0077

REPO_DIR="$HOME/AcerbE_repo"
cd "$REPO_DIR"

# Load local environment or export defaults
export PAYMENT_RPC_ENDPOINT="${PAYMENT_RPC_ENDPOINT:-http://localhost:3000/settlements}"
export PAYMENT_API_TOKEN="${PAYMENT_API_TOKEN:-mock_token}"
export ACERBE_SIGNING_KEY="${ACERBE_SIGNING_KEY:-local_secure_test_key_abc123}"
export POLL_INTERVAL_MS="${POLL_INTERVAL_MS:-5000}"

LOG_DIR="$REPO_DIR/data/logs"
mkdir -p "$LOG_DIR"
chmod 0700 "$LOG_DIR"

PID_FILE="$REPO_DIR/data/acerbe_pipeline.pid"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[!] AcerbE pipeline is already running under PID $(cat "$PID_FILE")"
    exit 1
fi

echo "[*] Starting AcerbE Forensic Pipeline in Termux background mode..."
nohup node scripts/run_fulfillment_pipeline.js > "$LOG_DIR/pipeline_stdout.ndjson" 2>&1 &

echo $! > "$PID_FILE"
echo "[✔] Pipeline daemon started successfully. PID: $(cat "$PID_FILE")"
echo "[*] Monitoring logs via: tail -f $LOG_DIR/pipeline_stdout.ndjson"
