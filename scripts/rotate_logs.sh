#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="$HOME/AcerbE_repo/data/logs"
STAMP_DIR="$HOME/AcerbE_repo/data/stamps"
RETENTION_DAYS=30

echo "[*] Starting AcerbE storage maintenance and rotation..."

# Rotate and compress NDJSON logs older than 1 day
if [ -d "$LOG_DIR" ]; then
    find "$LOG_DIR" -name "*.ndjson" -mmin +1440 -exec gzip {} \;
    # Purge compressed logs older than retention period
    find "$LOG_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete
fi

# Enforce strict permissions on active storage
chmod 0700 "$STAMP_DIR" 2>/dev/null || true
chmod 0600 "$STAMP_DIR"/*.json 2>/dev/null || true

echo "[✔] Storage maintenance completed successfully."
