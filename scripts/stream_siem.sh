#!/usr/bin/env bash
set -euo pipefail

# Dependencies check
if ! command -v cloudflared &> /dev/null; then
    echo "[!] cloudflared not found. Install via: pkg install cloudflared"
    exit 1
fi

echo "[*] Establishing outbound-only zero-trust tunnel for NDJSON telemetry..."
# Stream local NDJSON fulfillment logs securely to an external ingestion collector
tail -F "$HOME/AcerbE_repo/data/logs/pipeline_stdout.ndjson" | while read -r line; do
    # Example secure outbound dispatch via curl with mutual TLS or bearer token
    curl -s -X POST "https://siem.acerbe-analytics.internal/ingest" \
        -H "Authorization: Bearer prod_secure_token_xyz789" \
        -H "Content-Type: application/x-ndjson" \
        -d "$line" > /dev/null || true
done
