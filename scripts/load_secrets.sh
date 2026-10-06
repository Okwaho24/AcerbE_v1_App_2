#!/usr/bin/env bash
set -euo pipefail

# Zero Trust: Ensure umask protects any temporary credential files
umask 077

SECRET_STORE="$HOME/.acerbe_vault"
mkdir -p "$SECRET_STORE"
chmod 0700 "$SECRET_STORE"

KEY_FILE="$SECRET_STORE/signing.key"

if [ ! -f "$KEY_FILE" ]; then
    echo "[*] Initializing new ephemeral HMAC signing key..."
    openssl rand -hex 32 > "$KEY_FILE"
    chmod 0600 "$KEY_FILE"
fi

# Export key into current session environment
export ACERBE_SIGNING_KEY="$(cat "$KEY_FILE")"
export PAYMENT_RPC_ENDPOINT="http://localhost:3000/settlements"
export PAYMENT_API_TOKEN="prod_secure_token_xyz789"

echo "[✔] Secure environment credentials loaded into runtime memory."
