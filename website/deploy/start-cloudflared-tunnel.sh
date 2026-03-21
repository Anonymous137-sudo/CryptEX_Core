#!/usr/bin/env bash
set -euo pipefail

if ! command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared is not installed. Install it first with: brew install cloudflared"
  exit 1
fi

TARGET_URL="${1:-http://127.0.0.1:8080}"
ORIGIN_HOST_HEADER="${CRYPTEX_TUNNEL_HOST_HEADER:-cryptexorg.duckdns.org}"
echo "Starting Cloudflared quick tunnel"
echo "Origin URL: ${TARGET_URL}"
echo "Origin Host header: ${ORIGIN_HOST_HEADER}"
exec cloudflared tunnel --no-autoupdate --url "${TARGET_URL}" --http-host-header "${ORIGIN_HOST_HEADER}"
