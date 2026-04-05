#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

detect_public_ip() {
  curl -fsS http://ifconfig.me/ip 2>/dev/null || curl -fsS https://api.ipify.org 2>/dev/null || true
}

detect_local_ip() {
  ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true
}

HOST="${CRYPTEX_SITE_HOST:-0.0.0.0}"
PORT="${CRYPTEX_SITE_PORT:-8080}"
if [[ -z "${CRYPTEX_SITE_URL:-}" ]]; then
  export CRYPTEX_SITE_URL="http://cryptexorg.duckdns.org:${PORT}"
fi
if [[ -z "${CRYPTEX_ALLOWED_HOSTS:-}" ]]; then
  LOCAL_IP="$(detect_local_ip)"
  PUBLIC_IP_FOR_HOSTS="${CRYPTEX_SITE_PUBLIC_IP:-auto}"
  if [[ "${PUBLIC_IP_FOR_HOSTS}" == "auto" ]]; then
    PUBLIC_IP_FOR_HOSTS="$(detect_public_ip)"
  fi
  HOSTS="cryptexorg.duckdns.org,localhost,127.0.0.1"
  if [[ -n "${LOCAL_IP}" ]]; then
    HOSTS="${HOSTS},${LOCAL_IP}"
  fi
  if [[ -n "${PUBLIC_IP_FOR_HOSTS}" ]]; then
    HOSTS="${HOSTS},${PUBLIC_IP_FOR_HOSTS}"
  fi
  export CRYPTEX_ALLOWED_HOSTS="${HOSTS}"
fi
RELOAD_ARGS=()
if [[ "${CRYPTEX_SITE_RELOAD:-1}" == "1" ]]; then
  RELOAD_ARGS=(--reload)
fi
echo "CryptEX website listening on ${HOST}:${PORT}"
echo "Public site URL: ${CRYPTEX_SITE_URL}"
PUBLIC_IP="${CRYPTEX_SITE_PUBLIC_IP:-auto}"
if [[ "${PUBLIC_IP}" == "auto" ]]; then
  PUBLIC_IP="$(detect_public_ip)"
fi
LOCAL_IP="$(detect_local_ip)"
if [[ -n "${PUBLIC_IP}" ]]; then
  echo "Detected public IP: ${PUBLIC_IP}"
fi
if [[ -n "${LOCAL_IP}" ]]; then
  echo "Detected local IP: ${LOCAL_IP}"
fi
echo "Allowed hosts: ${CRYPTEX_ALLOWED_HOSTS}"
exec "${ROOT_DIR}/.venv/bin/uvicorn" app.main:app \
  --app-dir "${ROOT_DIR}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --no-server-header \
  --no-date-header \
  "${RELOAD_ARGS[@]}"
