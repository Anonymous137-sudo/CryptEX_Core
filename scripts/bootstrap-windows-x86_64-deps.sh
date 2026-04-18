#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CRYPTEX_WINDOWS_X86_64_PREFIX:-${ROOT_DIR}/third_party/windows-x86_64}"
SRC_DIR="${PREFIX}/src"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.1}"
OPUS_VERSION="${OPUS_VERSION:-1.5.2}"
OPENSSL_PREFIX="${PREFIX}/openssl"
OPUS_PREFIX="${PREFIX}/opus"
OPENSSL_TARBALL="${SRC_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
OPUS_TARBALL="${SRC_DIR}/opus-${OPUS_VERSION}.tar.gz"
OPENSSL_SRC="${SRC_DIR}/openssl-${OPENSSL_VERSION}"
OPUS_SRC="${SRC_DIR}/opus-${OPUS_VERSION}"
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      ;;
    *)
      echo "usage: $(basename "$0") [--force]" >&2
      exit 1
      ;;
  esac
  shift
done

cpu_count() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu 2>/dev/null && return 0
  fi
  if command -v nproc >/dev/null 2>&1; then
    nproc && return 0
  fi
  echo 4
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[bootstrap-win-x64] missing required tool: $1" >&2
    exit 1
  fi
}

download_if_missing() {
  local url="$1"
  local dest="$2"
  if [[ ! -f "${dest}" ]]; then
    echo "[bootstrap-win-x64] downloading $(basename "${dest}")"
    curl -L --fail --retry 3 "${url}" -o "${dest}"
  fi
}

require_tool curl
require_tool tar
require_tool make
require_tool x86_64-w64-mingw32-gcc
require_tool x86_64-w64-mingw32-g++

mkdir -p "${SRC_DIR}"

download_if_missing "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_TARBALL}"
download_if_missing "https://archive.mozilla.org/pub/opus/opus-${OPUS_VERSION}.tar.gz" "${OPUS_TARBALL}"

if [[ ! -d "${OPENSSL_SRC}" ]]; then
  tar -xzf "${OPENSSL_TARBALL}" -C "${SRC_DIR}"
fi

if [[ ! -d "${OPUS_SRC}" ]]; then
  tar -xzf "${OPUS_TARBALL}" -C "${SRC_DIR}"
fi

echo "[bootstrap-win-x64] building OpenSSL ${OPENSSL_VERSION}"
if [[ ${FORCE} -eq 1 || ! -f "${OPENSSL_PREFIX}/lib64/libcrypto.a" ]]; then
  rm -rf "${OPENSSL_PREFIX}"
  (
    cd "${OPENSSL_SRC}"
    make distclean >/dev/null 2>&1 || true
    ./Configure mingw64 no-tests no-shared no-quic \
      --cross-compile-prefix=x86_64-w64-mingw32- \
      --prefix="${OPENSSL_PREFIX}"
    make -j"$(cpu_count)" >/dev/null
    make install_sw >/dev/null
  )
else
  echo "[bootstrap-win-x64] reusing existing OpenSSL prefix: ${OPENSSL_PREFIX}"
fi

echo "[bootstrap-win-x64] building Opus ${OPUS_VERSION}"
if [[ ${FORCE} -eq 1 || ! -f "${OPUS_PREFIX}/lib/libopus.a" ]]; then
  rm -rf "${OPUS_PREFIX}"
  (
    cd "${OPUS_SRC}"
    make distclean >/dev/null 2>&1 || true
    ./configure \
      --host=x86_64-w64-mingw32 \
      --prefix="${OPUS_PREFIX}" \
      --disable-shared \
      --enable-static
    make -j"$(cpu_count)" >/dev/null
    make install >/dev/null
  )
else
  echo "[bootstrap-win-x64] reusing existing Opus prefix: ${OPUS_PREFIX}"
fi

cat <<EOF
[bootstrap-win-x64] complete
export OPENSSL_ROOT_DIR_WIN_X86_64="${OPENSSL_PREFIX}"
export OPUS_ROOT_DIR_WIN_X86_64="${OPUS_PREFIX}"
EOF
