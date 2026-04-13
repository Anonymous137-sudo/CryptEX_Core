#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build-release/windows-x86_64}"
OUT_DIR="${2:-${ROOT_DIR}/dist/CryptEX_windows_x86_64_bundle}"
QT_ROOT="${QT6_ROOT_WIN_X86_64:-${HOME}/Qt/6.10.2/mingw_64}"

cache_value() {
  local key="$1"
  local cache="${BUILD_DIR}/CMakeCache.txt"
  if [[ ! -f "${cache}" ]]; then
    return 0
  fi
  sed -n "s/^${key}:[^=]*=//p" "${cache}" | head -n 1
}

OPENSSL_ROOT="${OPENSSL_ROOT_DIR_WIN_X86_64:-$(cache_value OPENSSL_ROOT_DIR)}"
OPUS_ROOT="${OPUS_ROOT_DIR_WIN_X86_64:-$(cache_value OPUS_ROOT_DIR)}"

detect_mingw_bin() {
  for candidate in \
    "$(command -v x86_64-w64-mingw32-g++ 2>/dev/null || true)" \
    "$(command -v x86_64-w64-mingw32-g++-posix 2>/dev/null || true)" \
    "$(command -v x86_64-w64-mingw32-gcc 2>/dev/null || true)" \
    "$(command -v x86_64-w64-mingw32-gcc-posix 2>/dev/null || true)"; do
    if [[ -n "${candidate}" ]]; then
      dirname "${candidate}"
      return 0
    fi
  done
  return 1
}

MINGW_BIN="${MINGW_W64_BIN_WIN_X86_64:-$(detect_mingw_bin || true)}"

if [[ ! -d "${BUILD_DIR}" ]]; then
  echo "[package-win] build directory not found: ${BUILD_DIR}" >&2
  exit 1
fi

if [[ ! -d "${QT_ROOT}" ]]; then
  echo "[package-win] Qt root not found: ${QT_ROOT}" >&2
  exit 1
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

copy_required() {
  local src="$1"
  local dst="$2"
  if [[ ! -f "${src}" ]]; then
    echo "[package-win] missing required file: ${src}" >&2
    exit 1
  fi
  cp "${src}" "${dst}"
}

copy_optional_glob() {
  local pattern="$1"
  local dst_dir="$2"
  local matched=0
  shopt -s nullglob
  for file in ${pattern}; do
    cp "${file}" "${dst_dir}/"
    matched=1
  done
  shopt -u nullglob
  return ${matched}
}

copy_tree_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -d "${src}" ]]; then
    mkdir -p "${dst}"
    cp -R "${src}/." "${dst}/"
  fi
}

copy_required "${BUILD_DIR}/cryptexqt_win32.exe" "${OUT_DIR}/cryptexqt_win32.exe"
copy_required "${BUILD_DIR}/cryptexd_win32.exe" "${OUT_DIR}/cryptexd_win32.exe"
copy_required "${BUILD_DIR}/cryptex_tests.exe" "${OUT_DIR}/cryptex_tests.exe"
copy_required "${BUILD_DIR}/cryptex_powminer_win32.exe" "${OUT_DIR}/cryptex_powminer_win32.exe"

# Copy the broad Qt runtime set to avoid missing transitive DLLs at launch time.
copy_optional_glob "${QT_ROOT}/bin/*.dll" "${OUT_DIR}" || true

# Copy compiler/runtime DLLs from the active mingw toolchain if available.
if [[ -n "${MINGW_BIN}" && -d "${MINGW_BIN}" ]]; then
  copy_optional_glob "${MINGW_BIN}/*.dll" "${OUT_DIR}" || true
fi

# OpenSSL and Opus are not always inside the Qt prefix.
if [[ -n "${OPENSSL_ROOT}" && -d "${OPENSSL_ROOT}" ]]; then
  copy_optional_glob "${OPENSSL_ROOT}/bin/*.dll" "${OUT_DIR}" || true
fi
if [[ -n "${OPUS_ROOT}" && -d "${OPUS_ROOT}" ]]; then
  copy_optional_glob "${OPUS_ROOT}/bin/*.dll" "${OUT_DIR}" || true
fi

copy_tree_if_exists "${QT_ROOT}/plugins" "${OUT_DIR}/plugins"

cat > "${OUT_DIR}/qt.conf" <<'EOF'
[Paths]
Plugins = plugins
EOF

cat > "${OUT_DIR}/README.txt" <<'EOF'
CryptEX Windows Runtime Bundle
==============================

Contents
- cryptexqt_win32.exe : Qt GUI client
- cryptexd_win32.exe  : backend / node / RPC daemon
- cryptex_tests.exe   : test binary
- cryptex_powminer_win32.exe : external SHA3-512 PoW worker

How to launch
1. Start cryptexqt_win32.exe
2. The GUI will auto-discover cryptexd_win32.exe in the same folder
3. The GUI can launch the backend for you
4. Mining uses cryptex_powminer_win32.exe from the same folder

Notes
- Keep the plugins directory and DLLs beside the executables
- This bundle intentionally includes the broad Qt/runtime DLL set to reduce missing-dependency crashes on clean Windows systems
EOF

(
  cd "$(dirname "${OUT_DIR}")"
  rm -f "$(basename "${OUT_DIR}").zip"
  zip -qry "$(basename "${OUT_DIR}").zip" "$(basename "${OUT_DIR}")"
)

echo "[package-win] created bundle: ${OUT_DIR}"
echo "[package-win] created archive: ${OUT_DIR}.zip"
