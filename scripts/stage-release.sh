#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $(basename "$0") <version> [--force]" >&2
  exit 1
fi

VERSION="$1"
FORCE=0
if [[ ${2:-} == "--force" ]]; then
  FORCE=1
elif [[ $# -eq 2 ]]; then
  echo "usage: $(basename "$0") <version> [--force]" >&2
  exit 1
fi

if [[ "${VERSION}" != v* ]]; then
  VERSION="v${VERSION}"
fi

OUT_DIR="${DIST_DIR}/${VERSION}"

if [[ -d "${OUT_DIR}" ]]; then
  if [[ ${FORCE} -ne 1 ]]; then
    echo "[stage-release] output directory already exists: ${OUT_DIR}" >&2
    echo "[stage-release] rerun with --force to replace it" >&2
    exit 1
  fi
  rm -rf "${OUT_DIR}"
fi

mkdir -p "${OUT_DIR}"

copy_if_exists() {
  local src="$1"
  if [[ -e "${src}" ]]; then
    cp -R "${src}" "${OUT_DIR}/"
  fi
}

copy_if_exists "${DIST_DIR}/CryptEX_macos_arm64_bundle.zip"
copy_if_exists "${DIST_DIR}/cryptexd_macos_arm64"
copy_if_exists "${DIST_DIR}/cryptex_tests_macos_arm64"
copy_if_exists "${DIST_DIR}/cryptex_powminer_macos_arm64"
copy_if_exists "${DIST_DIR}/cryptexqt_macos_arm64.app"

copy_if_exists "${DIST_DIR}/cryptexd_linux_x86_64"
copy_if_exists "${DIST_DIR}/cryptex_tests_linux_x86_64"
copy_if_exists "${DIST_DIR}/cryptex_powminer_linux_x86_64"
copy_if_exists "${DIST_DIR}/cryptexqt_linux_x86_64"
copy_if_exists "${DIST_DIR}/cryptexqt_linux_x86_64.AppImage"

copy_if_exists "${DIST_DIR}/cryptexd_linux_arm64"
copy_if_exists "${DIST_DIR}/cryptex_tests_linux_arm64"
copy_if_exists "${DIST_DIR}/cryptex_powminer_linux_arm64"
copy_if_exists "${DIST_DIR}/cryptexqt_linux_arm64"
copy_if_exists "${DIST_DIR}/cryptexqt_linux_arm64.AppImage"

copy_if_exists "${DIST_DIR}/CryptEX_windows_x86_64_bundle.zip"
copy_if_exists "${DIST_DIR}/cryptexd_windows_x86_64.exe"
copy_if_exists "${DIST_DIR}/cryptex_tests_windows_x86_64.exe"
copy_if_exists "${DIST_DIR}/cryptex_powminer_windows_x86_64.exe"
copy_if_exists "${DIST_DIR}/cryptexqt_windows_x86_64.exe"

(
  cd "${OUT_DIR}"
  rm -f SHA256SUMS.txt
  find . -maxdepth 1 -mindepth 1 -type f -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS.txt
)

echo "[stage-release] staged release assets in ${OUT_DIR}"
