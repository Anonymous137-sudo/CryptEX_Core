#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${ROOT_DIR}/build-release"
DIST_DIR="${ROOT_DIR}/dist"
mkdir -p "${BUILD_ROOT}" "${DIST_DIR}"

built_targets=()
skipped_targets=()

log() {
  printf '[build-matrix] %s\n' "$*"
}

record_built() {
  built_targets+=("$1")
}

record_skipped() {
  skipped_targets+=("$1: $2")
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "${src}" ]]; then
    cp "${src}" "${dst}"
    return 0
  fi
  return 1
}

copy_bundle_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -d "${src}" ]]; then
    rm -rf "${dst}"
    ditto "${src}" "${dst}"
    return 0
  fi
  return 1
}

openssl_is_universal() {
  local root="$1"
  local lib
  for lib in "${root}/lib/libssl.dylib" "${root}/lib/libcrypto.dylib" \
             "${root}/lib/libssl.a" "${root}/lib/libcrypto.a"; do
    [[ -f "${lib}" ]] || continue
    local info
    info="$(lipo -info "${lib}" 2>/dev/null || true)"
    if [[ "${info}" == *"arm64"* && "${info}" == *"x86_64"* ]]; then
      return 0
    fi
  done
  return 1
}

build_macos_arm64() {
  local build_dir="${BUILD_ROOT}/macOS-ARM64"
  cmake -S "${ROOT_DIR}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="arm64" >/dev/null
  cmake --build "${build_dir}" --target cryptexd cryptex_tests cryptexqt -j4 >/dev/null
  cp "${build_dir}/cryptexd_osx" "${DIST_DIR}/cryptexd_macos_arm64"
  cp "${build_dir}/cryptex_tests" "${DIST_DIR}/cryptex_tests_macos_arm64"
  if [[ -d "${build_dir}/cryptexqt_osx.app" ]]; then
    rm -f "${build_dir}/cryptexqt_osx" "${DIST_DIR}/cryptexqt_macos_arm64"
    copy_bundle_if_exists "${build_dir}/cryptexqt_osx.app" "${DIST_DIR}/cryptexqt_macos_arm64.app" || true
  else
    copy_if_exists "${build_dir}/cryptexqt_osx" "${DIST_DIR}/cryptexqt_macos_arm64" || true
  fi
  record_built "macos-arm64"
}

build_macos_universal() {
  local openssl_root="${CRYPTEX_MACOS_UNIVERSAL_OPENSSL_ROOT:-/opt/homebrew/opt/openssl@3}"
  if ! openssl_is_universal "${openssl_root}"; then
    record_skipped "macos-universal" "need universal OpenSSL; set CRYPTEX_MACOS_UNIVERSAL_OPENSSL_ROOT to a universal prefix"
    return 0
  fi
  local build_dir="${BUILD_ROOT}/macos-universal"
  cmake -S "${ROOT_DIR}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
    -DOPENSSL_ROOT_DIR="${openssl_root}" >/dev/null
  cmake --build "${build_dir}" --target cryptexd cryptex_tests cryptexqt -j4 >/dev/null
  cp "${build_dir}/cryptexd_osx" "${DIST_DIR}/cryptexd_macos_universal"
  cp "${build_dir}/cryptex_tests" "${DIST_DIR}/cryptex_tests_macos_universal"
  if [[ -d "${build_dir}/cryptexqt_osx.app" ]]; then
    rm -f "${build_dir}/cryptexqt_osx" "${DIST_DIR}/cryptexqt_macos_universal"
    copy_bundle_if_exists "${build_dir}/cryptexqt_osx.app" "${DIST_DIR}/cryptexqt_macos_universal.app" || true
  else
    copy_if_exists "${build_dir}/cryptexqt_osx" "${DIST_DIR}/cryptexqt_macos_universal" || true
  fi
  record_built "macos-universal"
}

build_windows_x86_64() {
  local openssl_root="${OPENSSL_ROOT_DIR_WIN_X86_64:-}"
  local qt_root="${QT6_ROOT_WIN_X86_64:-}"
  if [[ -z "${openssl_root}" ]]; then
    record_skipped "windows-x86_64" "set OPENSSL_ROOT_DIR_WIN_X86_64 to a Windows x86_64 OpenSSL prefix"
    return 0
  fi
  local build_dir="${BUILD_ROOT}/windows-x86_64"
  cmake -S "${ROOT_DIR}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="${ROOT_DIR}/toolchains/mingw-w64-x86_64.cmake" \
    ${qt_root:+-DCMAKE_PREFIX_PATH="${qt_root}"} \
    ${qt_root:+-DQT_HOST_PATH="/opt/homebrew/opt/qt"} \
    -DOPENSSL_ROOT_DIR="${openssl_root}" >/dev/null
  if [[ -n "${qt_root}" ]]; then
    cmake --build "${build_dir}" --target cryptexd cryptex_tests cryptexqt -j4 >/dev/null
  else
    cmake --build "${build_dir}" --target cryptexd cryptex_tests -j4 >/dev/null
    record_skipped "windows-x86_64-gui" "set QT6_ROOT_WIN_X86_64 to a Qt6 mingw prefix"
  fi
  cp "${build_dir}/cryptexd_win32.exe" "${DIST_DIR}/cryptexd_windows_x86_64.exe"
  cp "${build_dir}/cryptex_tests.exe" "${DIST_DIR}/cryptex_tests_windows_x86_64.exe"
  copy_if_exists "${build_dir}/cryptexqt_win32.exe" "${DIST_DIR}/cryptexqt_windows_x86_64.exe" || true
  record_built "windows-x86_64"
}

build_windows_arm64() {
  local openssl_root="${OPENSSL_ROOT_DIR_WIN_ARM64:-}"
  local qt_root="${QT6_ROOT_WIN_ARM64:-}"
  if [[ -z "${openssl_root}" ]]; then
    record_skipped "windows-arm64" "set OPENSSL_ROOT_DIR_WIN_ARM64 to a Windows ARM64 OpenSSL prefix"
    return 0
  fi
  if [[ -z "${MINGW_W64_ARM64_ROOT:-}" && -z "${LLVM_MINGW_ROOT:-}" ]]; then
    record_skipped "windows-arm64" "set MINGW_W64_ARM64_ROOT or LLVM_MINGW_ROOT to an ARM64 mingw toolchain"
    return 0
  fi
  local build_dir="${BUILD_ROOT}/windows-arm64"
  cmake -S "${ROOT_DIR}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="${ROOT_DIR}/toolchains/mingw-w64-arm64.cmake" \
    ${qt_root:+-DCMAKE_PREFIX_PATH="${qt_root}"} \
    ${qt_root:+-DQT_HOST_PATH="/opt/homebrew/opt/qt"} \
    -DOPENSSL_ROOT_DIR="${openssl_root}" >/dev/null
  if [[ -n "${qt_root}" ]]; then
    cmake --build "${build_dir}" --target cryptexd cryptex_tests cryptexqt -j4 >/dev/null
  else
    cmake --build "${build_dir}" --target cryptexd cryptex_tests -j4 >/dev/null
    record_skipped "windows-arm64-gui" "set QT6_ROOT_WIN_ARM64 to a Qt6 ARM64 mingw prefix"
  fi
  cp "${build_dir}/cryptexd_win32.exe" "${DIST_DIR}/cryptexd_windows_arm64.exe"
  cp "${build_dir}/cryptex_tests.exe" "${DIST_DIR}/cryptex_tests_windows_arm64.exe"
  copy_if_exists "${build_dir}/cryptexqt_win32.exe" "${DIST_DIR}/cryptexqt_windows_arm64.exe" || true
  record_built "windows-arm64"
}

build_linux_target() {
  local arch="$1"
  local platform
  case "${arch}" in
    x86_64) platform="linux/amd64" ;;
    arm64) platform="linux/arm64" ;;
    *) record_skipped "linux-${arch}" "unsupported architecture"; return 0 ;;
  esac
  if ! docker info >/dev/null 2>&1; then
    record_skipped "linux-${arch}" "docker daemon not running"
    return 0
  fi
  local build_dir="/src/build-release/linux-${arch}"
  docker run --rm --platform "${platform}" \
    -v "${ROOT_DIR}:/src" -w /src golang:1.24-bookworm bash -lc \
    "apt-get update >/dev/null && \
     apt-get install -y g++ gcc cmake libssl-dev libboost-system-dev zlib1g-dev qt6-base-dev git squashfs-tools desktop-file-utils patchelf file >/dev/null && \
     export CC=/usr/bin/gcc CXX=/usr/bin/g++ && \
     rm -rf ${build_dir} && \
     cmake -S /src -B ${build_dir} -DCMAKE_BUILD_TYPE=Release >/dev/null && \
     cmake --build ${build_dir} --target cryptexd cryptex_tests cryptexqt -j4 >/dev/null && \
     /src/scripts/package-linux-appimage.sh ${arch} /src ${build_dir}"
  cp "${BUILD_ROOT}/linux-${arch}/cryptexd_linux" "${DIST_DIR}/cryptexd_linux_${arch}"
  cp "${BUILD_ROOT}/linux-${arch}/cryptex_tests" "${DIST_DIR}/cryptex_tests_linux_${arch}"
  copy_if_exists "${BUILD_ROOT}/linux-${arch}/cryptexqt_linux" "${DIST_DIR}/cryptexqt_linux_${arch}" || true
  record_built "linux-${arch}"
}

build_linux_x86_64() {
  build_linux_target x86_64
}

build_linux_arm64() {
  build_linux_target arm64
}

run_target() {
  case "$1" in
    macos-arm64) build_macos_arm64 ;;
    macos-universal) build_macos_universal ;;
    windows-x86_64) build_windows_x86_64 ;;
    windows-arm64) build_windows_arm64 ;;
    linux-x86_64) build_linux_x86_64 ;;
    linux-arm64) build_linux_arm64 ;;
    all)
      build_macos_arm64
      build_macos_universal
      build_windows_x86_64
      build_windows_arm64
      build_linux_x86_64
      build_linux_arm64
      ;;
    *)
      printf 'Unknown target: %s\n' "$1" >&2
      exit 1
      ;;
  esac
}

if [[ $# -eq 0 ]]; then
  run_target all
else
  for target in "$@"; do
    run_target "${target}"
  done
fi

log "built targets: ${built_targets[*]:-none}"
if [[ ${#skipped_targets[@]} -gt 0 ]]; then
  log "skipped targets:"
  for entry in "${skipped_targets[@]}"; do
    printf '  - %s\n' "${entry}"
  done
fi
