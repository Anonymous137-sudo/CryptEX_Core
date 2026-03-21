#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <arch> <root_dir> <build_dir>" >&2
  exit 1
fi

ARCH_INPUT="$1"
ROOT_DIR="$2"
BUILD_DIR="$3"

case "${ARCH_INPUT}" in
  x86_64) ARCH_TAG="x86_64" ;;
  arm64) ARCH_TAG="aarch64" ;;
  *) echo "unsupported arch: ${ARCH_INPUT}" >&2; exit 1 ;;
esac

APPDIR="${BUILD_DIR}/AppDir"
DIST_OUTPUT="${ROOT_DIR}/dist/cryptexqt_linux_${ARCH_INPUT}.AppImage"
TOOLS_DIR="/tmp/cryptex-go-appimage-${ARCH_TAG}"
APPIMAGETOOL_BIN="${TOOLS_DIR}/appimagetool"
RUNTIME_BIN="${TOOLS_DIR}/runtime-${ARCH_TAG}"

mkdir -p "${TOOLS_DIR}"

if [[ ! -x "${APPIMAGETOOL_BIN}" ]]; then
  export GOBIN="${TOOLS_DIR}"
  GO111MODULE=on /usr/local/go/bin/go install github.com/probonopd/go-appimage/src/appimagetool@latest
fi

if [[ ! -f "${RUNTIME_BIN}" ]]; then
  wget -qO "${RUNTIME_BIN}" "https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-${ARCH_TAG}"
fi

if [[ ! -x "${TOOLS_DIR}/uploadtool" ]]; then
  cat > "${TOOLS_DIR}/uploadtool" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "${TOOLS_DIR}/uploadtool"
fi
export PATH="${TOOLS_DIR}:${PATH}"

rm -rf "${APPDIR}" "${DIST_OUTPUT}"
mkdir -p "${APPDIR}/usr/bin" \
         "${APPDIR}/usr/lib" \
         "${APPDIR}/usr/plugins/platforms" \
         "${APPDIR}/usr/share/icons/hicolor/256x256/apps" \
         "${APPDIR}/usr/share/icons/hicolor/512x512/apps"

cp "${BUILD_DIR}/cryptexqt_linux" "${APPDIR}/usr/bin/"
cp "${BUILD_DIR}/cryptexd_linux" "${APPDIR}/usr/bin/"
cp "${ROOT_DIR}/gui/resources/CryptEX.png" "${APPDIR}/usr/share/icons/hicolor/512x512/apps/CryptEX.png"
cp "${ROOT_DIR}/gui/resources/CryptEX.png" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/CryptEX.png"
cp "${ROOT_DIR}/gui/resources/CryptEX.png" "${APPDIR}/CryptEX.png"
cp "${ROOT_DIR}/gui/resources/CryptEX.png" "${APPDIR}/.DirIcon"
cp "${ROOT_DIR}/gui/resources/cryptexqt.desktop" "${APPDIR}/cryptexqt.desktop"

cat > "${APPDIR}/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH:-}"
export QT_PLUGIN_PATH="${HERE}/usr/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="${HERE}/usr/plugins/platforms"
exec "${HERE}/usr/bin/cryptexqt_linux" "$@"
EOF
chmod +x "${APPDIR}/AppRun"

QMAKE_BIN="$(command -v qmake6 || command -v qmake || true)"
if [[ -z "${QMAKE_BIN}" ]]; then
  echo "qmake6/qmake not found in container" >&2
  exit 1
fi
QT_PLUGIN_ROOT="$(${QMAKE_BIN} -query QT_INSTALL_PLUGINS)"
QXCB_PLUGIN="${QT_PLUGIN_ROOT}/platforms/libqxcb.so"
if [[ ! -f "${QXCB_PLUGIN}" ]]; then
  echo "Qt platform plugin not found at ${QXCB_PLUGIN}" >&2
  exit 1
fi
cp -L "${QXCB_PLUGIN}" "${APPDIR}/usr/plugins/platforms/"

declare -A COPIED_LIBS=()

should_skip_lib() {
  case "$(basename "$1")" in
    ld-linux*.so*|ld-musl-*.so*|libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libutil.so.*|libresolv.so.*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

copy_deps() {
  local input="$1"
  local dep
  while IFS= read -r dep; do
    [[ -n "${dep}" ]] || continue
    [[ -f "${dep}" ]] || continue
    if should_skip_lib "${dep}"; then
      continue
    fi
    if [[ -n "${COPIED_LIBS[${dep}]:-}" ]]; then
      continue
    fi
    COPIED_LIBS["${dep}"]=1
    cp -L "${dep}" "${APPDIR}/usr/lib/"
    copy_deps "${dep}"
  done < <(ldd "${input}" | awk '{for (i = 1; i <= NF; ++i) if ($i ~ /^\//) print $i}')
}

copy_deps "${APPDIR}/usr/bin/cryptexqt_linux"
copy_deps "${APPDIR}/usr/bin/cryptexd_linux"
copy_deps "${APPDIR}/usr/plugins/platforms/libqxcb.so"

patchelf --set-rpath '$ORIGIN/../lib' "${APPDIR}/usr/bin/cryptexqt_linux"
patchelf --set-rpath '$ORIGIN/../lib' "${APPDIR}/usr/bin/cryptexd_linux"
patchelf --set-rpath '$ORIGIN/../../lib' "${APPDIR}/usr/plugins/platforms/libqxcb.so"

rm -f "${BUILD_DIR}"/*.AppImage
(cd "${BUILD_DIR}" && VERSION=1.0 ARCH="${ARCH_TAG}" "${APPIMAGETOOL_BIN}" "${APPDIR}" >/dev/null)
PRODUCED="$(find "${BUILD_DIR}" -maxdepth 1 -type f -name '*.AppImage' | head -n 1)"
if [[ -z "${PRODUCED}" ]]; then
  echo "AppImage output was not produced" >&2
  exit 1
fi
cp "${PRODUCED}" "${DIST_OUTPUT}"
chmod +x "${DIST_OUTPUT}"
