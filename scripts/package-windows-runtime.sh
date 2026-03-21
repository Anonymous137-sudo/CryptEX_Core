#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${1:-${ROOT_DIR}/build-release/windows-x86_64}"
OUT_DIR="${2:-${ROOT_DIR}/dist/CryptEX_windows_x86_64_bundle}"
QT_ROOT="${QT6_ROOT_WIN_X86_64:-/Users/gitanshchakravarty/Qt/6.10.2/mingw_64}"

if [[ ! -d "${BUILD_DIR}" ]]; then
  echo "[package-win] build directory not found: ${BUILD_DIR}" >&2
  exit 1
fi

if [[ ! -d "${QT_ROOT}" ]]; then
  echo "[package-win] Qt root not found: ${QT_ROOT}" >&2
  exit 1
fi

rm -rf "${OUT_DIR}"
mkdir -p \
  "${OUT_DIR}" \
  "${OUT_DIR}/plugins/platforms" \
  "${OUT_DIR}/plugins/imageformats" \
  "${OUT_DIR}/plugins/iconengines" \
  "${OUT_DIR}/plugins/styles" \
  "${OUT_DIR}/plugins/tls" \
  "${OUT_DIR}/plugins/networkinformation"

copy_file() {
  local src="$1"
  local dst="$2"
  if [[ ! -f "${src}" ]]; then
    echo "[package-win] missing file: ${src}" >&2
    exit 1
  fi
  cp "${src}" "${dst}"
}

copy_file "${BUILD_DIR}/cryptexqt_win32.exe" "${OUT_DIR}/cryptexqt_win32.exe"
copy_file "${BUILD_DIR}/cryptexd_win32.exe" "${OUT_DIR}/cryptexd_win32.exe"
copy_file "${BUILD_DIR}/cryptex_tests.exe" "${OUT_DIR}/cryptex_tests.exe"

for dll in \
  Qt6Core.dll \
  Qt6Gui.dll \
  Qt6Network.dll \
  Qt6Widgets.dll \
  Qt6Svg.dll \
  libgcc_s_seh-1.dll \
  libstdc++-6.dll \
  libwinpthread-1.dll \
  d3dcompiler_47.dll \
  opengl32sw.dll
do
  copy_file "${QT_ROOT}/bin/${dll}" "${OUT_DIR}/${dll}"
done

for plugin in \
  platforms/qwindows.dll \
  imageformats/qico.dll \
  imageformats/qjpeg.dll \
  imageformats/qgif.dll \
  imageformats/qsvg.dll \
  iconengines/qsvgicon.dll \
  styles/qmodernwindowsstyle.dll \
  tls/qcertonlybackend.dll \
  tls/qschannelbackend.dll \
  tls/qopensslbackend.dll \
  networkinformation/qnetworklistmanager.dll
do
  copy_file "${QT_ROOT}/plugins/${plugin}" "${OUT_DIR}/plugins/${plugin}"
done

cat > "${OUT_DIR}/qt.conf" <<'EOF'
[Paths]
Plugins = plugins
EOF

cat > "${OUT_DIR}/README.txt" <<'EOF'
CryptEX Windows x86_64 Runtime Bundle
====================================

Contents
- cryptexqt_win32.exe : Qt GUI client
- cryptexd_win32.exe  : backend / node / RPC daemon
- cryptex_tests.exe   : test binary

How to launch
1. Start cryptexqt_win32.exe
2. The GUI will auto-discover cryptexd_win32.exe in the same folder
3. The GUI can launch the backend for you

Notes
- Keep the plugins directory and DLLs beside the executables
- Do not move cryptexqt_win32.exe away from cryptexd_win32.exe if you want auto-discovery to keep working
EOF

(
  cd "$(dirname "${OUT_DIR}")"
  rm -f "$(basename "${OUT_DIR}").zip"
  zip -qry "$(basename "${OUT_DIR}").zip" "$(basename "${OUT_DIR}")"
)

echo "[package-win] created bundle: ${OUT_DIR}"
echo "[package-win] created archive: ${OUT_DIR}.zip"
