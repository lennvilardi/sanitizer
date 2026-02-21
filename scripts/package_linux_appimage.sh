#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="ConfigSanitizer"
VERSION_RAW="${APP_VERSION:-0.1.0}"
VERSION="${VERSION_RAW#v}"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_DIR="${ROOT_DIR}/build"
RELEASE_DIR="${ROOT_DIR}/release"
APPDIR="${ROOT_DIR}/AppDir"
BIN_PATH="${DIST_DIR}/${APP_NAME}"
APPIMAGE_PATH="${RELEASE_DIR}/${APP_NAME}-${VERSION}-linux-x86_64.AppImage"
APPIMAGE_TOOL="${RUNNER_TEMP:-/tmp}/appimagetool-x86_64.AppImage"

rm -rf "${DIST_DIR}" "${BUILD_DIR}" "${APPDIR}" "${ROOT_DIR}/${APP_NAME}.spec"
mkdir -p "${RELEASE_DIR}"

python -m PyInstaller \
  --noconfirm \
  --clean \
  --name "${APP_NAME}" \
  --windowed \
  --onefile \
  "${ROOT_DIR}/sanitize_gui.py"

if [[ ! -f "${BIN_PATH}" ]]; then
  echo "ERROR: expected binary not found: ${BIN_PATH}" >&2
  exit 3
fi

mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"

cp "${BIN_PATH}" "${APPDIR}/usr/bin/${APP_NAME}"
cp "${ROOT_DIR}/packaging/linux/ConfigSanitizer.desktop" "${APPDIR}/usr/share/applications/ConfigSanitizer.desktop"
cp "${ROOT_DIR}/packaging/assets/config-sanitizer.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/config-sanitizer.svg"

cat > "${APPDIR}/AppRun" <<'EOF'
#!/usr/bin/env sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/ConfigSanitizer" "$@"
EOF
chmod +x "${APPDIR}/AppRun"

ln -sf "usr/share/applications/ConfigSanitizer.desktop" "${APPDIR}/ConfigSanitizer.desktop"
ln -sf "usr/share/icons/hicolor/scalable/apps/config-sanitizer.svg" "${APPDIR}/config-sanitizer.svg"

curl -sSL -o "${APPIMAGE_TOOL}" "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
chmod +x "${APPIMAGE_TOOL}"

ARCH=x86_64 "${APPIMAGE_TOOL}" --appimage-extract-and-run "${APPDIR}" "${APPIMAGE_PATH}"

echo "Built AppImage: ${APPIMAGE_PATH}"
