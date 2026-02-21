#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="ConfigSanitizer"
VERSION_RAW="${APP_VERSION:-0.1.0}"
VERSION="${VERSION_RAW#v}"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_DIR="${ROOT_DIR}/build"
RELEASE_DIR="${ROOT_DIR}/release"
APP_PATH="${DIST_DIR}/${APP_NAME}.app"
DMG_PATH="${RELEASE_DIR}/${APP_NAME}-${VERSION}-macos.dmg"

rm -rf "${DIST_DIR}" "${BUILD_DIR}" "${ROOT_DIR}/${APP_NAME}.spec"
mkdir -p "${RELEASE_DIR}"

python -m PyInstaller \
  --noconfirm \
  --clean \
  --name "${APP_NAME}" \
  --windowed \
  "${ROOT_DIR}/sanitize_gui.py"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "ERROR: expected app bundle not found: ${APP_PATH}" >&2
  exit 3
fi

if [[ -n "${MACOS_SIGNING_CERT_BASE64:-}" ]] && [[ -n "${MACOS_SIGNING_CERT_PASSWORD:-}" ]] && [[ -n "${MACOS_SIGNING_IDENTITY:-}" ]]; then
  KEYCHAIN_PASSWORD="${MACOS_KEYCHAIN_PASSWORD:-temp-build-keychain-password}"
  KEYCHAIN_PATH="${RUNNER_TEMP:-/tmp}/build.keychain-db"
  CERT_PATH="${RUNNER_TEMP:-/tmp}/codesign.p12"

  echo "${MACOS_SIGNING_CERT_BASE64}" | base64 --decode > "${CERT_PATH}"

  security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
  security default-keychain -s "${KEYCHAIN_PATH}"
  security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
  security set-keychain-settings -lut 21600 "${KEYCHAIN_PATH}"
  security import "${CERT_PATH}" -k "${KEYCHAIN_PATH}" -P "${MACOS_SIGNING_CERT_PASSWORD}" -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"

  codesign --force --deep --options runtime --timestamp --sign "${MACOS_SIGNING_IDENTITY}" "${APP_PATH}"
  codesign --verify --deep --strict --verbose=2 "${APP_PATH}"
else
  echo "INFO: macOS signing secrets missing, build will be unsigned."
fi

hdiutil create -volname "${APP_NAME}" -srcfolder "${APP_PATH}" -ov -format UDZO "${DMG_PATH}"

if [[ -n "${MACOS_SIGNING_IDENTITY:-}" ]]; then
  codesign --force --timestamp --sign "${MACOS_SIGNING_IDENTITY}" "${DMG_PATH}" || true
fi

if [[ -n "${MACOS_NOTARY_KEY_ID:-}" ]] && [[ -n "${MACOS_NOTARY_ISSUER_ID:-}" ]] && [[ -n "${MACOS_NOTARY_API_KEY_BASE64:-}" ]]; then
  KEY_PATH="${RUNNER_TEMP:-/tmp}/AuthKey_${MACOS_NOTARY_KEY_ID}.p8"
  echo "${MACOS_NOTARY_API_KEY_BASE64}" | base64 --decode > "${KEY_PATH}"
  xcrun notarytool submit "${DMG_PATH}" \
    --key "${KEY_PATH}" \
    --key-id "${MACOS_NOTARY_KEY_ID}" \
    --issuer "${MACOS_NOTARY_ISSUER_ID}" \
    --wait
  xcrun stapler staple "${DMG_PATH}"
else
  echo "INFO: notarization secrets missing, DMG will not be notarized."
fi

echo "Built DMG: ${DMG_PATH}"
