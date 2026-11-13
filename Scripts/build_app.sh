#!/bin/bash
# Verificator.app paketini derler ve oluşturur.
#
# Kullanım:
#   build_app.sh [debug|release] [--universal]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="release"
UNIVERSAL=0
for arg in "$@"; do
  case "$arg" in
    debug|release) CONFIG="$arg" ;;
    --universal) UNIVERSAL=1 ;;
    *) echo "Kullanım: $0 [debug|release] [--universal]" >&2; exit 2 ;;
  esac
done

APP_DIR="$ROOT/build/Verificator.app"
CONTENTS="$APP_DIR/Contents"
MACOS="$CONTENTS/MacOS"
RES="$CONTENTS/Resources"

if [ ! -f "$ROOT/Resources/AppIcon.icns" ]; then
  echo "▸ Simge üretiliyor…"
  swift "$ROOT/Scripts/make_icon.swift" "$ROOT"
fi

BUILD_ARGS=(-c "$CONFIG" --package-path "$ROOT")
if [ "$UNIVERSAL" = 1 ]; then
  BUILD_ARGS+=(--arch arm64 --arch x86_64)
fi
if [ "${SWIFTPM_DISABLE_SANDBOX:-0}" = 1 ]; then
  BUILD_ARGS+=(--disable-sandbox)
fi
if [ -n "${SWIFTPM_SCRATCH_PATH:-}" ]; then
  BUILD_ARGS+=(--scratch-path "$SWIFTPM_SCRATCH_PATH")
fi

echo "▸ Verificator derleniyor ($CONFIG$([ "$UNIVERSAL" = 1 ] && echo ", universal"))…"
swift build "${BUILD_ARGS[@]}"
BIN_DIR="$(swift build "${BUILD_ARGS[@]}" --show-bin-path)"

echo "▸ Verificator.app paketleniyor…"
rm -rf "$APP_DIR"
mkdir -p "$MACOS" "$RES"

cp "$BIN_DIR/Verificator" "$MACOS/Verificator"
chmod +x "$MACOS/Verificator"
if [ -x "$BIN_DIR/verificator-cli" ]; then
  cp "$BIN_DIR/verificator-cli" "$MACOS/verificator-cli"
  chmod +x "$MACOS/verificator-cli"
fi
cp "$ROOT/Support/Info.plist" "$CONTENTS/Info.plist"
printf 'APPL????' > "$CONTENTS/PkgInfo"

cp -R "$ROOT/Resources/"* "$RES/"
cp "$ROOT/LICENSE" "$RES/Verificator-License.txt"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$RES/Third-Party-Notices.txt"

echo "▸ Kod imzası (ad-hoc)…"
[ -x "$MACOS/verificator-cli" ] && codesign --force --sign - "$MACOS/verificator-cli"
codesign --force --sign - "$MACOS/Verificator"
codesign --force --sign - "$APP_DIR"

echo "▸ Mimariler: $(lipo -archs "$MACOS/Verificator")"
echo "✓ Hazır: $APP_DIR"
