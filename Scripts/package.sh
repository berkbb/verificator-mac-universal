#!/bin/bash
# Verificator'ı başkalarının indirip kurabileceği şekilde paketler.
#
# Çıktılar (dist/ altında):
#   Verificator-<sürüm>.dmg        Applications kısayollu kurulum disk kalıbı
#   Verificator-<sürüm>.dmg.sig    Ed25519 (EdDSA) DMG imzası
#   SHA256SUMS.txt                 İndirilen dosyaları doğrulamak için özetler
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKIP_TESTS=0
UNIVERSAL=1
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    --native-only) UNIVERSAL=0 ;;
    *) echo "Kullanım: $0 [--skip-tests] [--native-only]" >&2; exit 2 ;;
  esac
done

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$ROOT/Support/Info.plist")"
BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$ROOT/Support/Info.plist")"
NAME="Verificator-$VERSION"
DIST="$ROOT/dist"
APP="$ROOT/build/Verificator.app"

echo "▸ Sürüm: $VERSION (yapı $BUILD)"

if [ "$SKIP_TESTS" = 0 ]; then
  echo "▸ Testler çalıştırılıyor…"
  (cd "$ROOT" && swift test)
fi

BUILD_ARGS=(release)
[ "$UNIVERSAL" = 1 ] && BUILD_ARGS+=(--universal)
"$ROOT/Scripts/build_app.sh" "${BUILD_ARGS[@]}"

VERIFY_UNIVERSAL="$UNIVERSAL" "$ROOT/Scripts/verify_bundle.sh" "$APP"

echo "▸ Dağıtım dosyaları hazırlanıyor: $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

echo "▸ DMG disk kalıbı oluşturuluyor: $NAME.dmg"
DMG_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/verificator-dmg.XXXXXX")"
trap 'rm -rf "$DMG_STAGE"' EXIT
ditto "$APP" "$DMG_STAGE/Verificator.app"
ln -s /Applications "$DMG_STAGE/Applications"
cp "$ROOT/LICENSE" "$DMG_STAGE/LICENSE.txt"
cp "$ROOT/THIRD_PARTY_NOTICES.md" "$DMG_STAGE/THIRD_PARTY_NOTICES.txt"

hdiutil create \
  -quiet \
  -volname "Verificator $VERSION" \
  -srcfolder "$DMG_STAGE" \
  -fs HFS+ \
  -ov -format UDZO \
  "$DIST/$NAME.dmg"

hdiutil verify -quiet "$DIST/$NAME.dmg"

DMG_PATH="$DIST/$NAME.dmg"
SIGNING_TOOL=(xcrun swift "$ROOT/Scripts/update_signing.swift")
APP_PUBLIC_KEY="$(/usr/libexec/PlistBuddy -c 'Print :VerificatorUpdatePublicEDKey' "$ROOT/Support/Info.plist" 2>/dev/null || true)"

if [ -n "$APP_PUBLIC_KEY" ]; then
  KEYCHAIN_PUBLIC_KEY="$("${SIGNING_TOOL[@]}" public-key 2>/dev/null || true)"
  if [ "$APP_PUBLIC_KEY" = "$KEYCHAIN_PUBLIC_KEY" ]; then
    echo "▸ DMG imzalanıyor (Ed25519)…"
    "${SIGNING_TOOL[@]}" sign "$DMG_PATH" > "$DMG_PATH.sig"
    "${SIGNING_TOOL[@]}" verify "$DMG_PATH" "$(cat "$DMG_PATH.sig")" "$APP_PUBLIC_KEY"
    echo "✓ İmza doğrulandı ($DMG_PATH.sig)"
  else
    echo "UYARI: Keychain anahtarı ile Info.plist'teki VerificatorUpdatePublicEDKey uyuşmuyor; .sig üretilemedi." >&2
  fi
fi

echo "▸ SHA-256 özetleri oluşturuluyor…"
(
  cd "$DIST"
  shasum -a 256 "$NAME.dmg" > SHA256SUMS.txt
)

echo
echo "✓ Paketleme tamamlandı:"
READY_FILES=("$DIST/$NAME.dmg" "$DIST/SHA256SUMS.txt")
if [ -f "$DMG_PATH.sig" ]; then
  READY_FILES+=("$DMG_PATH.sig")
fi
for file in "${READY_FILES[@]}"; do
  printf '   %s\t%s\n' "$(du -h "$file" | cut -f1)" "$file"
done
cat "$DIST/SHA256SUMS.txt"
