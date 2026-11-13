#!/bin/bash
# Oluşturulan Verificator.app paketinin dağıtıma hazır olduğunu doğrular.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/build/Verificator.app}"
RES="$APP/Contents/Resources"
MACOS="$APP/Contents/MacOS"
PLIST="$APP/Contents/Info.plist"

fail() { echo "DOĞRULAMA HATASI: $*" >&2; exit 1; }

[ -d "$APP" ] || fail "$APP bulunamadı"
[ -f "$PLIST" ] || fail "Info.plist eksik"
[ -x "$MACOS/Verificator" ] || fail "Verificator çalıştırılabilir dosyası eksik"
[ -f "$RES/AppIcon.icns" ] || fail "AppIcon.icns eksik"
[ -f "$RES/InternetAccessPolicy.plist" ] || fail "InternetAccessPolicy.plist eksik"
[ -f "$RES/Verificator-License.txt" ] || fail "Verificator-License.txt eksik"
[ -f "$RES/Third-Party-Notices.txt" ] || fail "Third-Party-Notices.txt eksik"

plutil -lint "$PLIST" >/dev/null || fail "Info.plist geçersiz"
plutil -lint "$RES/InternetAccessPolicy.plist" >/dev/null || fail "InternetAccessPolicy.plist geçersiz"

for lang in tr en ro; do
  for table in Localizable.strings InfoPlist.strings ServicesMenu.strings AppShortcuts.strings InternetAccessPolicy.strings; do
    [ -f "$RES/$lang.lproj/$table" ] || fail "$lang $table eksik"
    plutil -lint "$RES/$lang.lproj/$table" >/dev/null || fail "$lang $table geçersiz"
  done
done

if [ "${VERIFY_UNIVERSAL:-0}" = "1" ]; then
  for bin in "$MACOS/Verificator" "$MACOS/verificator-cli"; do
    [ -x "$bin" ] || continue
    ARCHS="$(lipo -archs "$bin")"
    [[ "$ARCHS" == *arm64* && "$ARCHS" == *x86_64* ]] || fail "$bin evrensel değil ($ARCHS)"
  done
fi

codesign --verify --deep --strict "$APP" || fail "Kod imzası doğrulaması başarısız"
echo "✓ Paket doğrulandı: $APP"
