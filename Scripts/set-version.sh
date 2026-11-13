#!/bin/bash
# Verificator sürümünü değiştirir. Sürümün tek kaynağı Support/Info.plist'tir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLIST="$ROOT/Support/Info.plist"
VERSION="${1:-}"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Kullanım: $(basename "$0") <büyük.küçük.yama>  (ör. 1.2.1)" >&2
  exit 2
fi

OLD_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$PLIST")"
OLD_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$PLIST")"
NEW_BUILD=$((OLD_BUILD + 1))

/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $NEW_BUILD" "$PLIST"

APP_INFO="$ROOT/Sources/VerificatorCore/AppInfo.swift"
if [ -f "$APP_INFO" ]; then
  /usr/bin/sed -i '' -E "s/public static let fallbackVersion = \"[^\"]*\"/public static let fallbackVersion = \"$VERSION\"/" "$APP_INFO"
  /usr/bin/sed -i '' -E "s/public static let fallbackBuild = \"[^\"]*\"/public static let fallbackBuild = \"$NEW_BUILD\"/" "$APP_INFO"
fi

echo "Sürüm: $OLD_VERSION ($OLD_BUILD) → $VERSION ($NEW_BUILD)"
echo "CHANGELOG.md içinde '## [$VERSION]' başlığını eklemeyi unutmayın."
