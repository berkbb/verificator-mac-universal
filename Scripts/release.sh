#!/bin/bash
# Verificator sürümünü bu Mac'te paketler ve GitHub Releases'e yükler.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=0
DRAFT=0
PACKAGE_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --draft) DRAFT=1 ;;
    --skip-tests) PACKAGE_ARGS+=(--skip-tests) ;;
    -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Bilinmeyen seçenek: $arg" >&2; exit 2 ;;
  esac
done

fail() { echo "HATA: $*" >&2; exit 1; }
run() {
  if [ "$DRY_RUN" = 1 ]; then echo "  (deneme) $*"; else "$@"; fi
}

cd "$ROOT"
command -v gh >/dev/null || fail "gh CLI bulunamadı (brew install gh)"
gh auth status >/dev/null 2>&1 || fail "gh oturumu yok (gh auth login)"

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Support/Info.plist)"
TAG="v$VERSION"
NAME="Verificator-$VERSION"
REPO="$(/usr/libexec/PlistBuddy -c 'Print :VerificatorRepository' Support/Info.plist)"
echo "▸ Sürüm: $VERSION  (etiket $TAG, depo $REPO)"

"$ROOT/Scripts/package.sh" "${PACKAGE_ARGS[@]+"${PACKAGE_ARGS[@]}"}"
ASSETS=("dist/$NAME.dmg" "dist/$NAME.dmg.sig" "dist/SHA256SUMS.txt")
for asset in "${ASSETS[@]}"; do [ -f "$asset" ] || fail "$asset oluşmadı"; done

echo "▸ Etiket: $TAG"
if ! git rev-parse "$TAG" >/dev/null 2>&1; then
  run git tag -a "$TAG" -m "Verificator $VERSION"
  run git push origin "$TAG"
else
  echo "  (etiket zaten var: $TAG)"
fi

RELEASE_ARGS=(release create "$TAG" "${ASSETS[@]}" --repo "$REPO" --title "Verificator $VERSION" --generate-notes --verify-tag)
[ "$DRAFT" = 1 ] && RELEASE_ARGS+=(--draft)
echo "▸ GitHub sürümü oluşturuluyor…"
run gh "${RELEASE_ARGS[@]}"
