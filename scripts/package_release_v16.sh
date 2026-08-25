#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT_DIR/dist"}
VERSION=v16.0.1
MAIN_NAME=METAL_CRYPTO_TOOLKIT
MAIN_ARCHIVE="$MAIN_NAME-$VERSION-macos-arm64.tar.gz"
MAIN_BINARY="$ROOT_DIR/bin/$MAIN_NAME"
METAL_LIBRARY="$ROOT_DIR/build/default.metallib"
METAL_BINARY_ARCHIVE="$ROOT_DIR/build/default.binary.metallib"
METAL_BINARY_ARCHIVE_BUILDER="$ROOT_DIR/scripts/build_metal_binary_archive.py"
PYTHON3=${PYTHON3:-python3}

fail() {
    printf '%s\n' "[!] $*" >&2
    exit 1
}

command -v lipo >/dev/null 2>&1 ||
    fail "lipo is required to validate the release architecture"
command -v otool >/dev/null 2>&1 ||
    fail "otool is required to validate the Mach-O release binary"
command -v shasum >/dev/null 2>&1 ||
    fail "shasum is required to generate release checksums"
xcrun --find metal-lipo >/dev/null 2>&1 ||
    fail "metal-lipo is required to validate the Metal IR architecture"
xcrun --find metal-objdump >/dev/null 2>&1 ||
    fail "metal-objdump is required to validate the Metal deployment target"

[ -x "$MAIN_BINARY" ] ||
    fail "build the toolkit first: make clean && make -j\$(sysctl -n hw.ncpu)"
[ -f "$METAL_LIBRARY" ] ||
    fail "Metal library is missing: $METAL_LIBRARY"
[ -f "$METAL_BINARY_ARCHIVE" ] ||
    fail "Metal binary archive is missing: $METAL_BINARY_ARCHIVE"

"$PYTHON3" "$METAL_BINARY_ARCHIVE_BUILDER" verify \
    --archive "$METAL_BINARY_ARCHIVE" ||
    fail "Metal binary archive verification failed"

METAL_ARCHITECTURES=$(xcrun metal-lipo "$METAL_LIBRARY" -archs |
    tr -d '[:space:]')
[ "$METAL_ARCHITECTURES" = "air64_v26" ] ||
    fail "release metallib must contain AIR 2.6 only; found: ${METAL_ARCHITECTURES:-missing}"

METAL_PLATFORM=$(xcrun metal-objdump --metallib --private-headers "$METAL_LIBRARY" |
    LC_ALL=C tr -d '\000' |
    awk '$1 == "PlatformMajor:" { print $2; exit }')
[ "$METAL_PLATFORM" = "14" ] ||
    fail "release metallib must target macOS 14; found: ${METAL_PLATFORM:-missing}"

ARCHITECTURES=$(lipo -archs "$MAIN_BINARY")
[ "$ARCHITECTURES" = "arm64" ] ||
    fail "release binary must contain arm64 only; found: $ARCHITECTURES"

MINIMUM_OS=$(otool -l "$MAIN_BINARY" |
    awk '$1 == "minos" { print $2; exit }')
[ "$MINIMUM_OS" = "15.0" ] ||
    fail "release binary must declare macOS 15.0; found: ${MINIMUM_OS:-missing}"

otool -l "$MAIN_BINARY" |
    awk '$1 == "sectname" && $2 == "__metallib" { found = 1 }
         END { exit(found ? 0 : 1) }' ||
    fail "embedded __DATA,__metallib section is missing"

otool -l "$MAIN_BINARY" |
    awk '$1 == "sectname" && $2 == "__metalarc" { found = 1 }
         END { exit(found ? 0 : 1) }' ||
    fail "embedded __DATA,__metalarc section is missing"

"$MAIN_BINARY" -help |
    grep -q "METAL_CRYPTO_TOOLKIT v16.0.1" ||
    fail "release binary does not report v16.0.1"

mkdir -p "$OUTPUT_DIR"
for ARTIFACT in \
    "$OUTPUT_DIR/$MAIN_ARCHIVE" \
    "$OUTPUT_DIR/$MAIN_ARCHIVE.sha256"; do
    [ ! -e "$ARTIFACT" ] ||
        fail "refusing to overwrite existing artifact: $ARTIFACT"
done

STAGING_DIR=$(mktemp -d "${TMPDIR:-/tmp}/metal-crypto-v16.0.1-package.XXXXXX")
trap 'rm -rf "$STAGING_DIR"' EXIT HUP INT TERM
MAIN_STAGE="$STAGING_DIR/main"
mkdir -p "$MAIN_STAGE"

cp "$MAIN_BINARY" "$MAIN_STAGE/$MAIN_NAME"
cp "$ROOT_DIR/README.md" \
   "$ROOT_DIR/LICENSE" \
   "$ROOT_DIR/COPYING.GPLv3.txt" \
   "$ROOT_DIR/THIRD_PARTY_NOTICES.md" \
   "$ROOT_DIR/RELEASE_NOTES_v16_EN.md" \
   "$ROOT_DIR/RELEASE_NOTES_v16_RU.md" \
   "$MAIN_STAGE/"

COPYFILE_DISABLE=1 tar -czf "$OUTPUT_DIR/$MAIN_ARCHIVE" \
    -C "$MAIN_STAGE" .

(
    cd "$OUTPUT_DIR"
    shasum -a 256 "$MAIN_ARCHIVE" >"$MAIN_ARCHIVE.sha256"
)

printf '%s\n' \
    "[!] v16.0.1 release artifacts created in $OUTPUT_DIR" \
    "[!] $MAIN_ARCHIVE"
