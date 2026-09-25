#!/usr/bin/env bash
# Cut a release: builds host binaries (all 3 OSes via cross-compilers
# where available), the Android APK, and the GUI installer.
#
#   ./packaging/release.sh v0.1.0
set -euo pipefail
TAG="${1:?tag required, e.g. v0.1.0}"
cd "$(dirname "$0")/.."
rm -rf dist "$TAG"
mkdir -p dist "$TAG"

# ---- host CLI (native arch of the runner; cross in CI matrix) ----
cargo build --release --manifest-path host/Cargo.toml
cp host/target/release/unitether "$TAG/unitether-$(uname -s | tr '[:upper:]' '[:lower:]')"

# ---- GUI installer (Tauri) ----
if command -v npm >/dev/null; then
  (cd host/gui && npm install --no-audit --no-fund && npx tauri build) \
    && cp host/gui/src-tauri/target/release/bundle/*/*.AppImage "$TAG"/ 2>/dev/null || true
fi

# ---- Android APK ----
if [ -n "${ANDROID_HOME:-}" ]; then
  bash packaging/android-ndk.sh build \
    && cp device/app/build/outputs/apk/release/app-release-unsigned.apk "$TAG/unitether.apk" || true
fi

cd "$TAG"
sha256sum * > SHA256SUMS
cd ..
tar -czf "unitether-$TAG.tar.gz" "$TAG"
echo "release ready: unitether-$TAG.tar.gz"
