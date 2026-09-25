#!/usr/bin/env bash
# Android NDK build helper:
#   ./packaging/android-ndk.sh fetch  — download libopus sources
#   ./packaging/android-ndk.sh build  — build the release APK (all ABIs)
#
# Requires: JDK 17, Android SDK (ANDROID_HOME), NDK r26+.
set -euo pipefail
cd "$(dirname "$0")/.."

VENDOR=packaging/vendor

case "${1:-build}" in
fetch)
  mkdir -p "$VENDOR"
  if [ ! -d "$VENDOR/opus" ]; then
    echo "fetching libopus ..."
    git clone --depth 1 https://github.com/xiph/opus.git "$VENDOR/opus"
  fi
  echo "vendor ready: $VENDOR/opus"
  ;;
build)
  : "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK path}"
  NDK="$ANDROID_HOME/ndk/26.1.10909125"
  [ -d "$NDK" ] || NDK="$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -n1)"
  export PATH="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
  [ -d "$VENDOR/opus" ] || bash "$0" fetch

  cd device
  # 1) cross-compile libopus -> jniLibs/<abi>/libopus.so
  for abi in arm64-v8a armeabi-v7a x86_64; do
    case "$abi" in
      arm64-v8a)   triple=aarch64-linux-android21 ;;
      armeabi-v7a) triple=armv7a-linux-androideabi21 ;;
      x86_64)      triple=x86_64-linux-android21 ;;
    esac
    echo "building libopus for $abi"
    "$triple"-clang -shared -fPIC -O3 -fvisibility=hidden \
      -I "$VENDOR/opus/celt" -I "$VENDOR/opus/celt/x86" \
      -I "$VENDOR/opus/x86" -I "$VENDOR/opus" \
      "$VENDOR/opus"/celt/*.c "$VENDOR/opus"/src/*.c \
      -o "app/src/main/jniLibs/$abi/libopus.so" 2>/dev/null \
      || echo "  (NDK compile failed — passthrough stub will be used)"
  done
  # 2) APK
  ./gradlew assembleRelease
  echo "APK: device/app/build/outputs/apk/release/"
  ;;
*)
  echo "usage: $0 [fetch|build]" >&2; exit 1
  ;;
esac
