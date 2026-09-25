cmake_minimum_required(VERSION 3.22.1)
project("unilink-ndk" C)

# Opus codec wrapper (the reference encoder/decoder is vendored at
# third_party/opus at build time by the packaging script; see
# packaging/android-ndk.sh). The JNI layer is built even when the Opus
# sources are absent, with a stub fallback so the app still compiles in
# CI sandboxes without the NDK toolchain.
add_library(opus_jni SHARED
    ${CMAKE_SOURCE_DIR}/src/main/jni/opus_jni.c)

target_compile_options(opus_jni PRIVATE -O2)
