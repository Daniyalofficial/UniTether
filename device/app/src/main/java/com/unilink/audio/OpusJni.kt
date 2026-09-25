package com.unilink.audio

/**
 * Opus codec bindings. The native implementation (opus_jni.c) links the
 * reference libopus (vendored at build time by packaging/android-ndk.sh).
 * API mirrors libopus 1.3: 10 ms frames, 48 kHz mono, ~32 kbps.
 */
object OpusJni {
    const val SAMPLE_RATE = 48000
    const val FRAME_MS = 10
    const val FRAME_SAMPLES = SAMPLE_RATE / 1000 * FRAME_MS // 480

    init {
        var loaded = false
        try {
            System.loadLibrary("opus_jni")
            loaded = true
        } catch (_: UnsatisfiedLinkError) {
            // Conformance/CI builds without the NDK: fall back to the
            // pure-JVM passthrough so the protocol stack still runs.
        }
        if (!loaded) {
            System.loadLibrary("opus_jni_passthrough")
        }
    }

    external fun encoderCreate(): Long
    external fun encoderEncode(handle: Long, pcm: ShortArray, out: ByteArray): Int
    external fun encoderDestroy(handle: Long)

    external fun decoderCreate(): Long
    external fun decoderDecode(handle: Long, data: ByteArray, out: ShortArray): Int
    external fun decoderDestroy(handle: Long)
}
