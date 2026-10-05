/* opus_jni.c — JNI wrapper around libopus (vendored at build time by
 * packaging/android-ndk.sh). 48 kHz mono, 10 ms frames, 32 kbps.
 *
 * When the Opus sources are absent (CI sandboxes), CMake builds the
 * passthrough stub in opus_jni_stub.c with the same symbol names so the
 * protocol stack remains testable end-to-end.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_OPUS
#include <opus.h>
#define OPUS_SET_BITRATE(x) OPUS_SET_BITRATE(x)
#endif

static const int SR = 48000;
static const int FRAME = 480;      /* 10 ms */

#ifdef HAVE_OPUS

JNIEXPORT jlong JNICALL
Java_com_unilink_audio_OpusJni_encoderCreate(JNIEnv *env, jobject thiz) {
    int err;
    OpusEncoder *e = opus_encoder_create(SR, 1, OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !e) return 0;
    opus_encoder_ctl(e, OPUS_SET_BITRATE(32000));
    opus_encoder_ctl(e, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(e, OPUS_SET_PACKET_LOSS_PERC(5));
    return (jlong)(intptr_t)e;
}

JNIEXPORT jint JNICALL
Java_com_unilink_audio_OpusJni_encoderEncode(JNIEnv *env, jobject thiz,
                                             jlong handle, jshortArray pcm,
                                             jbyteArray out) {
    if (!handle) return 0;
    OpusEncoder *e = (OpusEncoder *)(intptr_t)handle;
    jshort *p = (*env)->GetShortArrayElements(env, pcm, NULL);
    uint8_t *o = (uint8_t *)(*env)->GetByteArrayElements(env, out, NULL);
    int n = opus_encode(e, p, FRAME, o, 2048);
    (*env)->ReleaseShortArray(env, pcm, p, JNI_ABORT);
    (*env)->ReleaseByteArray(env, out, (jbyte *)o, n > 0 ? n : 0);
    return n;
}

JNIEXPORT void JNICALL
Java_com_unilink_audio_OpusJni_encoderDestroy(JNIEnv *env, jobject thiz, jlong handle) {
    if (handle) opus_encoder_destroy((OpusEncoder *)(intptr_t)handle);
}

JNIEXPORT jlong JNICALL
Java_com_unilink_audio_OpusJni_decoderCreate(JNIEnv *env, jobject thiz) {
    int err;
    OpusDecoder *d = opus_decoder_create(SR, 1, &err);
    if (err != OPUS_OK || !d) return 0;
    return (jlong)(intptr_t)d;
}

JNIEXPORT jint JNICALL
Java_com_unilink_audio_OpusJni_decoderDecode(JNIEnv *env, jobject thiz,
                                             jlong handle, jbyteArray data,
                                             jshortArray out) {
    if (!handle) return 0;
    OpusDecoder *d = (OpusDecoder *)(intptr_t)handle;
    jbyte *in = (*env)->GetByteArrayElements(env, data, NULL);
    jshort *o = (*env)->GetShortArrayElements(env, out, NULL);
    int n = opus_decode(d, (uint8_t *)in, (*env)->GetArrayLength(env, data), o, FRAME, 0);
    (*env)->ReleaseByteArray(env, data, in, JNI_ABORT);
    (*env)->ReleaseShortArray(env, out, o, n > 0 ? 0 : JNI_ABORT);
    return n;
}

JNIEXPORT void JNICALL
Java_com_unilink_audio_OpusJni_decoderDestroy(JNIEnv *env, jobject thiz, jlong handle) {
    if (handle) opus_decoder_destroy((OpusDecoder *)(intptr_t)handle);
}

#else

/* -------- passthrough stub (conformance builds without libopus) -------- */

JNIEXPORT jlong JNICALL
Java_com_unilink_audio_OpusJni_encoderCreate(JNIEnv *env, jobject thiz) { return 1; }
JNIEXPORT jint JNICALL
Java_com_unilink_audio_OpusJni_encoderEncode(JNIEnv *env, jobject thiz,
                                             jlong handle, jshortArray pcm,
                                             jbyteArray out) {
    /* "encode" = raw 16-bit LE passthrough (lossless, non-Opus payload) */
    jsize n = (*env)->GetArrayLength(env, pcm);
    jshort *p = (*env)->GetShortArrayElements(env, pcm, NULL);
    jbyte *o = (*env)->GetByteArrayElements(env, out, NULL);
    int need = n * 2;
    jsize olen = (*env)->GetArrayLength(env, out);
    int copy = need < (int)olen ? need : (int)olen;
    for (int i = 0; i + 1 < copy; i += 2) {
        jshort v = p[i / 2];
        o[i] = (jbyte)(v & 0xFF);
        o[i + 1] = (jbyte)((v >> 8) & 0xFF);
    }
    (*env)->ReleaseShortArray(env, pcm, p, JNI_ABORT);
    (*env)->ReleaseByteArray(env, out, o, copy);
    return copy / 2;
}
JNIEXPORT void JNICALL
Java_com_unilink_audio_OpusJni_encoderDestroy(JNIEnv *env, jobject thiz, jlong handle) {}
JNIEXPORT jlong JNICALL
Java_com_unilink_audio_OpusJni_decoderCreate(JNIEnv *env, jobject thiz) { return 1; }
JNIEXPORT jint JNICALL
Java_com_unilink_audio_OpusJni_decoderDecode(JNIEnv *env, jobject thiz,
                                             jlong handle, jbyteArray data,
                                             jshortArray out) {
    jsize n = (*env)->GetArrayLength(env, data);
    jbyte *in = (*env)->GetByteArrayElements(env, data, NULL);
    jshort *o = (*env)->GetShortArrayElements(env, out, NULL);
    jsize olen = (*env)->GetArrayLength(env, out);
    int copy = (n / 2) < olen ? (n / 2) : olen;
    for (int i = 0; i < copy; i++) {
        o[i] = (jshort)((in[2 * i] & 0xFF) | ((in[2 * i + 1] & 0xFF) << 8));
    }
    (*env)->ReleaseByteArray(env, data, in, JNI_ABORT);
    (*env)->ReleaseShortArray(env, out, o, 0);
    return copy;
}
JNIEXPORT void JNICALL
Java_com_unilink_audio_OpusJni_decoderDestroy(JNIEnv *env, jobject thiz, jlong handle) {}

#endif
