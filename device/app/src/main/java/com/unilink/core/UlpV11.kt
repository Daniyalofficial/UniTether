package com.unilink.core

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * ULP v1.1 extensions (docs/21 §3) — conformance port of
 * tests/protocol/ulp_v11.py + golden vectors protocol/vectors/v11.json.
 *
 * Adds (only when FEAT_VERSIONED is negotiated — v1 bytes unchanged):
 *  MSG_DEVICE_ID (0x11) / MSG_DEVICE_AUTH (0x12) identity exchange
 *  MSG_RESUME_REQ (0x0E) / MSG_RESUME_OK (0x13) session resumption
 *  structured MSG_ERROR bodies with stable codes
 *
 * MACs bind the wire transcript (exact frame bytes since connection,
 * both directions, local observation order) — UlpSession exposes
 * `transcript` / `transcriptPrefix` for this.
 */
object UlpV11 {
    const val FEAT_VERSIONED = 1 shl 8

    const val MSG_DEVICE_ID = 0x11
    const val MSG_DEVICE_AUTH = 0x12
    const val MSG_RESUME_REQ = 0x0E
    const val MSG_RESUME_OK = 0x13

    const val CAP_NETWORK = 1 shl 0
    const val CAP_DISPLAY = 1 shl 1
    const val CAP_CAMERA = 1 shl 2
    const val CAP_MIC = 1 shl 3
    const val CAP_AUDIO = 1 shl 4
    const val CAP_INPUT = 1 shl 5
    const val CAP_STORAGE = 1 shl 6
    const val CAP_MESSAGING = 1 shl 7
    const val CAP_NOTIFICATIONS = 1 shl 8
    const val CAP_AUTOMATION = 1 shl 9

    const val ERR_AUTH = 0x0001
    const val ERR_CIPHER = 0x0002
    const val ERR_VERSION = 0x0003
    const val ERR_FORMAT = 0x0004
    const val ERR_LIMIT = 0x0005
    const val ERR_TIMEOUT = 0x0006
    const val ERR_IDENTITY_REQUIRED = 0x0007
    const val ERR_THROTTLED = 0x0008
    const val ERR_REVOKED = 0x0009
    const val ERR_RESUME_INVALID = 0x000A
    const val ERR_UPGRADE_REQUIRED = 0x000B

    const val DECISION_TRUSTED = 0
    const val DECISION_TRUSTED_NEW = 1
    const val DECISION_REVOKED = 2
    const val DECISION_THROTTLED = 3

    // ---------------------------------------------------------- identity
    fun deviceIdFromPub(identityPub: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("unilink-dev-id-v1".toByteArray())
        md.update(identityPub)
        return md.digest().copyOf(16)
    }

    private fun pad(b: ByteArray, n: Int): ByteArray {
        if (b.size >= n) return b.copyOf(n)
        return b + ByteArray(n - b.size)
    }

    private fun hmac16(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) mac.update(p)
        return mac.doFinal().copyOf(16)
    }

    /** 164 B: id(16) pub(32) name(64) platform(16) appVer(16) caps(u32be) mac(16). */
    fun deviceIdBody(deviceId: ByteArray, identityPub: ByteArray, name: String,
                     platform: String, appVer: String, caps: Int,
                     transcript: ByteArray, keyMac: ByteArray): ByteArray {
        val pre = ByteArray(148).apply {
            deviceId.copyInto(this, 0)
            identityPub.copyInto(this, 16)
            pad(name.toByteArray(Charsets.UTF_8), 64).copyInto(this, 48)
            pad(platform.toByteArray(Charsets.UTF_8), 16).copyInto(this, 112)
            pad(appVer.toByteArray(Charsets.UTF_8), 16).copyInto(this, 128)
            this[144] = (caps ushr 24).toByte()
            this[145] = (caps ushr 16).toByte()
            this[146] = (caps ushr 8).toByte()
            this[147] = caps.toByte()
        }
        return pre + hmac16(keyMac, "unilink-dev-id-v1".toByteArray(),
                            transcript, pre)
    }

    fun deviceIdParse(body: ByteArray, transcript: ByteArray,
                      keyMac: ByteArray): DeviceIdentity {
        require(body.size == 164) { "device_id: bad length ${body.size}" }
        val pre = body.copyOfRange(0, 148)
        val expect = hmac16(keyMac, "unilink-dev-id-v1".toByteArray(),
                            transcript, pre)
        require(java.security.MessageDigest.isEqual(expect, body.copyOfRange(148, 164))) {
            "device_id: mac mismatch"
        }
        val caps = ((body[144].toInt() and 0xFF) shl 24) or
                   ((body[145].toInt() and 0xFF) shl 16) or
                   ((body[146].toInt() and 0xFF) shl 8) or
                   (body[147].toInt() and 0xFF)
        return DeviceIdentity(
            deviceId = body.copyOfRange(0, 16),
            identityPub = body.copyOfRange(16, 48),
            name = unpad(body.copyOfRange(48, 112)),
            platform = unpad(body.copyOfRange(112, 128)),
            appVer = unpad(body.copyOfRange(128, 144)),
            caps = caps)
    }

    private fun unpad(b: ByteArray): String {
        val z = b.indexOf(0.toByte())
        val end = if (z < 0) b.size else z
        return b.copyOfRange(0, end).toString(Charsets.UTF_8)
    }

    /** 49 B: decision(1) sessionId(16) senderId(16) mac(16). */
    fun deviceAuthBody(decision: Int, sessionId: ByteArray, senderId: ByteArray,
                       transcript: ByteArray, keyMac: ByteArray): ByteArray {
        val pre = ByteArray(33).apply {
            this[0] = decision.toByte()
            sessionId.copyInto(this, 1)
            senderId.copyInto(this, 17)
        }
        return pre + hmac16(keyMac, "unilink-dev-auth-v1".toByteArray(),
                            transcript, pre)
    }

    fun deviceAuthParse(body: ByteArray, transcript: ByteArray,
                        keyMac: ByteArray): DeviceAuth {
        require(body.size == 49) { "device_auth: bad length ${body.size}" }
        val pre = body.copyOfRange(0, 33)
        val expect = hmac16(keyMac, "unilink-dev-auth-v1".toByteArray(),
                            transcript, pre)
        require(java.security.MessageDigest.isEqual(expect, body.copyOfRange(33, 49))) {
            "device_auth: mac mismatch"
        }
        return DeviceAuth(body[0].toInt() and 0xFF,
                          body.copyOfRange(1, 17), body.copyOfRange(17, 33))
    }

    // ---------------------------------------------------------- resume
    /** 80 B: sessionId(16) freshPub(32) nonce(16) mac(16); keyed by pairing secret. */
    fun resumeReqBody(sessionId: ByteArray, freshPub: ByteArray,
                      resumeNonce: ByteArray, secret: ByteArray): ByteArray {
        val pre = sessionId + freshPub + resumeNonce
        return pre + hmac16(secret, "unilink-resume-v1".toByteArray(), pre)
    }

    fun resumeReqParse(body: ByteArray, secret: ByteArray): ResumeReq {
        require(body.size == 80) { "resume_req: bad length ${body.size}" }
        val pre = body.copyOfRange(0, 64)
        val expect = hmac16(secret, "unilink-resume-v1".toByteArray(), pre)
        require(java.security.MessageDigest.isEqual(expect, body.copyOfRange(64, 80))) {
            "resume_req: mac mismatch"
        }
        return ResumeReq(body.copyOfRange(0, 16), body.copyOfRange(16, 48),
                         body.copyOfRange(48, 64))
    }

    /** 48 B: freshPub(32) mac(16). */
    fun resumeOkBody(freshPub: ByteArray, sessionId: ByteArray,
                     reqPub: ByteArray, secret: ByteArray): ByteArray {
        return freshPub + hmac16(secret, "unilink-resume-v1".toByteArray(),
                                 sessionId, reqPub, freshPub)
    }

    fun resumeOkParse(body: ByteArray, sessionId: ByteArray,
                      reqPub: ByteArray, secret: ByteArray): ByteArray {
        require(body.size == 48) { "resume_ok: bad length ${body.size}" }
        val freshPub = body.copyOfRange(0, 32)
        val expect = hmac16(secret, "unilink-resume-v1".toByteArray(),
                            sessionId, reqPub, freshPub)
        require(java.security.MessageDigest.isEqual(expect, body.copyOfRange(32, 48))) {
            "resume_ok: mac mismatch"
        }
        return freshPub
    }

    // ---------------------------------------------------------- errors
    /** Structured error: fatal(1) code(u16be) len(u16be) msg. */
    fun errorBody(fatal: Boolean, code: Int, msg: String): ByteArray {
        val m = msg.toByteArray(Charsets.UTF_8).copyOf(120)
        return byteArrayOf(
            if (fatal) 1 else 0,
            (code ushr 8).toByte(), code.toByte(),
            (m.size ushr 8).toByte(), m.size.toByte()
        ) + m
    }

    data class DeviceIdentity(val deviceId: ByteArray, val identityPub: ByteArray,
                              val name: String, val platform: String,
                              val appVer: String, val caps: Int)

    data class DeviceAuth(val decision: Int, val sessionId: ByteArray,
                          val senderId: ByteArray)

    data class ResumeReq(val sessionId: ByteArray, val freshPub: ByteArray,
                         val resumeNonce: ByteArray)
}
