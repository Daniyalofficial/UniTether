package com.unilink.core

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** ULP v1 CONTROL messages — conformance port of reference_framing.py. */
object UlpMessages {
    const val MSG_HELLO = 0x01
    const val MSG_HELLO_ACK = 0x02
    const val MSG_AUTH_OK = 0x04
    const val MSG_PING = 0x05
    const val MSG_PONG = 0x06
    const val MSG_CONFIG = 0x07
    const val MSG_TUN_UP = 0x08
    const val MSG_TUN_DOWN = 0x09
    const val MSG_STATS_REQ = 0x0A
    const val MSG_STATS_RSP = 0x0B
    const val MSG_MUTE = 0x0C
    const val MSG_QOS = 0x0D
    const val MSG_RESUME = 0x0E
    const val MSG_BYE = 0x0F
    const val MSG_ERROR = 0x10

    const val CIPHER_NONE = 0
    const val CIPHER_INTEROP = 1
    const val CIPHER_AESGCM = 2
    const val CIPHER_CHACHA = 3

    const val ROLE_HOST = 0
    const val ROLE_DEVICE = 1

    const val MUTE_VIDEO = 0x01
    const val MUTE_AUDIO_IN = 0x02
    const val MUTE_AUDIO_OUT = 0x04
    const val MUTE_INPUT = 0x08

    const val QOS_NONE = 0
    const val QOS_2G = 1
    const val QOS_3G = 2
    const val QOS_4G = 3
    const val QOS_5G = 4

    const val HELLO_BODY_LEN = 84
    const val HELLO_ACK_BODY_LEN = 83

    data class Message(val mtype: Int, val flags: Int, val body: ByteArray)

    fun encode(mtype: Int, body: ByteArray): ByteArray {
        val out = ByteArray(4 + body.size)
        out[0] = mtype.toByte(); out[1] = 0
        out[2] = ((body.size shr 8) and 0xFF).toByte()
        out[3] = (body.size and 0xFF).toByte()
        System.arraycopy(body, 0, out, 4, body.size)
        return out
    }

    fun decode(payload: ByteArray): Message {
        if (payload.size < 4) throw UlpError("short message")
        val mtype = payload[0].toInt() and 0xFF
        val flags = payload[1].toInt() and 0xFF
        val blen = ((payload[2].toInt() and 0xFF) shl 8) or (payload[3].toInt() and 0xFF)
        if (payload.size < 4 + blen) throw UlpError("short message body")
        return Message(mtype, flags, payload.copyOfRange(4, 4 + blen))
    }

    // -------------------------------------------------------------- pairing
    private val AUTH_INFO = "unilink-auth-v1".toByteArray()

    fun pairingMac(secret: ByteArray, ecdhPub: ByteArray, nonce: ByteArray): ByteArray =
        UlpCrypto.hmacSha256(secret, AUTH_INFO + ecdhPub + nonce)

    fun helloBody(role: Int, featureMask: Int, cipherPref: Int,
                  ecdhPub: ByteArray, nonceA: ByteArray, secret: ByteArray): ByteArray {
        require(ecdhPub.size == 32 && nonceA.size == 16)
        val mac = pairingMac(secret, ecdhPub, nonceA)
        val b = ByteArray(HELLO_BODY_LEN)
        b[0] = role.toByte()
        b[1] = ((featureMask shr 8) and 0xFF).toByte()
        b[2] = (featureMask and 0xFF).toByte()
        b[3] = cipherPref.toByte()
        ecdhPub.copyInto(b, 4)
        nonceA.copyInto(b, 36)
        mac.copyInto(b, 52)
        return b
    }

    fun helloVerify(body: ByteArray, secret: ByteArray): Hello {
        if (body.size != HELLO_BODY_LEN) throw UlpError("hello: bad length ${body.size}")
        val role = body[0].toInt() and 0xFF
        val featureMask = ((body[1].toInt() and 0xFF) shl 8) or (body[2].toInt() and 0xFF)
        val cipherPref = body[3].toInt() and 0xFF
        val pub = body.copyOfRange(4, 36)
        val nonceA = body.copyOfRange(36, 52)
        val mac = body.copyOfRange(52, 84)
        val expect = pairingMac(secret, pub, nonceA)
        require(mac.contentEquals(expect)) { "hello: pairing mac mismatch" }
        return Hello(role, featureMask, cipherPref, pub, nonceA)
    }

    data class Hello(val role: Int, val featureMask: Int, val cipherPref: Int,
                     val ecdhPub: ByteArray, val nonceA: ByteArray)

    fun helloAckBody(negotiated: Int, cipherSel: Int, ecdhPub: ByteArray,
                     nonceB: ByteArray, nonceA: ByteArray, secret: ByteArray): ByteArray {
        val mac = UlpCrypto.hmacSha256(secret, AUTH_INFO + ecdhPub + nonceB + nonceA)
        val b = ByteArray(HELLO_ACK_BODY_LEN)
        b[0] = ((negotiated shr 8) and 0xFF).toByte()
        b[1] = (negotiated and 0xFF).toByte()
        b[2] = cipherSel.toByte()
        ecdhPub.copyInto(b, 3)
        nonceB.copyInto(b, 35)
        mac.copyInto(b, 51)
        return b
    }

    fun helloAckVerify(body: ByteArray, secret: ByteArray, nonceA: ByteArray): HelloAck {
        if (body.size != HELLO_ACK_BODY_LEN) throw UlpError("hello_ack: bad length ${body.size}")
        val negotiated = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        val cipherSel = body[2].toInt() and 0xFF
        val pub = body.copyOfRange(3, 35)
        val nonceB = body.copyOfRange(35, 51)
        val mac = body.copyOfRange(51, 83)
        val expect = UlpCrypto.hmacSha256(secret, AUTH_INFO + pub + nonceB + nonceA)
        require(mac.contentEquals(expect)) { "hello_ack: pairing mac mismatch" }
        return HelloAck(negotiated, cipherSel, pub, nonceB)
    }

    data class HelloAck(val negotiated: Int, val cipherSel: Int,
                        val ecdhPub: ByteArray, val nonceB: ByteArray)

    // ----------------------------------------------------------- session keys
    fun sessionKeys(shared: ByteArray, nonceA: ByteArray, nonceB: ByteArray,
                    cipherSel: Int): Pair<ByteArray, ByteArray> {
        val info = "unilink-v1".toByteArray() + byteArrayOf(cipherSel.toByte())
        val keys = UlpCrypto.hkdfSha256(shared, nonceA + nonceB, info, 64)
        return keys.copyOf(32) to keys.copyOfRange(32, 64)
    }

    // ------------------------------------------------------------- CONFIG
    class Config(
        val v4Prefix: Int,
        val v4Device: ByteArray, // 4
        val v4Host: ByteArray,   // 4
        val v6Prefix: Int,
        val v6Device: ByteArray, // 16
        val v6Host: ByteArray,   // 16
        val dns: List<ByteArray>,
        val routes: List<Pair<Int, ByteArray>>,
    )

    fun configBody(c: Config): ByteArray {
        val b = java.io.ByteArrayOutputStream()
        b.write(c.v4Prefix and 0xFF)
        b.write(c.v4Device); b.write(c.v4Host)
        b.write(c.v6Prefix and 0xFF)
        if (c.v6Prefix > 0) { b.write(c.v6Device); b.write(c.v6Host) }
        b.write((c.dns.size shr 8) and 0xFF); b.write(c.dns.size and 0xFF)
        c.dns.forEach { b.write(it) }
        b.write((c.routes.size shr 8) and 0xFF); b.write(c.routes.size and 0xFF)
        c.routes.forEach { (p, a) -> b.write(p and 0xFF); b.write(a) }
        return b.toByteArray()
    }

    // --------------------------------------------------------------- STATS
    fun statsBody(bytesIn: Long, bytesOut: Long, pktsIn: Long, pktsOut: Long,
                  bytesVideo: Long, bytesAudio: Long, bytesFile: Long, drops: Long,
                  errors: Long, framesVideo: Long, rttMs: Int, lossPctX100: Int,
                  cpuPctX100: Int, fpsVideo: Int, audioLevel: Int): ByteArray {
        val b = ByteBuffer.allocate(104).order(ByteOrder.BIG_ENDIAN)
        longArrayOf(bytesIn, bytesOut, pktsIn, pktsOut, bytesVideo, bytesAudio,
            bytesFile, drops, errors, framesVideo).forEach { b.putLong(it) }
        intArrayOf(rttMs, lossPctX100, cpuPctX100, fpsVideo, audioLevel, 0).forEach { b.putInt(it) }
        return b.array()
    }

    // ----------------------------------------------------------------- QOS
    fun qosBody(profile: Int, upKbps: Int, downKbps: Int,
                latencyMs: Int, jitterMs: Int, lossPct: Int): ByteArray {
        val b = ByteBuffer.allocate(13).order(ByteOrder.BIG_ENDIAN)
        b.put(profile.toByte())
        b.putInt(upKbps); b.putInt(downKbps)
        b.putShort(latencyMs.toShort())
        b.put(jitterMs.toByte()); b.put(lossPct.toByte())
        return b.array()
    }
}
