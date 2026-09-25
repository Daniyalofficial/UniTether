package com.unilink.core

import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * ULP session over a raw socket — device role. Conformance port of
 * tests/e2e/ulp_link.py: per-direction nonce counters, AAD = exact wire
 * header (ciphertext length included, F_ENCRYPTED set), plaintext
 * handshake then AEAD-only.
 */
class UlpSession(private val in: InputStream, private val out: OutputStream) {
    private val random = SecureRandom()
    private var txCounter = 0L
    private var rxCounter = 0L
    private var keyAead: ByteArray = ByteArray(32)
    private var keyMac: ByteArray = ByteArray(32)
    private var encrypted = false
    var peerFeatures: Int = 0
        private set

    class Keys(val aead: ByteArray, val mac: ByteArray, val cipherSel: Int)

    /** Device side: verify HELLO, send HELLO_ACK, mutual AUTH_OK. */
    fun startDevice(secret: ByteArray, features: Int): Keys {
        val (mtype, body) = recvMsg()
        require(mtype == UlpMessages.MSG_HELLO) { "expected HELLO, got ${mtype.toString(16)}" }
        val hello = UlpMessages.helloVerify(body, secret)
        val nonceB = ByteArray(16).also { random.nextBytes(it) }
        val priv = ByteArray(32).also { random.nextBytes(it) }
        val pub = UlpCrypto.x25519Public(priv)
        val sel = UlpMessages.CIPHER_INTEROP
        sendMsg(UlpMessages.MSG_HELLO_ACK,
            UlpMessages.helloAckBody(features, sel, pub, nonceB, hello.nonceA, secret))
        val shared = UlpCrypto.x25519(priv, hello.ecdhPub)
        val (ka, km) = UlpMessages.sessionKeys(shared, hello.nonceA, nonceB, sel)
        keyAead = ka; keyMac = km
        sendMsg(UlpMessages.MSG_AUTH_OK, ByteArray(0))
        val (mtype2, _) = recvMsg()
        require(mtype2 == UlpMessages.MSG_AUTH_OK) { "missing peer AUTH_OK" }
        encrypted = true
        peerFeatures = hello.featureMask
        return Keys(ka, km, sel)
    }

    private fun recvExact(n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = in.read(buf, off, n - off)
            if (r < 0) throw UlpError("peer closed")
            off += r
        }
        return buf
    }

    fun recvFrame(): UlpFrame.Frame {
        val hdr7 = recvExact(7)
        val ln = ((hdr7[5].toInt() and 0xFF) shl 8) or (hdr7[6].toInt() and 0xFF)
        val hdr = if (ln == 0x8000) hdr7 + recvExact(4) else hdr7
        val size = if (ln == 0x8000) {
            (((hdr[7].toInt() and 0xFF) shl 24) or ((hdr[8].toInt() and 0xFF) shl 16) or
             ((hdr[9].toInt() and 0xFF) shl 8) or (hdr[10].toInt() and 0xFF))
        } else ln
        var payload = recvExact(size)
        val channel = hdr[3].toInt() and 0xFF
        val flags = hdr[4].toInt() and 0xFF
        val enc = (flags and UlpFrame.F_ENCRYPTED) != 0
        require(enc == encrypted) { "encryption state mismatch" }
        if (enc) {
            // peer = host, direction bit 0
            val nonce = UlpFrame.nonce(rxCounter++, channel, 0)
            payload = UlpCrypto.interopDecrypt(keyAead, keyMac, nonce, hdr, payload)
        }
        return UlpFrame.Frame(channel, flags and UlpFrame.F_ENCRYPTED.let { it.inv() and 0xFF }, payload)
    }

    fun sendFrame(channel: Int, flags: Int, payload: ByteArray) {
        if (encrypted) {
            val wireLen = payload.size + 16
            val wire = UlpFrame.Frame(channel, (flags or UlpFrame.F_ENCRYPTED) and 0xFF,
                ByteArray(wireLen))
            val hdr = wire.headerBytes()
            val nonce = UlpFrame.nonce(txCounter++, channel, 1) // device dir = 1
            val ct = UlpCrypto.interopEncrypt(keyAead, keyMac, nonce, hdr, payload)
            require(ct.size == wireLen) { "interop length mismatch" }
            out.write(hdr); out.write(ct)
        } else {
            out.write(UlpFrame.Frame(channel, flags, payload).encode())
        }
        out.flush()
    }

    fun sendMsg(mtype: Int, body: ByteArray) {
        sendFrame(UlpFrame.CH_CONTROL, 0, UlpMessages.encode(mtype, body))
    }

    fun recvMsg(): Pair<Int, ByteArray> {
        while (true) {
            val f = recvFrame()
            require(f.channel == UlpFrame.CH_CONTROL) { "expected control, got ${f.channel.toString(16)}" }
            val m = UlpMessages.decode(f.payload)
            return m.mtype to m.body
        }
    }

    fun close() {
        try { in.close() } catch (_: Exception) {}
        try { out.close() } catch (_: Exception) {}
    }

    companion object {
        @JvmStatic
        fun randomBytes(n: Int): ByteArray {
            val b = ByteArray(n)
            SecureRandom().nextBytes(b)
            return b
        }

        @JvmStatic
        fun formatIp(o: ByteArray): String =
            if (o.size == 4) o.joinToString(".") { (it.toInt() and 0xFF).toString() } else o.toHex()
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
