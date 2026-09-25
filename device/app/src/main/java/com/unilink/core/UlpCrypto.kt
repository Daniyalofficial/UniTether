package com.unilink.core

import java.math.BigInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * ULP v1 crypto — conformance port of reference_framing.py.
 *
 * X25519 is implemented in pure Kotlin (BigInteger) so it behaves
 * identically on every API 21+ device (Conscrypt X25519 only exists
 * from API 25). Verified against RFC 7748 §6.1 in tests.
 */
object UlpCrypto {
    private val P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665)
    private val TWO_POW = BigInteger.TWO

    // ------------------------------------------------------------- X25519
    fun clamp(secret: ByteArray): BigInteger {
        // RFC 7748 decodeScalar25519: k &= ~7; clear bit 255; set bit 254
        val allOnes = BigInteger.TWO.pow(256).subtract(BigInteger.ONE)
        var k = BigInteger(1, secret)
        k = k.and(allOnes.xor(BigInteger.valueOf(7)))          // clear low 3 bits
        k = k.and(TWO_POW.pow(255).subtract(BigInteger.ONE))   // clear bit 255
        k = k.or(TWO_POW.pow(254))                             // set bit 254
        return k
    }

    fun x25519Public(secret: ByteArray): ByteArray {
        return x25519(secret, ByteArray(32).also { it[0] = 9 })
    }

    fun x25519(secret: ByteArray, uBytes: ByteArray): ByteArray {
        val k = clamp(secret)
        var u = BigInteger(1, uBytes).mod(P)

        var x1 = u
        var z1 = BigInteger.ONE
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = u
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = if (k.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = kt
            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).mod(P).let { it.multiply(it).mod(P) }
            val dmc = da.subtract(cb).mod(P)
            z3 = x1.multiply(dmc.multiply(dmc).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e).mod(P)).mod(P)).mod(P)
        }
        val res = x2.multiply(z2.modInverse(P)).mod(P)
        return res.toByteArray32()
    }

    // ---------------------------------------------------------------- HKDF
    fun hmacSha256(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val s = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmacSha256(s, ikm)
        val out = ByteArray(length)
        var offset = 0
        var block = ByteArray(0)
        var i = 1
        while (offset < length) {
            block = hmacSha256(prk, block + info + byteArrayOf(i.toByte()))
            val n = minOf(32, length - offset)
            block.copyInto(out, offset, 0, n)
            offset += n
            i++
        }
        return out
    }

    // ------------------------------------------------------- INTEROP cipher
    fun interopKeystream(keyAead: ByteArray, nonce: ByteArray, n: Int): ByteArray {
        val ks = ByteArray(n)
        var i = 0
        var o = 0
        while (o < n) {
            val input = keyAead + nonce + ByteArray(4).also {
                it[0] = ((i >>> 24) and 0xFF).toByte()
                it[1] = ((i >>> 16) and 0xFF).toByte()
                it[2] = ((i >>> 8) and 0xFF).toByte()
                it[3] = (i and 0xFF).toByte()
            }
            val block = sha256(input)
            val take = minOf(32, n - o)
            block.copyInto(ks, o, 0, take)
            o += take
            i++
        }
        return ks
    }

    fun interopEncrypt(keyAead: ByteArray, keyMac: ByteArray, nonce: ByteArray,
                       aad: ByteArray, pt: ByteArray): ByteArray {
        val ks = interopKeystream(keyAead, nonce, pt.size)
        val ct = ByteArray(pt.size) { pt[it] xor ks[it] }
        val tag = hmacSha256(keyMac, nonce + aad + ct).copyOf(16)
        return ct + tag
    }

    fun interopDecrypt(keyAead: ByteArray, keyMac: ByteArray, nonce: ByteArray,
                       aad: ByteArray, ctTag: ByteArray): ByteArray {
        if (ctTag.size < 16) throw UlpError("interop: too short")
        val ct = ctTag.copyOf(ctTag.size - 16)
        val tag = ctTag.copyOfRange(ctTag.size - 16, ctTag.size)
        val expect = hmacSha256(keyMac, nonce + aad + ct).copyOf(16)
        var diff = 0
        for (i in 0 until 16) diff = diff or (tag[i].toInt() xor expect[i].toInt())
        if (diff != 0) throw UlpError("interop: tag mismatch")
        val ks = interopKeystream(keyAead, nonce, ct.size)
        return ByteArray(ct.size) { ct[it] xor ks[it] }
    }

    // --------------------------------------------------------- SHA-256 (JCE)
    private fun sha256(data: ByteArray): ByteArray {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }
}

/** Big-endian 32-byte little-endian output (RFC 7748 encoding). */
private fun BigInteger.toByteArray32(): ByteArray {
    val le = toByteArray() // big-endian, maybe 33 bytes
    val out = ByteArray(32)
    for (i in 0 until 32) {
        val srcIdx = le.size - 1 - i
        out[i] = if (srcIdx >= 0) le[srcIdx] else 0
    }
    return out
}
