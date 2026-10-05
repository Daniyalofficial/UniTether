package com.unilink.core

/** Pairing blob: UNITETHER1:<base64url(32 B)>|<name<=32 B> — conformance port. */
object Pairing {
    const val PREFIX = "UNITETHER1:"
    private const val ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun base64UrlEncode(data: ByteArray): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xFF else 0
            val n = (b0 shl 16) or (b1 shl 8) or b2
            sb.append(ALPHABET[(n shr 18) and 63])
            sb.append(ALPHABET[(n shr 12) and 63])
            sb.append(if (i + 1 < data.size) ALPHABET[(n shr 6) and 63] else "=")
            sb.append(if (i + 2 < data.size) ALPHABET[n and 63] else "=")
            i += 3
        }
        return sb.toString()
    }

    fun base64UrlDecode(s: String): ByteArray {
        var n = s.length
        while (n > 0 && s[n - 1] == '=') n--
        require(n % 4 != 1) { "bad base64 length" }
        var acc = 0
        var bits = 0
        val out = java.io.ByteArrayOutputStream()
        for (i in 0 until n) {
            val c = s[i]
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '-', '+' -> 62
                '_', '/' -> 63
                else -> error("bad base64 char $c")
            }
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((acc shr bits) and 0xFF)
            }
        }
        return out.toByteArray()
    }

    fun blob(secret: ByteArray, name: String): String {
        require(secret.size == 32)
        val nb = name.encodeToByteArray().copyOf(minOf(32, name.length))
        val safe = String(nb, Charsets.UTF_8)
        return "$PREFIX${base64UrlEncode(secret)}|$safe"
    }

    fun parse(blob: String): Pair<ByteArray, String> {
        require(blob.startsWith(PREFIX)) { "bad pairing prefix" }
        val rest = blob.removePrefix(PREFIX)
        val idx = rest.indexOf('|')
        val b64 = if (idx >= 0) rest.substring(0, idx) else rest
        val name = if (idx >= 0) rest.substring(idx + 1) else ""
        val secret = base64UrlDecode(b64)
        require(secret.size == 32) { "bad pairing secret length" }
        return secret to name
    }
}
