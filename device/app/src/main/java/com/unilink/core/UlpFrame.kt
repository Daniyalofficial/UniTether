package com.unilink.core

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * ULP v1 framing — conformance port of tests/protocol/reference_framing.py
 * (must stay byte-identical; protocol/vectors/*.json is the gate).
 *
 * base header  (7 B): 55 4C ver channel flags len(u16be)
 * extended     (11 B): len==0x8000 -> u32be length follows (max 1 MiB)
 */
object UlpFrame {
    const val MAGIC0 = 0x55.toByte()
    const val MAGIC1 = 0x4C.toByte()
    const val VERSION = 1
    const val MAX_PAYLOAD = 0x0010_0000

    const val CH_CONTROL = 0x00
    const val CH_VIDEO = 0x01
    const val CH_AUDIO_IN = 0x02
    const val CH_AUDIO_OUT = 0x03
    const val CH_INPUT = 0x04
    const val CH_FILE = 0x05
    const val CH_CLIPBOARD = 0x06
    const val CH_NOTIFICATION = 0x07
    const val CH_STATS = 0x08
    const val CH_TUN_V4 = 0x09
    const val CH_TUN_V6 = 0x0A
    const val CH_PROXY = 0x0B
    const val CH_CAMERA = 0x0C
    const val CH_USER = 0x0D

    const val F_COMPRESSED = 0x01
    const val F_ENCRYPTED = 0x02
    const val F_FRAG = 0x04
    const val F_PRIORITY = 0x08
    const val F_ACK = 0x10

    class Frame(val channel: Int, val flags: Int, val payload: ByteArray) {
        fun headerBytes(): ByteArray {
            val h = if (payload.size >= 0x8000) ByteArray(11) else ByteArray(7)
            h[0] = MAGIC0; h[1] = MAGIC1; h[2] = VERSION.toByte()
            h[3] = channel.toByte(); h[4] = flags.toByte()
            if (payload.size >= 0x8000) {
                h[5] = 0x80.toByte(); h[6] = 0
                ByteBuffer.wrap(h, 7, 4).order(ByteOrder.BIG_ENDIAN).putInt(payload.size)
            } else {
                ByteBuffer.wrap(h, 5, 2).order(ByteOrder.BIG_ENDIAN).putShort(payload.size.toShort())
            }
            return h
        }

        fun encode(): ByteArray {
            val h = headerBytes()
            return h + payload
        }
    }

    /** Returns (frame, bytesConsumed) or null if `data` is incomplete. */
    fun decode(data: ByteArray, off: Int = 0): Pair<Frame, Int>? {
        if (data.size - off < 7) return null
        if (data[off] != MAGIC0 || data[off + 1] != MAGIC1)
            throw UlpError("bad magic")
        if (data[off + 2].toInt() != VERSION) throw UlpError("bad version")
        val channel = data[off + 3].toInt() and 0xFF
        val flags = data[off + 4].toInt() and 0xFF
        val ln = ((data[off + 5].toInt() and 0xFF) shl 8) or (data[off + 6].toInt() and 0xFF)
        val size: Int
        val headerLen: Int
        if (ln < 0x8000) { size = ln; headerLen = 7 }
        else if (ln == 0x8000) {
            if (data.size - off < 11) return null
            size = ByteBuffer.wrap(data, off + 7, 4).order(ByteOrder.BIG_ENDIAN).int
            if (size > MAX_PAYLOAD) throw UlpError("bad extended length")
            headerLen = 11
        } else throw UlpError("bad length field ${ln.toString(16)}")
        if (data.size - off < headerLen + size) return null
        val payload = data.copyOfRange(off + headerLen, off + headerLen + size)
        return Frame(channel, flags, payload) to (off + headerLen + size)
    }

    /** 12 B nonce: u64be((dir<<63)|counter) || u32be(channel). */
    fun nonce(counter: Long, channel: Int, direction: Int): ByteArray {
        val hi = ((direction.toLong() and 1L) shl 63) or (counter and ((1L shl 63) - 1))
        val n = ByteArray(12)
        val bb = ByteBuffer.wrap(n).order(ByteOrder.BIG_ENDIAN)
        bb.putLong(hi)
        bb.putInt(channel)
        return n
    }
}

class UlpError(msg: String) : RuntimeException(msg)
