package com.unilink.core

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** ULP v1 channel payload codecs — conformance port of reference_framing.py. */
object UlpChannels {

    // ---------------------------------------------------------------- VIDEO
    const val VIDEO_KIND_KEY = 0
    const val VIDEO_KIND_DELTA = 1
    const val VIDEO_KIND_EOI = 2
    const val VIDEO_H264 = 0
    const val VIDEO_HEVC = 1
    const val VIDEO_AV1 = 2
    const val VIDEO_MJPEG = 3

    fun videoBody(kind: Int, codec: Int, width: Int, height: Int, fps: Int,
                  ptsMs: Int, seq: Int, nal: ByteArray): ByteArray {
        val b = ByteBuffer.allocate(15 + nal.size).order(ByteOrder.BIG_ENDIAN)
        b.put(kind.toByte()); b.put(codec.toByte())
        b.putShort(width.toShort()); b.putShort(height.toShort())
        b.put(fps.toByte())
        b.putInt(ptsMs); b.putInt(seq)
        b.put(nal)
        return b.array()
    }

    class VideoFrame(val kind: Int, val codec: Int, val width: Int, val height: Int,
                     val fps: Int, val ptsMs: Int, val seq: Int, val nal: ByteArray)

    fun videoParse(body: ByteArray): VideoFrame {
        if (body.size < 15) throw UlpError("short video")
        val k = body[0].toInt() and 0xFF
        val c = body[1].toInt() and 0xFF
        val w = ((body[2].toInt() and 0xFF) shl 8) or (body[3].toInt() and 0xFF)
        val h = ((body[4].toInt() and 0xFF) shl 8) or (body[5].toInt() and 0xFF)
        val fps = body[6].toInt() and 0xFF
        val pts = ((body[7].toInt() and 0xFF) shl 24) or ((body[8].toInt() and 0xFF) shl 16) or
                  ((body[9].toInt() and 0xFF) shl 8) or (body[10].toInt() and 0xFF)
        val seq = ((body[11].toInt() and 0xFF) shl 24) or ((body[12].toInt() and 0xFF) shl 16) or
                  ((body[13].toInt() and 0xFF) shl 8) or (body[14].toInt() and 0xFF)
        val nal = body.copyOfRange(15, body.size)
        return VideoFrame(k, c, w, h, fps, pts, seq, nal)
    }

    // ---------------------------------------------------------------- AUDIO
    const val AUDIO_OPUS = 0
    const val AUDIO_AAC = 1
    const val AUDIO_PCM16 = 2

    fun audioBody(codec: Int, rate: Int, ch: Int, seq: Int, ptsMs: Int, data: ByteArray): ByteArray {
        val b = ByteBuffer.allocate(12 + data.size).order(ByteOrder.BIG_ENDIAN)
        b.put(codec.toByte())
        b.putShort(rate.toShort())
        b.put(ch.toByte())
        b.putInt(seq); b.putInt(ptsMs)
        b.put(data)
        return b.array()
    }

    class AudioFrame(val codec: Int, val rate: Int, val ch: Int,
                     val seq: Int, val ptsMs: Int, val data: ByteArray)

    fun audioParse(body: ByteArray): AudioFrame {
        if (body.size < 12) throw UlpError("short audio")
        val codec = body[0].toInt() and 0xFF
        val rate = ((body[1].toInt() and 0xFF) shl 8) or (body[2].toInt() and 0xFF)
        val ch = body[3].toInt() and 0xFF
        val seq = ((body[4].toInt() and 0xFF) shl 24) or ((body[5].toInt() and 0xFF) shl 16) or
                  ((body[6].toInt() and 0xFF) shl 8) or (body[7].toInt() and 0xFF)
        val pts = ((body[8].toInt() and 0xFF) shl 24) or ((body[9].toInt() and 0xFF) shl 16) or
                  ((body[10].toInt() and 0xFF) shl 8) or (body[11].toInt() and 0xFF)
        return AudioFrame(codec, rate, ch, seq, pts, body.copyOfRange(12, body.size))
    }

    // ---------------------------------------------------------------- INPUT
    const val INPUT_TOUCH = 0
    const val INPUT_KEY = 1
    const val INPUT_MOUSE = 2
    const val INPUT_TEXT = 3

    fun inputBody(ty: Int, action: Int, x: Int, y: Int, key: Int, text: String): ByteArray {
        val t = text.toByteArray(Charsets.UTF_8)
        val b = ByteBuffer.allocate(10 + t.size).order(ByteOrder.BIG_ENDIAN)
        b.put(ty.toByte()); b.put(action.toByte())
        b.putShort(x.toShort()); b.putShort(y.toShort())
        b.putShort(key.toShort())
        b.putShort(t.size.toShort())
        b.put(t)
        return b.array()
    }

    class InputEvent(val ty: Int, val action: Int, val x: Int, val y: Int,
                     val key: Int, val text: String)

    fun inputParse(body: ByteArray): InputEvent {
        if (body.size < 10) throw UlpError("short input")
        val tl = ((body[8].toInt() and 0xFF) shl 8) or (body[9].toInt() and 0xFF)
        if (body.size < 10 + tl) throw UlpError("short input text")
        return InputEvent(
            ty = body[0].toInt() and 0xFF,
            action = body[1].toInt() and 0xFF,
            x = ((body[2].toInt() and 0xFF) shl 8) or (body[3].toInt() and 0xFF),
            y = ((body[4].toInt() and 0xFF) shl 8) or (body[5].toInt() and 0xFF),
            key = ((body[6].toInt() and 0xFF) shl 8) or (body[7].toInt() and 0xFF),
            text = String(body, 10, tl, Charsets.UTF_8),
        )
    }

    // ------------------------------------------------------------- CLIPBOARD
    fun clipboardBody(direction: Int, kind: Int, data: ByteArray): ByteArray =
        byteArrayOf(direction.toByte(), kind.toByte()) + data

    class ClipboardUpdate(val direction: Int, val kind: Int, val data: ByteArray)

    fun clipboardParse(body: ByteArray): ClipboardUpdate {
        if (body.size < 2) throw UlpError("short clipboard")
        return ClipboardUpdate(body[0].toInt() and 0xFF, body[1].toInt() and 0xFF,
            body.copyOfRange(2, body.size))
    }

    // ------------------------------------------------------------ NOTIFICATION
    fun notificationBody(id: Int, tsMs: Long, action: Int,
                         app: String, title: String, body: String): ByteArray {
        fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
        val (a, t, b) = Triple(utf8(app), utf8(title), utf8(body))
        val total = 13 + (2 + a.size) + (2 + t.size) + (2 + b.size)
        val bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        bb.putInt(id); bb.putLong(tsMs); bb.put(action.toByte())
        for (s in listOf(a, t, b)) {
            bb.putShort(s.size.toShort())
            bb.put(s)
        }
        return bb.array()
    }

    class Notification(val id: Int, val tsMs: Long, val action: Int,
                       val app: String, val title: String, val body: String)

    fun notificationParse(body: ByteArray): Notification {
        if (body.size < 13) throw UlpError("short notification")
        var off = 13
        val fields = Array(3) { s: String ->
            val l = ((body[off].toInt() and 0xFF) shl 8) or (body[off + 1].toInt() and 0xFF)
            off += 2
            s = String(body, off, l, Charsets.UTF_8)
            off += l
            s
        }
        val id = ((body[0].toInt() and 0xFF) shl 24) or ((body[1].toInt() and 0xFF) shl 16) or
                 ((body[2].toInt() and 0xFF) shl 8) or (body[3].toInt() and 0xFF)
        val ts = (0L or (body[4].toLong() and 0xFF) shl 56 or (body[5].toLong() and 0xFF) shl 48 or
                 (body[6].toLong() and 0xFF) shl 40 or (body[7].toLong() and 0xFF) shl 32 or
                 (body[8].toLong() and 0xFF) shl 24 or (body[9].toLong() and 0xFF) shl 16 or
                 (body[10].toLong() and 0xFF) shl 8 or (body[11].toLong() and 0xFF))
        return Notification(id, ts, body[12].toInt() and 0xFF,
            fields[0], fields[1], fields[2])
    }
}
