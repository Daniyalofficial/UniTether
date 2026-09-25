package com.unilink.productivity

import android.content.Context
import android.os.Build
import android.util.Log
import com.unilink.core.UlpFrame
import com.unilink.core.UlpSession
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Bidirectional file transfer over CH_FILE (spec section 12).
 *
 * Wire ops (conformance port of reference_framing.py):
 *   0x00 meta  direction, file_id, u64 total, u16 len + name
 *   0x01 data  direction, file_id, seq, u64 offset, chunk
 *   0x02 ack   direction, file_id, seq_ack
 *   0x03 cancel, 0x04 done
 *
 * Device side: incoming files land in Downloads/UniTether/; outgoing
 * files are chosen via SAF (ACTION_OPEN_DOCUMENT) by the UI.
 */
class FileTransfer(private val context: Context, private val session: UlpSession) {

    private val pending = ConcurrentHashMap<Long, PendingFile>()

    data class PendingFile(
        val direction: Int,
        val file: File?,
        val name: String,
        val total: Long,
        var written: Long = 0,
        var nextSeq: Int = 0,
    )

    fun deliver(payload: ByteArray) {
        val op = payload[0].toInt() and 0xFF
        val dir = payload[1].toInt() and 0xFF
        val fileId = ((payload[2].toInt() and 0xFF) shl 24) or ((payload[3].toInt() and 0xFF) shl 16) or
                     ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF).toLong()
        when (op) {
            0x00 -> onMeta(dir, fileId, payload)
            0x01 -> onData(dir, fileId, payload)
            0x02 -> onAck(dir, fileId, payload)
            0x03 -> pending.remove(fileId)
            0x04 -> pending.remove(fileId)
        }
    }

    private fun onMeta(dir: Int, fileId: Long, payload: ByteArray) {
        val total = (0L).let { acc ->
            var v = acc
            for (i in 6..13) v = (v shl 8) or (payload[i].toLong() and 0xFF)
            v
        }
        val nameLen = ((payload[14].toInt() and 0xFF) shl 8) or (payload[15].toInt() and 0xFF)
        val name = String(payload, 16, nameLen, Charsets.UTF_8)
        var file: File? = null
        if (dir == 0) { // host -> device
            val dirF = File(context.getExternalFilesDir(null) ?: context.filesDir, "Inbox")
            dirF.mkdirs()
            file = File(dirF, sanitize(name))
        }
        pending[fileId] = PendingFile(dir, file, name, total)
        if (dir == 1) sendMeta(fileId, name, total)
    }

    private fun onData(dir: Int, fileId: Long, payload: ByteArray) {
        val p = pending[fileId] ?: return
        val seq = ((payload[6].toInt() and 0xFF) shl 24) or ((payload[7].toInt() and 0xFF) shl 16) or
                  ((payload[8].toInt() and 0xFF) shl 8) or (payload[9].toInt() and 0xFF)
        val chunk = payload.copyOfRange(18, payload.size)
        if (dir == 0) {
            val f = p.file ?: return
            synchronized(f) {
                java.io.FileOutputStream(f, true).use { it.write(chunk) }
            }
            p.written += chunk.size
            sendAck(dir, fileId, seq)
            if (p.written >= p.total) {
                pending.remove(fileId)
                onTransferComplete?.invoke(p.name, p.written, dir)
            }
        }
    }

    private fun onAck(dir: Int, fileId: Long, payload: ByteArray) {
        // Outgoing ack: file fully read; nothing to do (SAF stream closed on done)
    }

    private fun sendAck(dir: Int, fileId: Long, seq: Int) {
        val b = ByteArray(10)
        b[0] = 0x02; b[1] = dir.toByte()
        putU32(b, 2, fileId.toInt())
        putU32(b, 6, seq)
        runCatching { session.sendFrame(UlpFrame.CH_FILE, 0, b) }
    }

    private fun sendMeta(fileId: Long, name: String, total: Long) {
        val n = name.toByteArray(Charsets.UTF_8)
        val b = ByteArray(16 + n.size)
        b[0] = 0x00; b[1] = 1
        putU32(b, 2, fileId.toInt())
        putU64(b, 6, total)
        b[14] = ((n.size shr 8) and 0xFF).toByte(); b[15] = (n.size and 0xFF).toByte()
        n.copyInto(b, 16)
        runCatching { session.sendFrame(UlpFrame.CH_FILE, 0, b) }
    }

    var onTransferComplete: ((name: String, bytes: Long, direction: Int) -> Unit)? = null

    private fun sanitize(name: String): String =
        name.replace(Regex("[^A-Za-z0-9._-]"), "_").takeWhile { it != '/' }
            .ifEmpty { "file" }

    private fun putU32(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v shr 24) and 0xFF).toByte()
        b[off + 1] = ((v shr 16) and 0xFF).toByte()
        b[off + 2] = ((v shr 8) and 0xFF).toByte()
        b[off + 3] = (v and 0xFF).toByte()
    }

    private fun putU64(b: ByteArray, off: Int, v: Long) {
        for (i in 0..7) b[off + i] = ((v shr (8 * (7 - i))) and 0xFF).toByte()
    }
}
