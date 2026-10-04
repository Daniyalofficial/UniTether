package com.unilink.productivity

import android.content.Context
import android.util.Log
import com.unilink.core.UlpFrame
import com.unilink.core.UlpSession
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

/**
 * Bidirectional file transfer over CH_FILE (spec section 12) — v2.
 *
 * Wire ops (conformance port of tests/protocol/file_transfer.py):
 *   0x00 meta       direction, file_id, u64 total, u16 len + name
 *   0x01 data       direction, file_id, u32 seq, u64 offset, chunk
 *   0x02 ack        direction, file_id, u32 seq_ack
 *   0x03 cancel     direction, file_id
 *   0x04 done       direction, file_id
 *   0x05 resume_req direction, file_id, u64 expected_offset      (v2)
 *   0x06 resume_rsp direction, file_id, u64 offset, state(1)     (v2)
 *      state: 0 none | 1 partial | 2 complete
 *   0x07 checksum   direction, file_id, sha256(32)               (v2)
 *
 * v1 peers ignore 0x05-0x07 (unknown-op rule): backward compatible.
 *
 * v2 guarantees (mirror of the reference engine, tested in test_file.py):
 *  - writes go to .part files; commit is an atomic rename after the
 *    receiver verifies whole-file SHA-256 (MessageDigest — audited
 *    system library, no custom crypto)
 *  - name collisions get .1/.2 suffixes; identical re-sends
 *    (same bare name + size) are skipped, zero bytes transferred
 *  - resume: the sender asks for the receiver's contiguous offset and
 *    continues instead of restarting
 *  - integrity failure deletes the partial file; the receiver cancels
 *    and the sender restarts from 0
 *
 * Threading: the app runs ONE receive loop (MainActivity); this class
 * never blocks on the wire. Outgoing transfers are a small state
 * machine advanced by deliver() — all frame I/O stays in the single
 * consumer (no double consumer, no send/recv races).
 */
class FileTransfer(private val context: Context, private val session: UlpSession) {

    private val TAG = "UlpFileTransfer"
    private val pending = ConcurrentHashMap<Long, PendingFile>()
    private val activeSend = AtomicReference<SendState?>()
    private val DEFAULT_CHUNK = 256 * 1024

    data class PendingFile(
        val direction: Int,
        val file: File?,
        val part: File?,
        val name: String,
        val total: Long,
        var written: Long = 0,
        var done: Boolean = false,
        var dupComplete: Boolean = false,
    )

    /** phase: 0 = waiting resume_rsp, 1 = data (ack-driven), 2 = checksum ack */
    private class SendState(
        val fileId: Long,
        val src: File,
        val total: Long,
        var offset: Long,
        var seq: Int,
        var phase: Int,
        val startedFrom: Long,
    )

    var onTransferComplete: ((name: String, bytes: Long, direction: Int) -> Unit)? = null
    var onIntegrityFailure: ((name: String) -> Unit)? = null
    var onSendComplete: ((fileId: Long, skipped: Boolean) -> Unit)? = null

    fun deliver(payload: ByteArray) {
        if (payload.size < 6) return
        val op = payload[0].toInt() and 0xFF
        val dir = payload[1].toInt() and 0xFF
        val fileId = readU32(payload, 2).toLong()
        // sender state machine first (responses for our own transfer)
        val st = activeSend.get()
        if (st != null && fileId == st.fileId && dir == 0) {
            advanceSend(st, op, payload)
            return
        }
        when (op) {
            0x00 -> onMeta(dir, fileId, payload)
            0x01 -> onData(dir, fileId, payload)
            0x02 -> {}
            0x03 -> onCancel(dir, fileId)
            0x04 -> onDone(dir, fileId)
            0x05 -> onResumeReq(dir, fileId, payload)
            0x06 -> {}
            0x07 -> onChecksum(dir, fileId, payload)
        }
    }

    // ------------------------------------------------------ receiver
    private fun onMeta(dir: Int, fileId: Long, payload: ByteArray) {
        val total = readU64(payload, 6)
        val nameLen = ((payload[14].toInt() and 0xFF) shl 8) or (payload[15].toInt() and 0xFF)
        val name = String(payload, 16, nameLen, Charsets.UTF_8)
        val baseDir = File(context.getExternalFilesDir(null) ?: context.filesDir, "Inbox")
        baseDir.mkdirs()
        val clean = sanitize(name)
        val dupComplete = clean.isFile() && File(baseDir, clean).length() == total
        val final = uniquePath(baseDir, clean)
        val part = File(baseDir, ".${fileId.toString(16).padStart(8, '0')}.part")
        pending[fileId] = PendingFile(dir, final, part, clean, total,
            dupComplete = dupComplete)
        Log.i(TAG, "meta id=$fileId name=$clean total=$total dup=$dupComplete")
        if (dir == 1) sendMeta(fileId, name, total)
    }

    private fun onData(dir: Int, fileId: Long, payload: ByteArray) {
        val p = pending[fileId] ?: return
        if (p.done) return
        val seq = readU32(payload, 6)
        val offset = readU64(payload, 10)
        if (dir == 0) {
            val partF = p.part ?: return
            RandomAccessFile(partF, "rw").use { f ->
                if (f.length() < offset) f.setLength(offset)
                f.seek(offset)
                f.write(payload, 18, payload.size - 18)
            }
            p.written = maxOf(p.written, offset + (payload.size - 18))
            sendAck(1 - dir, fileId, seq)
        }
    }

    private fun onDone(dir: Int, fileId: Long) {
        val p = pending[fileId] ?: return
        p.done = true
    }

    private fun onResumeReq(dir: Int, fileId: Long, payload: ByteArray) {
        val p = pending[fileId]
        val offset: Long
        val state: Int
        when {
            p == null -> { offset = 0L; state = 0 }
            p.dupComplete -> { offset = p.total; state = 2 }
            p.part != null && p.part.length() >= p.total -> {
                offset = p.total; state = 2
            }
            p.part != null && p.part.length() > 0 -> {
                offset = p.part.length(); state = 1
            }
            else -> { offset = 0L; state = 0 }
        }
        val b = ByteArray(15)
        b[0] = 0x06; b[1] = (1 - dir).toByte()
        putU32(b, 2, fileId.toInt())
        putU64(b, 6, offset)
        b[14] = state.toByte()
        send(b)
    }

    private fun onChecksum(dir: Int, fileId: Long, payload: ByteArray) {
        if (payload.size != 38) return
        val p = pending[fileId] ?: return
        if (!p.done) return
        val expected = payload.copyOfRange(6, 38)
        val partF = p.part ?: return
        val actual = sha256(partF)
        if (actual.contentEquals(expected)) {
            val finalF = p.file ?: return
            if (!partF.renameTo(finalF)) {
                partF.copyTo(finalF, overwrite = true)
                partF.delete()
            }
            pending.remove(fileId)
            Log.i(TAG, "committed id=$fileId -> ${finalF.name}")
            onTransferComplete?.invoke(p.name, p.total, dir)
            sendAck(1 - dir, fileId, -1) // 0xFFFF
        } else {
            partF.delete()
            p.done = false
            p.written = 0
            Log.w(TAG, "INTEGRITY FAILURE id=$fileId — partial deleted, cancel sent")
            onIntegrityFailure?.invoke(p.name)
            sendCancel(1 - dir, fileId)
        }
    }

    private fun onCancel(dir: Int, fileId: Long) {
        val p = pending.remove(fileId) ?: return
        p.part?.delete()
    }

    // ------------------------------------------------------ sender (state machine)
    /**
     * Start an outgoing transfer: meta + resume_req. Continuation is
     * driven by deliver() (single consumer). One active send at a time.
     */
    fun beginSend(src: File, fileId: Long, name: String) {
        if (activeSend.get() != null) {
            Log.w(TAG, "beginSend: send already active")
            return
        }
        val total = src.length()
        sendMeta(fileId, name, total)
        val st = SendState(fileId, src, total, 0L, 0, 0, 0L)
        activeSend.set(st)
        sendResumeReq(fileId, 0L)
    }

    private fun advanceSend(st: SendState, op: Int, payload: ByteArray) {
        when {
            st.phase == 0 && op == 0x06 -> {
                val state = payload[14].toInt() and 0xFF
                when (state) {
                    2 -> {
                        activeSend.set(null)
                        onSendComplete?.invoke(st.fileId, true) // duplicate
                    }
                    1 -> {
                        st.offset = readU64(payload, 6)
                        st.startedFrom = st.offset
                        st.seq = (st.offset / DEFAULT_CHUNK).toInt()
                        st.phase = 1
                        sendNextChunk(st)
                    }
                    else -> { st.phase = 1; sendNextChunk(st) }
                }
            }
            st.phase == 1 && op == 0x02 -> {
                if (st.offset < st.total) {
                    sendNextChunk(st)
                } else {
                    sendDone(st)
                    sendChecksum(st)
                    st.phase = 2
                }
            }
            st.phase == 1 && op == 0x03 -> {
                // receiver integrity failure: restart from 0
                Log.w(TAG, "send id=${st.fileId} canceled — restarting from 0")
                st.offset = 0L
                st.seq = 0
                sendResumeReq(st.fileId, 0L)
                st.phase = 0
            }
            st.phase == 2 && op == 0x02 -> {
                activeSend.set(null)
                Log.i(TAG, "sent id=${st.fileId} total=${st.total} from=${st.startedFrom}")
                onSendComplete?.invoke(st.fileId, false)
            }
            st.phase == 2 && op == 0x03 -> {
                activeSend.set(null)
                Log.e(TAG, "send id=${st.fileId} integrity FAILED after checksum")
                onSendComplete?.invoke(st.fileId, false)
            }
        }
    }

    private fun sendNextChunk(st: SendState) {
        val n = minOf(DEFAULT_CHUNK, (st.total - st.offset).toInt())
        val buf = ByteArray(n)
        RandomAccessFile(st.src, "r").use { f ->
            f.seek(st.offset)
            f.readFully(buf)
        }
        val b = ByteArray(18 + n)
        b[0] = 0x01; b[1] = 1
        putU32(b, 2, st.fileId.toInt())
        putU32(b, 6, st.seq)
        putU64(b, 10, st.offset)
        buf.copyInto(b, 18)
        send(b)
        st.offset += n
        st.seq++
    }

    private fun sendDone(st: SendState) {
        val d = ByteArray(6)
        d[0] = 0x04; d[1] = 1
        putU32(d, 2, st.fileId.toInt())
        send(d)
    }

    private fun sendChecksum(st: SendState) {
        val digest = sha256(st.src)
        val c = ByteArray(38)
        c[0] = 0x07; c[1] = 1
        putU32(c, 2, st.fileId.toInt())
        digest.copyInto(c, 6)
        send(c)
    }

    private fun sendResumeReq(fileId: Long, expected: Long) {
        val b = ByteArray(14)
        b[0] = 0x05; b[1] = 1
        putU32(b, 2, fileId.toInt())
        putU64(b, 6, expected)
        send(b)
    }

    // ------------------------------------------------------ frame helpers
    private fun send(b: ByteArray) {
        runCatching { session.sendFrame(UlpFrame.CH_FILE, 0, b) }
    }

    private fun sendAck(dir: Int, fileId: Long, seq: Int) {
        val b = ByteArray(10)
        b[0] = 0x02; b[1] = dir.toByte()
        putU32(b, 2, fileId.toInt())
        putU32(b, 6, seq)
        send(b)
    }

    private fun sendCancel(dir: Int, fileId: Long) {
        val b = ByteArray(6)
        b[0] = 0x03; b[1] = dir.toByte()
        putU32(b, 2, fileId.toInt())
        send(b)
    }

    private fun sendMeta(fileId: Long, name: String, total: Long) {
        val n = name.toByteArray(Charsets.UTF_8)
        val b = ByteArray(16 + n.size)
        b[0] = 0x00; b[1] = 1
        putU32(b, 2, fileId.toInt())
        putU64(b, 6, total)
        b[14] = ((n.size shr 8) and 0xFF).toByte(); b[15] = (n.size and 0xFF).toByte()
        n.copyInto(b, 16)
        send(b)
    }

    private fun uniquePath(dir: File, name: String): File {
        var cand = File(dir, name)
        if (!cand.exists()) return cand
        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""
        var i = 1
        while (true) {
            cand = File(dir, "$stem.$i$ext")
            if (!cand.exists()) return cand
            i++
        }
    }

    private fun sha256(f: File): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { ins ->
            val buf = ByteArray(1 shl 20)
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest()
    }

    private fun sanitize(name: String): String =
        name.replace(Regex("[^A-Za-z0-9._-]"), "_").takeWhile { it != '/' }
            .ifEmpty { "file" }

    private fun readU32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
        ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun readU64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0..7) v = (v shl 8) or (b[off + i].toLong() and 0xFF)
        return v
    }

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
