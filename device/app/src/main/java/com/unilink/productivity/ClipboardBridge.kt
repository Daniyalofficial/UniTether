package com.unilink.productivity

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.util.Log
import com.unilink.core.UlpChannels
import com.unilink.core.UlpFrame
import com.unilink.core.UlpSession

/**
 * Clipboard sync (spec section 12):
 *  * device -> host: ClipboardManager.OnPrimaryClipChangedListener
 *  * host -> device: CH_CLIPBOARD frames (direction=1)
 * Loop protection: a copy performed by the bridge is ignored for 2 s.
 */
class ClipboardBridge(
    private val context: Context,
    private val session: UlpSession,
) {
    private val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val main = Handler(Looper.getMainLooper())
    private var suppressUntil = 0L
    private var seq = 0

    private val listener = ClipboardManager.OnPrimaryClipChangedListener {
        val clip = cm.primaryClip ?: return@OnPrimaryClipChangedListener
        if (System.currentTimeMillis() < suppressUntil) return@OnPrimaryClipChangedListener
        val item = clip.getItemAt(0) ?: return@OnPrimaryClipChangedListener
        val text = item.coerceToText(context)?.toString()
        if (text.isNullOrEmpty() || TextUtils.isEmpty(item.label)) {
            if (item.targetUri != null) return@OnPrimaryClipChangedListener
        }
        if (text.isNullOrEmpty()) return@OnPrimaryClipChangedListener
        seq = (seq + 1) and 0x7FFF_FFFF
        val body = UlpChannels.clipboardBody(0, 0, text.toByteArray(Charsets.UTF_8))
        try {
            session.sendFrame(UlpFrame.CH_CLIPBOARD, 0, body)
        } catch (e: Exception) {
            Log.w("ClipboardBridge", "send failed: ${e.message}")
        }
    }

    fun start() {
        main.post { cm.addPrimaryClipChangedListener(listener) }
    }

    fun deliverHostClip(payload: ByteArray) {
        val c = UlpChannels.clipboardParse(payload)
        if (c.direction != 1) return
        val text = String(c.data, Charsets.UTF_8)
        suppressUntil = System.currentTimeMillis() + 2000
        main.post {
            val clip = ClipData.newPlainText("UniTether", text)
            cm.setPrimaryClip(clip)
        }
    }

    fun stop() {
        main.post { cm.removePrimaryClipChangedListener(listener) }
    }
}
