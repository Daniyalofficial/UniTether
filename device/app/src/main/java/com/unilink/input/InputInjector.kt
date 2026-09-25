package com.unilink.input

import android.os.Handler
import android.os.Looper
import android.view.InputEvent
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager
import android.content.Context
import android.util.DisplayMetrics
import android.view.WindowManager as WM

/**
 * Host -> device input (spec section 9): normalized (0..1000) touch
 * coordinates are mapped to the current display size; text is injected
 * via KeyCharacterMap; keys arrive as KeyEvent down/up pairs.
 */
class InputInjector(private val context: Context) {
    private val wm = context.getSystemService(Context.WINDOW_SERVICE) as WM
    private val main = Handler(Looper.getMainLooper())
    private val dm = DisplayMetrics()
    @Volatile var enabled = true

    @Suppress("DEPRECATION")
    private fun displaySize(): Pair<Int, Int> {
        wm.defaultDisplay.getRealMetrics(dm)
        return dm.widthPixels to dm.heightPixels
    }

    fun deliver(payload: ByteArray) {
        if (!enabled) return
        val ev = com.unilink.core.UlpChannels.inputParse(payload)
        main.post {
            when (ev.ty) {
                com.unilink.core.UlpChannels.INPUT_TOUCH -> injectTouch(ev)
                com.unilink.core.UlpChannels.INPUT_KEY -> injectKey(ev)
                com.unilink.core.UlpChannels.INPUT_MOUSE -> injectMouse(ev)
                com.unilink.core.UlpChannels.INPUT_TEXT -> injectText(ev.text)
            }
        }
    }

    private fun injectTouch(ev: com.unilink.core.UlpChannels.InputEvent) {
        val (w, h) = displaySize()
        val x = (ev.x / 1000f) * w
        val y = (ev.y / 1000f) * h
        val action = when (ev.action) {
            0 -> MotionEvent.ACTION_DOWN
            1 -> MotionEvent.ACTION_UP
            else -> MotionEvent.ACTION_MOVE
        }
        val t = System.currentTimeMillis()
        val me = MotionEvent.obtain(t, t, action, x, y, 1)
        // Inject via the focused window's callback (no root, no
        // AccessibilityService needed for touch — the app window is the
        // target of remote control by design; mirroring mode routes
        // events to the VirtualDisplay instead).
        inject(me)
        me.recycle()
    }

    private fun injectMouse(ev: com.unilink.core.UlpChannels.InputEvent) {
        val (w, h) = displaySize()
        val x = (ev.x / 1000f) * w
        val y = (ev.y / 1000f) * h
        val action = when (ev.action) {
            0 -> MotionEvent.ACTION_DOWN
            1 -> MotionEvent.ACTION_UP
            else -> MotionEvent.ACTION_MOVE
        }
        val t = System.currentTimeMillis()
        val me = MotionEvent.obtain(t, t, action, x, y, 0)
        inject(me)
        me.recycle()
    }

    private fun injectKey(ev: com.unilink.core.UlpChannels.InputEvent) {
        val code = ev.key.toInt() and 0xFFFF
        val down = KeyEvent(KeyEvent.ACTION_DOWN, code)
        val up = KeyEvent(KeyEvent.ACTION_UP, code)
        inject(down); inject(up)
    }

    private fun injectText(text: String) {
        val kcm = KeyCharacterMap.load(context)
        val t = System.currentTimeMillis()
        for (c in text) {
            val codes = kcm.getEvents(c.toString().toCharArray())
            if (codes == null || codes.isEmpty()) continue
            for (k in codes) { inject(k) }
        }
    }

    private fun inject(event: InputEvent) {
        // The clean, no-root path on API 24+: AccessibilityService
        // (input injection). Without it, events are queued for the
        // VirtualDisplay of the active mirror session.
        MirrorInputQueue.enqueue(event)
    }
}

/** Events waiting for the mirror's VirtualDisplay injection loop. */
object MirrorInputQueue {
    private val queue = ArrayDeque<java.io.Serializable>()

    fun enqueue(event: InputEvent) {
        synchronized(queue) { queue.addLast(event) }
    }

    fun drain(): List<InputEvent> {
        synchronized(queue) {
            val out = ArrayList<InputEvent>(queue.size)
            while (queue.isNotEmpty()) out.add(queue.removeFirst() as InputEvent)
            return out
        }
    }
}
