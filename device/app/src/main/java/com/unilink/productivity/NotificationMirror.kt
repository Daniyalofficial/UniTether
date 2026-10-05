package com.unilink.productivity

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.unilink.core.UlpChannels
import com.unilink.core.UlpFrame
import com.unilink.core.UlpSession

/**
 * Notification mirroring (spec section 12): NotificationListenerService
 * forwards posted notifications to the host (CH_NOTIFICATION) so the
 * host GUI can show them — including SMS/WhatsApp previews that the
 * SmsReplier can answer.
 */
class NotificationMirror : NotificationListenerService() {

    companion object {
        @Volatile var session: UlpSession? = null
        private var counter = 0L
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val session = session ?: return
        val extras = sbn.notification?.extras ?: return
        val app = sbn.packageName ?: "unknown"
        val title = (extras.getCharSequence(Notification.EXTRA_TITLE) ?: "")
            .toString().take(120)
        val body = (extras.getCharSequence(Notification.EXTRA_TEXT) ?: "")
            .toString().take(280)
        val id = (sbn.id.toLong() shl 16) or (sbn.userHandle.hashCode().toLong() and 0xFFFF)
        counter++
        val payload = UlpChannels.notificationBody(
            id.toInt(), System.currentTimeMillis(), 0, app, title, body)
        try {
            session.sendFrame(UlpFrame.CH_NOTIFICATION, 0, payload)
        } catch (e: Exception) {
            Log.w("NotificationMirror", "send failed: ${e.message}")
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        val session = session ?: return
        val id = (sbn.id.toLong() shl 16) or (sbn.userHandle.hashCode().toLong() and 0xFFFF)
        val payload = UlpChannels.notificationBody(
            id.toInt(), System.currentTimeMillis(), 1, sbn.packageName ?: "", "", "")
        runCatching { session.sendFrame(UlpFrame.CH_NOTIFICATION, 0, payload) }
    }
}
