package com.unilink.mirror

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import com.unilink.MainActivity
import com.unilink.core.UlpFrame
import com.unilink.core.UlpMessages
import com.unilink.core.UlpSession

/** Foreground service that owns the MediaProjection consent flow and
 *  pumps encoded frames into the ULP session (video channel, keyframe
 *  first — spec section 10). */
class MirroringService : Service() {

    private var capturer: ScreenCapturer? = null
    private var session: UlpSession? = null

    companion object {
        const val ACTION_CONSENT_RESULT = "com.unilink.CONSENT_RESULT"
        const val NOTIF_CHANNEL = "unilink-mirror"
        const val NOTIF_ID = 43
        @Volatile var instance: MirroringService? = null
            private set
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        MirroringService.instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification())
        if (intent?.action == ACTION_CONSENT_RESULT) {
            capturer?.onResult(intent.getIntExtra("result", -1),
                intent.getParcelableExtra("data"))
        }
        return START_STICKY
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, NOTIF_CHANNEL)
        else Notification.Builder(this)
        return b.setContentTitle(getString(com.unilink.R.string.app_name))
            .setContentText(getString(com.unilink.R.string.mirror_running))
            .setSmallIcon(android.R.drawable.stat_sys_video_call)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    fun attach(capturer: ScreenCapturer, session: UlpSession) {
        this.capturer = capturer
        this.session = session
        capturer.onVideoFrame = { body, kind ->
            try {
                // Keyframes carry F_PRIORITY (spec 10.3)
                session.sendFrame(UlpFrame.CH_VIDEO,
                    if (kind == com.unilink.core.UlpChannels.VIDEO_KIND_KEY)
                        UlpFrame.F_PRIORITY else 0, body)
            } catch (e: Exception) {
                // session gone; MainActivity will restart mirroring
            }
        }
    }

    override fun onDestroy() {
        capturer?.stop()
        MirroringService.instance = null
        super.onDestroy()
    }
}
