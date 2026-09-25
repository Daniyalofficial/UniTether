package com.unilink.audio

import android.Manifest
import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.unilink.MainActivity
import com.unilink.core.UlpChannels
import com.unilink.core.UlpFrame
import com.unilink.core.UlpMessages
import com.unilink.core.UlpSession

/**
 * Bidirectional Opus audio (spec section 11):
 *  * IN  (device mic -> host): AudioRecord 48 kHz mono -> Opus encode ->
 *    CH_AUDIO_IN, per-stream mute via MUTE.
 *  * OUT (host speakers -> device): CH_AUDIO_OUT Opus frames -> decode ->
 *    AudioTrack (low-latency mode).
 */
class AudioBridgeService : Service() {

    private val tag = "AudioBridge"
    private var session: UlpSession? = null
    private var recorder: AudioRecord? = null
    private var player: AudioTrack? = null
    private var encHandle: Long = 0
    private var decHandle: Long = 0
    private var inSeq = 0
    private var outPts = 0L
    @Volatile private var mutedIn = false
    @Volatile private var running = false

    companion object {
        const val NOTIF_CHANNEL = "unilink-audio"
        const val NOTIF_ID = 44
        @Volatile var instance: AudioBridgeService? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        AudioBridgeService.instance = this
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, NOTIF_CHANNEL)
        else Notification.Builder(this)
        startForeground(NOTIF_ID, b
            .setContentTitle(getString(com.unilink.R.string.app_name))
            .setContentText(getString(com.unilink.R.string.audio_running))
            .setSmallIcon(android.R.drawable.stat_sys_audio)
            .setContentIntent(pi)
            .setOngoing(true)
            .build())
        return START_STICKY
    }

    fun attach(session: UlpSession) {
        this.session = session
        if (running) return
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED) {
            Log.w(tag, "RECORD_AUDIO not granted; input disabled")
            return
        }
        running = true
        encHandle = OpusJni.encoderCreate()
        decHandle = OpusJni.decoderCreate()

        val frame = OpusJni.FRAME_SAMPLES
        recorder = AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            OpusJni.SAMPLE_RATE,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            frame * 2 * 2
        ).also { it.startRecording() }

        player = AudioTrack(
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build()
            else AudioAttributes.DEFAULT,
            AudioFormat.Builder()
                .setSampleRate(OpusJni.SAMPLE_RATE)
                .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT).build(),
            frame * 4,
            AudioTrack.MODE_STREAM,
            AudioTrack.DEFAULT
        ).also { it.play() }

        // ---- input loop: mic -> opus -> CH_AUDIO_IN
        Thread {
            val pcm = ShortArray(OpusJni.FRAME_SAMPLES)
            val out = ByteArray(OpusJni.FRAME_SAMPLES * 2)
            while (running) {
                val n = recorder?.read(pcm, 0, pcm.size) ?: -1
                if (n <= 0) continue
                if (mutedIn) continue
                val encoded = OpusJni.encoderEncode(encHandle, pcm, out)
                if (encoded <= 0) continue
                inSeq = (inSeq + 1) and 0x7FFF_FFFF
                val body = UlpChannels.audioBody(
                    UlpChannels.AUDIO_OPUS, OpusJni.SAMPLE_RATE, 1,
                    inSeq, outPts.toInt(), out.copyOf(encoded))
                outPts += OpusJni.FRAME_MS.toLong()
                try {
                    session?.sendFrame(UlpFrame.CH_AUDIO_IN, 0, body)
                } catch (e: Exception) {
                    break
                }
            }
        }.start()
    }

    /** Device-side handler for CH_AUDIO_OUT frames. */
    fun deliverAudioOut(payload: ByteArray) {
        val f = UlpChannels.audioParse(payload)
        if (f.codec != UlpChannels.AUDIO_OPUS) return
        val pcm = ShortArray(OpusJni.FRAME_SAMPLES * 2)
        val n = OpusJni.decoderDecode(decHandle, f.data, pcm)
        if (n <= 0 || player == null) return
        player!!.write(pcm, 0, n)
    }

    fun setMute(mask: Int) {
        mutedIn = (mask and UlpMessages.MUTE_AUDIO_IN) != 0
    }

    override fun onDestroy() {
        running = false
        try { recorder?.stop() } catch (_: Exception) {}
        try { player?.stop() } catch (_: Exception) {}
        if (encHandle != 0L) OpusJni.encoderDestroy(encHandle)
        if (decHandle != 0L) OpusJni.decoderDestroy(decHandle)
        AudioBridgeService.instance = null
        super.onDestroy()
    }
}
