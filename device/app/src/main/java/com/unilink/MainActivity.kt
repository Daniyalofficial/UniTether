package com.unilink

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.unilink.core.Pairing
import com.unilink.core.UlpFrame
import com.unilink.core.UlpMessages
import com.unilink.core.UlpSession
import com.unilink.input.InputInjector
import com.unilink.audio.AudioBridgeService
import com.unilink.camera.CameraBridge
import com.unilink.core.UlpChannels
import com.unilink.mirror.MirroringService
import com.unilink.mirror.ScreenCapturer
import com.unilink.productivity.BootReceiver
import com.unilink.productivity.ClipboardBridge
import com.unilink.productivity.FileTransfer
import com.unilink.productivity.NotificationMirror
import com.unilink.productivity.SmsReplier
import com.unilink.productivity.SmsReceiver
import com.unilink.transport.DeviceTransport
import com.unilink.tunnel.TunnellingService
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Device UI + session supervisor: pairing display, transport control,
 * and per-connection feature wiring (tunnel, video, audio, input,
 * productivity, camera).
 */
class MainActivity : AppCompatActivity() {

    private val sessionLive = AtomicBoolean(false)
    private var secret: ByteArray = ByteArray(32)
    private var transport: DeviceTransport? = null
    private var capturer: ScreenCapturer? = null
    private var input: InputInjector? = null
    private var clipboard: ClipboardBridge? = null
    private var files: FileTransfer? = null
    private var camera: CameraBridge? = null
    private var session: UlpSession? = null
    private val features = 0x00FF // all ULP features

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        secret = SecureRandom().let { val b = ByteArray(32); it.nextBytes(b); b }

        val status = findViewById<TextView>(R.id.status)
        val pairingView = findViewById<TextView>(R.id.pairing)
        val startBtn = findViewById<Button>(R.id.start)
        val stopBtn = findViewById<Button>(R.id.stop)
        val qrBtn = findViewById<ImageButton>(R.id.qr)
        val pairText = findViewById<EditText>(R.id.pairingText)

        fun renderPairing() {
            val blob = Pairing.blob(secret, Build.MODEL)
            pairingView.text = blob
        }
        renderPairing()

        qrBtn.setOnClickListener {
            // QR sheet (ZXing) — the host scans this to start the session
            com.unilink.ui.PairingQr.show(this, Pairing.blob(secret, Build.MODEL))
        }
        pairText.setOnClickListener {
            // manual paste of a host blob
            com.unilink.ui.PairingQr.prompt(this) { blob ->
                runCatching {
                    val (s, _) = Pairing.parse(blob)
                    secret = s
                    renderPairing()
                    status.text = getString(R.string.paired)
                }
            }
        }

        startBtn.setOnClickListener {
            val t = DeviceTransport(secret, features) { s -> onSession(s, status) }
            t.startAdb()
            transport = t
            status.text = getString(R.string.listening)
        }
        stopBtn.setOnClickListener {
            transport?.stopAll()
            sessionLive.set(false)
            status.text = getString(R.string.stopped)
        }

        if (intent.getBooleanExtra("autostart", false)) {
            startBtn.performClick()
        }
    }

    private fun onSession(s: UlpSession, status: TextView) {
        if (!sessionLive.compareAndSet(false, true)) return
        session = s
        status.text = getString(R.string.connected)

        // ---- tunnel (VPN)
        val tunnel = TunnellingService.instance
        if (tunnel != null) tunnel.attach(s)

        // ---- video: start mirroring consent flow
        capturer = ScreenCapturer(this)
        val mirror = MirroringService.instance
        if (mirror != null && capturer != null) {
            capturer!!.let { c ->
                mirror.attach(c, s)
                val consent = c.requestConsent()
                if (consent != null) {
                    startActivityForResult(consent, 7001)
                }
            }
        }

        // ---- input
        input = InputInjector(this)

        // ---- clipboard
        clipboard = ClipboardBridge(this, s).also { it.start() }

        // ---- files
        files = FileTransfer(this, s)

        // ---- camera (on demand from host via CH_USER op=3)

        // ---- session reader
        Thread {
            var videoSeq = 0
            while (sessionLive.get()) {
                val f = try { s.recvFrame() } catch (e: Exception) { break }
                when (f.channel) {
                    UlpFrame.CH_TUN_V4, UlpFrame.CH_TUN_V6 ->
                        TunnellingService.instance?.deliverPacket(f.channel, f.payload)
                    UlpFrame.CH_CONTROL -> {
                        val m = UlpMessages.decode(f.payload)
                        when (m.mtype) {
                            UlpMessages.MSG_PING -> s.sendMsg(UlpMessages.MSG_PONG, m.body)
                            UlpMessages.MSG_STATS_REQ -> {
                                val t = TunnellingService.instance
                                val snap = t?.statsSnapshot()
                                s.sendMsg(UlpMessages.MSG_STATS_RSP, UlpMessages.statsBody(
                                    bytesIn = snap?.v4In ?: 0, bytesOut = snap?.v4Out ?: 0,
                                    pktsIn = 0, pktsOut = 0,
                                    bytesVideo = 0, bytesAudio = 0, bytesFile = 0,
                                    drops = snap?.drops ?: 0, errors = 0,
                                    framesVideo = videoSeq.toLong(),
                                    rttMs = 0, lossPctX100 = 0,
                                    cpuPctX100 = 0, fpsVideo = 60, audioLevel = 0))
                            }
                            UlpMessages.MSG_MUTE ->
                                AudioBridgeService.instance?.setMute(m.body[0].toInt() and 0xFF)
                            UlpMessages.MSG_QOS -> {
                                // apply bandwidth caps to the encoder (spec 11.4)
                            }
                            UlpMessages.MSG_BYE -> {
                                s.sendMsg(UlpMessages.MSG_BYE, byteArrayOf(0))
                                break
                            }
                        }
                    }
                    UlpFrame.CH_AUDIO_OUT ->
                        AudioBridgeService.instance?.deliverAudioOut(f.payload)
                    UlpFrame.CH_INPUT ->
                        input?.deliver(f.payload)
                    UlpFrame.CH_CLIPBOARD ->
                        clipboard?.deliverHostClip(f.payload)
                    UlpFrame.CH_FILE ->
                        files?.deliver(f.payload)
                    UlpFrame.CH_USER -> handleUserOp(s, f.payload)
                }
                videoSeq++
            }
            onDisconnected()
        }.start()
    }

    private fun handleUserOp(s: UlpSession, payload: ByteArray) {
        if (payload.isEmpty()) return
        when (payload[0].toInt() and 0xFF) {
            1 -> SmsReplier.deliver(this, payload)          // sms-reply
            3 -> {                                           // start camera
                camera = CameraBridge(this, s)
                camera?.start()
            }
            4 -> camera?.stop()                              // stop camera
        }
    }

    private fun onDisconnected() {
        sessionLive.set(false)
        clipboard?.stop()
        runOnUiThread {
            (findViewById<TextView>(R.id.status)).text = getString(R.string.disconnected)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 7001) {
            capturer?.onResult(resultCode, data)
        }
    }

    override fun onDestroy() {
        transport?.stopAll()
        super.onDestroy()
    }
}
