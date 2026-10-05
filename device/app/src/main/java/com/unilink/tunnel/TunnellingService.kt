package com.unilink.tunnel

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.unilink.MainActivity
import com.unilink.core.UlpFrame
import com.unilink.core.UlpMessages
import com.unilink.core.UlpSession
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Inet4Address
import java.net.Inet6Address

/**
 * No-root reverse-tether VPN (Gnirehtet-compatible approach):
 * the device's VPNService routes its own traffic (and traffic from
 * tethered clients) through the ULP session to the host, where a TUN
 * device injects it into the host network.
 *
 * Dual-stack: addAddressFamily for both IPv4 and IPv6; packets are
 * routed by their version nibble (spec section 8).
 */
class TunnellingService : android.net.VpnService() {

    private val tag = "TunnellingService"
    private var tunnelFd: ParcelFileDescriptor? = null
    private var session: UlpSession? = null
    private var readerThread: Thread? = null
    private val stats = TunnelStats()
    private var statsMark = SystemClock.elapsedRealtime()

    companion object {
        const val ACTION_START = "com.unilink.ACTION_START"
        @Volatile var instance: TunnellingService? = null
            private set
        const val NOTIF_CHANNEL = "unilink-tunnel"
        const val NOTIF_ID = 42
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        createChannel()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(android.app.NotificationManager::class.java)
            val channel = android.app.NotificationChannel(
                NOTIF_CHANNEL, getString(com.unilink.R.string.tunnel_channel),
                android.app.NotificationManager.IMPORTANCE_LOW)
            nm.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE)
        val notif: Notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIF_CHANNEL)
        } else {
            Notification.Builder(this)
        }.apply {
            setContentTitle(getString(com.unilink.R.string.app_name))
            setContentText(getString(com.unilink.R.string.tunnel_running))
            setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            setContentIntent(pi)
            setOngoing(true)
        }.build()
        startForeground(NOTIF_ID, notif)
        return START_STICKY
    }

    /** Attach to a live session and bring up the VPN. */
    fun attach(session: UlpSession) {
        this.session = session
        if (tunnelFd != null) return
        val builder = Builder()
            .setSession(getString(com.unilink.R.string.app_name))
            .addAddress("10.8.0.2", 20)                    // device tunnel IP
            .addAddress("fd00:4c:55:01::2", 64)             // dual-stack v6
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .addRoute("10.8.0.0/20")
            .addRoute("fd00:4c:55:01::/64")
            .addRoute("0.0.0.0/0")                           // default v4
            .addRoute("::/0")                                 // default v6
            .setMtu(1500)
            .setUnderlyingNetworks(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            @Suppress("DEPRECATION")
            builder.setBlocking(true)
        }
        val protected = VpnService.prepare(this)
        if (protected != null) {
            // User must grant VPN permission once; the Activity resumes us.
            intentSender = protected
            return
        }
        tunnelFd = builder.establish()
        readerThread = Thread { readLoop() }.also { it.start() }
        Log.i(tag, "VPN up: 10.8.0.2/20, fd00:4c:55:01::2/64")
        // Tell the host the tunnel is live (CONFIG was sent by the host;
        // we answer TUN_UP expectation by sending TUN_UP ourselves? No —
        // per spec the HOST sends CONFIG+TUN_UP; we just start flowing.)
    }

    var intentSender: android.content.IntentSender? = null

    private fun readLoop() {
        val fd = tunnelFd ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val buf = ByteArray(65536)
        while (tunnelFd != null) {
            val n = try { input.read(buf) } catch (e: Exception) { break }
            if (n <= 0) break
            val pkt = buf.copyOf(n)
            sendPacket(pkt)
        }
    }

    /** Route one packet by its IP version nibble. */
    fun sendPacket(pkt: ByteArray) {
        if (pkt.isEmpty()) return
        val ver = pkt[0].toInt() shr 4
        val ch = when (ver) {
            4 -> UlpFrame.CH_TUN_V4
            6 -> UlpFrame.CH_TUN_V6
            else -> return
        }
        stats.count(ch, pkt.size.toLong())
        try {
            session?.sendFrame(ch, 0, pkt)
        } catch (e: Exception) {
            Log.w(tag, "send failed: ${e.message}")
        }
    }

    /** Called by the session reader for TUN_V4/TUN_V6 frames. */
    fun deliverPacket(channel: Int, pkt: ByteArray) {
        val fd = tunnelFd?.fileDescriptor ?: return
        stats.count(channel, pkt.size.toLong())
        val out = FileOutputStream(fd)
        try {
            out.write(pkt)
        } catch (e: Exception) {
            Log.w(tag, "deliver failed: ${e.message}")
        }
    }

    fun statsSnapshot(): TunnelStats {
        return TunnelStats(
            v4In = stats.v4In, v4Out = stats.v4Out,
            v6In = stats.v6In, v6Out = stats.v6Out,
            drops = stats.drops)
    }

    fun statsSince(ts: Long): TunnelStats {
        val snap = stats.snapshot()
        val dt = (SystemClock.elapsedRealtime() - ts).coerceAtLeast(1)
        val rates = TunnelStats(
            v4In = snap.v4In, v4Out = snap.v4Out, v6In = snap.v6In, v6Out = snap.v6Out,
            v4InRate = (snap.v4In * 1000.0 / dt).toLong(),
            v4OutRate = (snap.v4Out * 1000.0 / dt).toLong(),
            drops = snap.drops)
        return rates
    }

    fun stop() {
        readerThread?.interrupt()
        readerThread = null
        try { tunnelFd?.close() } catch (_: Exception) {}
        tunnelFd = null
        stopForeground(true)
    }

    override fun onDestroy() {
        stop()
        instance = null
        super.onDestroy()
    }

    class TunnelStats(
        var v4In: Long = 0, var v4Out: Long = 0,
        var v6In: Long = 0, var v6Out: Long = 0,
        var v4InRate: Long = 0, var v4OutRate: Long = 0,
        var drops: Long = 0,
    ) {
        fun count(channel: Int, n: Long) {
            when (channel) {
                UlpFrame.CH_TUN_V4 -> v4Out += n
                UlpFrame.CH_TUN_V6 -> v6Out += n
            }
        }
        fun snapshot(): TunnelStats =
            TunnelStats(v4In, v4Out, v6In, v6Out, v4InRate, v4OutRate, drops)
    }
}
