package com.unilink.transport

import android.util.Log
import com.unilink.core.UlpSession
import com.unilink.core.UlpError
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket

/**
 * Device-side transports:
 *  * USB: ADB forwards tcp:<port> -> localabstract:unilink (host runs
 *    `adb forward`), so the device just serves a LocalSocket.
 *  * LAN / Wi-Fi Direct: plain TCP server + mDNS advertisement.
 *
 * All transports hand a connected stream to [onStream]; the session
 * handshake (UlpSession.startDevice) happens per connection so a
 * re-pair or host reconnect never wedges the app.
 */
class DeviceTransport(
    private val secret: ByteArray,
    private val features: Int,
    private val onStream: (UlpSession) -> Unit,
) {
    private val tag = "DeviceTransport"
    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var localSocketServer: android.net.LocalServerSocket? = null
    @Volatile private var running = false

    /** USB/ADB path: localabstract:unilink */
    fun startAdb() {
        stopAll()
        running = true
        val name = "unilink"
        val server = android.net.LocalServerSocket(name)
        localSocketServer = server
        Thread {
            Log.i(tag, "listening on localabstract:$name (ADB forward)")
            while (running) {
                val conn = try { server.accept() } catch (e: Exception) {
                    if (!running) break
                    continue
                }
                handle(conn.inputStream, conn.outputStream, conn)
            }
        }.start()
    }

    /** LAN / Wi-Fi Direct path: TCP + mDNS. */
    fun startLan(port: Int = 0): Int {
        stopAll()
        running = true
        val server = ServerSocket(0)
        server.reuseAddress = true
        serverSocket = server
        val actualPort = server.localPort
        Thread {
            Log.i(tag, "LAN listening on :$actualPort")
            while (running) {
                val sock = try { server.accept() } catch (e: Exception) {
                    if (!running) break
                    continue
                }
                sock.keepAlive = true
                sock.tcpNoDelay = true
                handle(sock.getInputStream(), sock.getOutputStream(), sock)
            }
        }.start()
        return actualPort
    }

    private fun handle(in: InputStream, out: OutputStream, conn: Any) {
        Thread {
            var session: UlpSession? = null
            try {
                session = UlpSession(in, out)
                session.startDevice(secret, features)
                Log.i(tag, "session established (${conn.javaClass.simpleName})")
                onStream(session)
            } catch (e: UlpError) {
                Log.w(tag, "handshake failed: ${e.message}")
            } catch (e: Exception) {
                Log.w(tag, "connection error: ${e.message}")
            } finally {
                session?.close()
                if (conn is Socket) runCatching { conn.close() }
                if (conn is android.net.LocalSocket) runCatching { conn.close() }
            }
        }.start()
    }

    fun stopAll() {
        running = false
        runCatching { serverSocket?.close() }
        runCatching { localSocketServer?.close() }
        serverSocket = null
        localSocketServer = null
    }
}
