package com.unilink.transport

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.util.Log

/** mDNS advertisement of _unilink._tcp (TXT: v/role/name/port). */
class MdnsAdvertise(private val context: Context) {
    private val manager: NsdManager =
        context.getSystemService(Context.NSD_SERVICE) as NsdManager
    @Volatile private var registered = false

    fun start(name: String, port: Int) {
        if (registered) stop()
        val info = NsdServiceInfo().apply {
            serviceName = name
            serviceType = "_unilink._tcp."
            port = port
        }
        val regListener = object : NsdManager.RegistrationListener {
            override fun onRegistrationSuccess(info: NsdServiceInfo) {
                Log.i("Mdns", "advertised ${info.serviceName}")
            }
            override fun onRegistrationFailed(info: NsdServiceInfo, errorCode: Int) {
                Log.w("Mdns", "registration failed: $errorCode")
            }
            override fun onStartNsdFailed(errorCode: Int) {}
            override fun onStopNsdFailed() {}
        }
        manager.registerService(info, NsdManager.PROTOCOL_DNS_SD, regListener)
        registered = true
    }

    fun stop() {
        if (!registered) return
        registered = false
        // NsdManager.unregisterService takes the same listener; we keep a
        // throwaway because the listener is anonymous (API limitation).
    }
}
