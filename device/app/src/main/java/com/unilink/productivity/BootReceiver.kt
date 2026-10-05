package com.unilink.productivity

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.preference.PreferenceManager

/**
 * Auto-restart (Gnirehtet parity, spec section 13): on boot, if the user
 * had auto-start enabled, restart the transports. Connection itself still
 * requires the host to be reachable (ADB/LAN).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        if (!prefs.getBoolean("autostart", false)) return
        val i = Intent(context, com.unilink.MainActivity::class.java)
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        i.putExtra("autostart", true)
        context.startActivity(i)
    }
}
