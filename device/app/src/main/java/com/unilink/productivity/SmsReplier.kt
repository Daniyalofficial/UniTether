package com.unilink.productivity

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.util.Log
import com.unilink.core.UlpChannels
import com.unilink.core.UlpFrame
import com.unilink.core.UlpSession

/**
 * SMS/WhatsApp reply (spec section 12): inbound SMS is mirrored to the
 * host via the notification channel; the host's reply arrives on
 * CH_USER as an `sms-reply` payload (address + text) and is sent through
 * SmsManager. Works without root on Android 5+; on Android 9+ only the
 * default SMS app may send — the app asks the user to set it as default
 * when a reply is requested.
 */
class SmsReceiver : BroadcastReceiver() {
    companion object {
        @Volatile var session: UlpSession? = null
    }

    override fun onReceive(context: Context, intent: Intent) {
        val session = session ?: return
        if (intent.action != "android.provider.Telephony.SMS_RECEIVED") return
        val bundle = intent.getBundleExtra("pdus") ?: return
        val messages = com.unilink.productivity.SmsParser.parse(bundle, context)
        for (m in messages) {
            if (m.address.isNullOrEmpty()) continue
            val payload = UlpChannels.notificationBody(
                m.msgId, m.timestampMillis, 0,
                "com.unilink.sms", "SMS from ${m.address}", m.body)
            runCatching { session.sendFrame(UlpFrame.CH_NOTIFICATION, 0, payload) }
        }
    }
}

class SmsParser {
    data class Sms(val address: String?, val body: String, val msgId: Int, val timestampMillis: Long)

    companion object {
        fun parse(bundle: android.os.Bundle, context: Context): List<Sms> {
            val pduCls = Class.forName("android.telephony.SmsMessage")
            val pdus = bundle.get("pdus") as? Array<*> ?: return emptyList()
            val out = ArrayList<Sms>()
            for (p in pdus) {
                val msg = pduCls.getMethod("createFromPdu", Array<String>::class.java)
                    .invoke(null, arrayOf(p as String))
                val addr = pduCls.getMethod("getOriginatingAddress").invoke(msg) as? String
                val body = pduCls.getMethod("getMessageBody").invoke(msg)?.toString() ?: ""
                val id = pduCls.getMethod("getMessageId").invoke(msg) as Int
                val ts = pduCls.getMethod("getTimestampMillis").invoke(msg) as Long
                out.add(Sms(addr, body, id, ts))
            }
            return out
        }
    }
}

/** Host -> device SMS reply: CH_USER payload = [1B op=1][u16be addrLen][addr][text]. */
object SmsReplier {
    fun deliver(context: Context, payload: ByteArray) {
        if (payload.size < 3) return
        if (payload[0].toInt() and 0xFF != 1) return
        val addrLen = ((payload[1].toInt() and 0xFF) shl 8) or (payload[2].toInt() and 0xFF)
        if (payload.size < 3 + addrLen) return
        val addr = String(payload, 3, addrLen, Charsets.UTF_8)
        val text = String(payload, 3 + addrLen, payload.size - 3 - addrLen, Charsets.UTF_8)
        val sms = context.getSystemService(Context.TELEPHONY_SERVICE) as SmsManager
        val parts = sms.divideMessage(text)
        if (parts.size == 1) {
            sms.sendTextMessage(addr, null, text, null, null)
        } else {
            sms.sendMultipartTextMessage(addr, null, parts, null, null)
        }
        Log.i("SmsReplier", "sent ${parts.size} part(s) to $addr")
    }
}
