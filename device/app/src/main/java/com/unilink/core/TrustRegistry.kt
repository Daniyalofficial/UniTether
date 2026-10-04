package com.unilink.core

import android.content.Context
import java.io.File
import java.security.MessageDigest

/**
 * Trusted-device registry (Phase 2) — conformance port of
 * tests/protocol/trust_registry.py. File-backed (app-private dir),
 * atomic writes (tmp + rename), SHA-256 footer, safe-fail on
 * corruption (no auto-trust). Trust keyed by identity public key;
 * names are display metadata only.
 */
class TrustRegistry(context: Context) {
    private val file = File(context.filesDir, "unitrust.json")
    private val devices = HashMap<String, Device>()   // identity_pub hex
    private val revoked = HashMap<String, Revoked>()
    private val groups = HashMap<String, MutableList<String>>()

    data class Device(
        val deviceId: ByteArray, val identityPub: ByteArray,
        val name: String, val platform: String, val appVer: String,
        val caps: Int, val group: String,
        var lastSeen: Long, var expires: Long, var revoked: Boolean)

    data class Revoked(val reason: String, val at: Long)

    init { load() }

    private fun load() {
        try {
            val raw = file.readBytes()
            if (!raw.startsWith(MAGIC)) throw IllegalArgumentException("magic")
            val body = raw.copyOfRange(0, raw.size - 64)
            val digest = MessageDigest.getInstance("SHA-256").digest(MAGIC + body)
            require(digest.contentEquals(raw.copyOfRange(raw.size - 64, raw.size - 32))) {
                "checksum mismatch"
            }
            val s = String(body, Charsets.UTF_8)
            org.json.JSONObject(s).let { root ->
                val devs = root.getJSONObject("devices")
                devs.keys().forEach { k ->
                    val d = devs.getJSONObject(k)
                    devices[k] = Device(
                        android.util.Base64.decode(d.getString("device_id"), 0),
                        android.util.Base64.decode(d.getString("identity_pub"), 0),
                        d.getString("name"), d.optString("platform"),
                        d.optString("app_ver"), d.optInt("caps"),
                        d.optString("group", "default"),
                        d.optLong("last_seen"), d.optLong("expires"),
                        d.optBoolean("revoked"))
                }
                val rev = root.optJSONObject("revoked") ?: return@let
                rev.keys().forEach { k ->
                    val r = rev.getJSONObject(k)
                    revoked[k] = Revoked(r.optString("reason"), r.optLong("at"))
                }
            }
        } catch (e: Exception) {
            // corruption → safe-fail: start empty, quarantine the file
            runCatching { file.renameTo(File(file.parent, "unitrust.json.corrupt")) }
        }
    }

    private fun save() {
        val root = org.json.JSONObject()
        root.put("version", 1)
        val devs = org.json.JSONObject()
        devices.forEach { (k, d) ->
            devs.put(k, org.json.JSONObject().apply {
                put("device_id", android.util.Base64.encodeToString(d.deviceId, 0))
                put("identity_pub", android.util.Base64.encodeToString(d.identityPub, 0))
                put("name", d.name); put("platform", d.platform)
                put("app_ver", d.appVer); put("caps", d.caps)
                put("group", d.group)
                put("last_seen", d.lastSeen); put("expires", d.expires)
                put("revoked", d.revoked)
            })
        }
        root.put("devices", devs)
        val rev = org.json.JSONObject()
        revoked.forEach { (k, r) ->
            rev.put(k, org.json.JSONObject().put("reason", r.reason).put("at", r.at))
        }
        root.put("revoked", rev)
        val body = root.toString().toByteArray(Charsets.UTF_8)
        val blob = MAGIC + body +
            MessageDigest.getInstance("SHA-256").digest(MAGIC + body) +
            ByteArray(32)
        val tmp = File(file.parent, "unitrust.json.tmp")
        tmp.writeBytes(blob)
        tmp.renameTo(file)
    }

    fun decide(identityPub: ByteArray, deviceId: ByteArray): Int {
        val key = identityPub.toHex()
        val d = devices[key] ?: return UlpV11.DECISION_TRUSTED_NEW
        if (d.revoked || revoked.containsKey(key)) return UlpV11.DECISION_REVOKED
        if (d.expires != 0L && System.currentTimeMillis() > d.expires)
            return UlpV11.DECISION_REVOKED
        d.lastSeen = System.currentTimeMillis()
        save()
        return UlpV11.DECISION_TRUSTED
    }

    fun noteTrusted(identityPub: ByteArray, deviceId: ByteArray,
                    name: String = "", platform: String = "",
                    appVer: String = "", caps: Int = 0) {
        val key = identityPub.toHex()
        val now = System.currentTimeMillis()
        if (devices.containsKey(key)) {
            val d = devices.getValue(key)
            if (name.isNotEmpty()) devices[key] = d.copy(name = name)
            d.lastSeen = now
        } else {
            devices[key] = Device(deviceId, identityPub, name.ifEmpty { "unknown" },
                platform, appVer, caps, "default", now, 0L, false)
        }
        save()
    }

    /** Revoke by identity and/or device id. Returns entries revoked. */
    fun revoke(identityPub: ByteArray? = null, deviceId: ByteArray? = null,
               reason: String = "manual"): Int {
        val now = System.currentTimeMillis()
        var n = 0
        devices.values.filter { d ->
            (identityPub != null && d.identityPub.toHex() == identityPub.toHex()) ||
            (deviceId != null && MessageDigest.isEqual(d.deviceId, deviceId))
        }.forEach { d ->
            devices[d.identityPub.toHex()] = d.copy(revoked = true)
            revoked[d.identityPub.toHex()] = Revoked(reason, now)
            n++
        }
        if (n > 0) save()
        return n
    }

    fun devices(): List<Device> =
        devices.values.sortedBy { it.deviceId.contentHashCode() }

    companion object {
        private val MAGIC = "UNITRUST1\n".toByteArray()
    }
}
