package com.unilink.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.graphics.Bitmap
import android.text.InputType
import android.widget.EditText
import android.widget.ImageView
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** QR display / manual-entry helpers (ZXing core only, no scanning). */
object PairingQr {
    fun show(activity: Activity, blob: String) {
        val bitmap = render(blob, 800)
        val dialog = AlertDialog.Builder(activity)
            .setTitle(activity.getString(com.unilink.R.string.scan_qr))
            .setView(ImageView(activity).apply { setImageBitmap(bitmap) })
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    fun render(blob: String, size: Int): Bitmap {
        val matrix = QRCodeWriter().encode(
            blob, BarcodeFormat.QR_CODE, size, size,
            mapOf(com.google.zxing.EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M))
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) for (y in 0 until size) {
            bmp.setPixel(x, y, if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
        }
        return bmp
    }

    fun prompt(activity: Activity, onBlob: (String) -> Unit) {
        val input = EditText(activity).apply {
            inputType = InputType.TYPE_CLASS_TEXT
            hint = activity.getString(com.unilink.R.string.paste_blob)
        }
        AlertDialog.Builder(activity)
            .setTitle(activity.getString(com.unilink.R.string.paste_title))
            .setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val text = input.text.toString().trim()
                if (text.isNotEmpty()) onBlob(text)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
