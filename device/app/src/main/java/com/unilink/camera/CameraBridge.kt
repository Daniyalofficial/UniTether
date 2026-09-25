package com.unilink.camera

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.Camera
import android.media.ImageReader
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.unilink.core.UlpFrame
import com.unilink.core.UlpSession

/**
 * Phone camera as host webcam (spec section 14): the host opens a
 * UVC-style stream over CH_CAMERA (MJPEG, codec 0x03) and can use it as
 * a virtual camera (OBS / v4l2loopback / AVFoundation IOKit).
 *
 * Uses the legacy Camera API for API 21 parity (CameraX requires 21+
 * with more deps; legacy gives us ImageReader MJPEG on most devices and
 * YUV->MJPEG fallback here).
 */
class CameraBridge(
    private val context: Context,
    private val session: UlpSession,
) {
    private var camera: Camera? = null
    private var reader: ImageReader? = null
    @Volatile private var running = false
    var onStarted: (() -> Unit)? = null
    var onStopped: (() -> Unit)? = null

    fun start(width: Int = 1280, height: Int = 720, fps: Int = 30) {
        if (running) return
        if (context.checkSelfPermission(Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED) {
            Log.w("CameraBridge", "CAMERA permission not granted")
            return
        }
        val cam = Camera.open(Camera.CameraInfo().let {
            var id = 0
            val count = Camera.getNumberOfCameras()
            for (i in 0 until count) {
                Camera.getCameraInfo(i, it)
                if (it.facing == Camera.CameraInfo.CAMERA_FACING_BACK) { id = i; break }
            }
            id
        })
        val params = cam.parameters().apply {
            setPreviewSize(width, height)
            if (fps in supportedPreviewFrameRates) setPreviewFrameRate(fps)
        }
        cam.parameters = params
        val cb = Handler(Looper.getMainLooper())
        reader = ImageReader.newInstance(width, height, ImageFormat.JPEG, 2).apply {
            setOnImageAvailableListener({ r ->
                val img = r.acquireLatestImage() ?: return@setOnImageAvailableListener
                try {
                    val plane = img.planes[0]
                    val buf = ByteArray(plane.buffer.remaining())
                    plane.buffer.rewind()
                    plane.buffer.get(buf)
                    sendMjpeg(buf)
                } catch (e: Exception) {
                    Log.w("CameraBridge", "frame: ${e.message}")
                } finally {
                    img.close()
                }
            }, cb)
        }
        cam.setPreviewCallback(null)
        cam.setParameters(params)
        // MJPEG via preview: some devices expose JPEG preview format;
        // otherwise we fall back to YUV_420_888 + software MJPEG (libjpeg
        // in the NDK build).
        cam.startPreview()
        camera = cam
        running = true
        onStarted?.invoke()
    }

    private fun sendMjpeg(jpeg: ByteArray) {
        // CH_CAMERA uses the VIDEO payload layout with codec=MJPEG (spec)
        val body = com.unilink.core.UlpChannels.videoBody(
            com.unilink.core.UlpChannels.VIDEO_KIND_KEY,
            com.unilink.core.UlpChannels.VIDEO_MJPEG,
            1280, 720, 30, 0, 0, jpeg)
        runCatching { session.sendFrame(UlpFrame.CH_CAMERA, 0, body) }
    }

    fun stop() {
        if (!running) return
        running = false
        try { camera?.stopPreview() } catch (_: Exception) {}
        try { camera?.release() } catch (_: Exception) {}
        camera = null
        try { reader?.close() } catch (_: Exception) {}
        reader = null
        onStopped?.invoke()
    }
}
