package com.frontguard.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class ProxyForegroundService : Service() {

    companion object {
        const val ACTION_START = "com.frontguard.proxy.ACTION_START"
        const val ACTION_STOP = "com.frontguard.proxy.ACTION_STOP"
        const val ACTION_STATUS_BROADCAST = "com.frontguard.proxy.STATUS"
        private const val CHANNEL_ID = "frontguard_proxy_channel"
        private const val NOTIF_ID = 1001

        @Volatile
        var isServiceRunning: Boolean = false
            private set

        @Volatile
        var currentEngine: FrontingProxyEngine? = null
            private set
    }

    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxyService()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                startProxyService()
            }
        }
        return START_STICKY
    }

    private fun startProxyService() {
        createNotificationChannel()
        val config = ProxyConfig.load(this)

        config.validate()?.let {
            LogBus.log(it, "ERR")
            isServiceRunning = false
            sendStatusBroadcast(false)
            stopSelf()
            return
        }

        acquireWakeLock()

        val notification = buildNotification(config, 0)
        startForeground(NOTIF_ID, notification)

        currentEngine?.stop()
        val engine = FrontingProxyEngine(
            config,
            filesDir,
            onStatsChanged = { activeCount ->
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.notify(NOTIF_ID, buildNotification(config, activeCount))
            },
            onRunningChanged = { running ->
                isServiceRunning = running
                sendStatusBroadcast(running)
                if (!running) {
                    releaseWakeLock()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        )
        currentEngine = engine
        engine.start()

        isServiceRunning = true
        sendStatusBroadcast(true)
    }

    private fun stopProxyService() {
        currentEngine?.stop()
        currentEngine = null
        isServiceRunning = false
        releaseWakeLock()
        sendStatusBroadcast(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        currentEngine?.stop()
        currentEngine = null
        isServiceRunning = false
        releaseWakeLock()
        sendStatusBroadcast(false)
        super.onDestroy()
    }

    private fun sendStatusBroadcast(running: Boolean) {
        sendBroadcast(
            Intent(ACTION_STATUS_BROADCAST)
                .setPackage(packageName)
                .putExtra("running", running)
        )
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "FrontGuard::ProxyWakeLock"
        ).apply {
            acquire()
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (_: Exception) {
        }
        wakeLock = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "FrontGuard Proxy Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "إشعار عمل البروكسي في الخلفية"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(config: ProxyConfig, activeConns: Int): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val pendingOpen = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyForegroundService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val modeText = if (config.googleRelayEnabled) {
            if (config.mitm) "Google Apps Script Relay + MITM" else "Google Apps Script Relay (HTTP only)"
        } else if (config.mitm) {
            "MITM (${config.sniMode})"
        } else {
            "RAW (${config.sniMode})"
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("FrontGuard يعمل على ${config.listenHost}:${config.listenPort}")
            .setContentText("الوضع: $modeText | الاتصالات النشطة: $activeConns")
            .setOngoing(true)
            .setContentIntent(pendingOpen)
            .addAction(android.R.drawable.ic_media_pause, "إيقاف", pendingStop)
            .build()
    }
}
