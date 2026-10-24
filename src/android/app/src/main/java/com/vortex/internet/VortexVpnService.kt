package com.vortex.internet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import com.vortex.internet.config.InternetConfig
import com.vortex.internet.tun.TunEngine

class VortexVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var engine: TunEngine? = null
    @Volatile private var starting = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (engine != null || starting) return
        starting = true
        startForeground(NOTIF_ID, buildNotification())
        // Load geo lists off the binder thread (geosite ~100k domains), then
        // establish() on main thread (some OEMs require it).
        Thread({
            val config = try {
                InternetConfig.loadFromAssets(this)
            } catch (e: Exception) {
                broadcastLog("config error: ${e.message}")
                starting = false
                stopSelf()
                return@Thread
            }
            Handler(Looper.getMainLooper()).post {
                try {
                    establishVpn(config)
                } finally {
                    starting = false
                }
            }
        }, "vpn-start").start()
    }

    private fun establishVpn(config: InternetConfig) {
        if (engine != null) return
        val builder = Builder()
            .setSession("Vortex Internet")
            .setMtu(1400)
            // /24 is more reliable than /32 on some OEMs for default-route VPN.
            .addAddress("10.8.0.2", 24)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .addRoute("0.0.0.0", 0)
            // Stand-in pool only used on DNS name collision / resolve miss (internet.cpp).
            .addRoute("198.18.0.0", 15)
            .setBlocking(true)

        if (Build.VERSION.SDK_INT >= 29) {
            try {
                // Prefer IPv4-only like desktop divert (IPv6 dropped there).
                builder.allowFamily(OsConstants.AF_INET)
            } catch (_: Exception) {
            }
            try {
                builder.setMetered(false)
            } catch (_: Exception) {
            }
        }
        // IPv6: desktop divert drops v6. Without an IPv6 TUN address, addRoute(::/0)
        // may fail — allowFamily(AF_INET) above is the primary leak mitigation.

        // Keep this app off the TUN — same idea as desktop self-exclude.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            broadcastLog("establish exception: ${e.message}")
            stopSelf()
            return
        }
        if (pfd == null) {
            broadcastLog("VpnService.establish() failed")
            stopSelf()
            return
        }
        tun = pfd
        engine = TunEngine(this, pfd, config) { msg -> broadcastLog(msg) }.also { it.start() }
        broadcastStatus(true)
        broadcastLog(
            "VPN up · default=${config.defaultLink} · links=${config.links.keys.joinToString()} · " +
                "geoip=${config.geoipCn.size} geosite=${config.geositeCn.size}"
        )
    }

    private fun stopVpn() {
        engine?.stop()
        engine = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        broadcastStatus(false)
        broadcastLog("VPN stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val channelId = "vortex_internet"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(channelId, "Vortex Internet", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun broadcastLog(msg: String) {
        sendBroadcast(Intent(ACTION_LOG).setPackage(packageName).putExtra(EXTRA_MSG, msg))
    }

    private fun broadcastStatus(running: Boolean) {
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_RUNNING, running)
        )
    }

    companion object {
        const val ACTION_STOP = "com.vortex.internet.STOP"
        const val ACTION_LOG = "com.vortex.internet.LOG"
        const val ACTION_STATUS = "com.vortex.internet.STATUS"
        const val EXTRA_MSG = "msg"
        const val EXTRA_RUNNING = "running"
        private const val NOTIF_ID = 42
    }
}
