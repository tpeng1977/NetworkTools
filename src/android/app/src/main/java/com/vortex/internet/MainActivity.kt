package com.vortex.internet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ScrollView
import androidx.appcompat.app.AppCompatActivity
import com.vortex.internet.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val logBuf = StringBuilder()

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                VortexVpnService.ACTION_LOG -> {
                    val msg = intent.getStringExtra(VortexVpnService.EXTRA_MSG) ?: return
                    appendLog(msg)
                }
                VortexVpnService.ACTION_STATUS -> {
                    val running = intent.getBooleanExtra(VortexVpnService.EXTRA_RUNNING, false)
                    binding.status.text = if (running) getString(R.string.status_running)
                    else getString(R.string.status_idle)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnStart.setOnClickListener { prepareAndStart() }
        binding.btnStop.setOnClickListener {
            startService(Intent(this, VortexVpnService::class.java).setAction(VortexVpnService.ACTION_STOP))
        }
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter().apply {
            addAction(VortexVpnService.ACTION_LOG)
            addAction(VortexVpnService.ACTION_STATUS)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(receiver, filter)
        }
    }

    override fun onStop() {
        unregisterReceiver(receiver)
        super.onStop()
    }

    private fun prepareAndStart() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN)
        } else {
            startVpnService()
        }
    }

    @Deprecated("Use Activity Result API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startVpnService()
        else if (requestCode == REQ_VPN) appendLog("VPN permission denied")
    }

    private fun startVpnService() {
        val i = Intent(this, VortexVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        appendLog("starting VPN…")
    }

    private fun appendLog(msg: String) {
        runOnUiThread {
            logBuf.append(msg).append('\n')
            if (logBuf.length > 8000) logBuf.delete(0, logBuf.length - 6000)
            binding.logView.text = logBuf.toString()
            binding.logScroll.post { binding.logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    companion object {
        private const val REQ_VPN = 1001
    }
}
