package com.frontguard.proxy

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.materialswitch.MaterialSwitch
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatusBadge: TextView
    private lateinit var btnToggleProxy: Button
    private lateinit var btnExportCa: Button
    private lateinit var etListenHost: EditText
    private lateinit var etListenPort: EditText
    private lateinit var etFronts: EditText
    private lateinit var etFrontPort: EditText
    private lateinit var spinnerSniMode: Spinner
    private lateinit var switchMitm: MaterialSwitch
    private lateinit var switchInsecure: MaterialSwitch
    private lateinit var switchVerbose: MaterialSwitch
    private lateinit var etTimeout: EditText
    private lateinit var etRetry: EditText
    private lateinit var etAuth: EditText
    private lateinit var etBlacklist: EditText
    private lateinit var etUserAgent: EditText
    private lateinit var tvLogs: TextView
    private lateinit var scrollLogs: ScrollView
    private lateinit var btnClearLogs: Button
    private lateinit var btnCopyLogs: Button

    private val sniModes = arrayOf("front", "target", "auto")

    private val logListener: (String) -> Unit = { line ->
        runOnUiThread {
            tvLogs.append(line + "\n")
            scrollLogs.post { scrollLogs.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateServiceUiState()
        }
    }

    private val exportCaLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-pem-file")
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                val ca = CertAuthority(filesDir)
                contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(ca.getCaPemString().toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(this, "تم حفظ شهادة CA بنجاح!", Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                Toast.makeText(this, "فشل حفظ الشهادة: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        requestNotificationPermissionIfNeeded()
        bindViews()
        loadConfigIntoUi()
        setupListeners()

        // عرض السجلات السابقة
        val history = LogBus.getHistory()
        if (history.isNotEmpty()) {
            tvLogs.text = history.joinToString("\n") + "\n"
            scrollLogs.post { scrollLogs.fullScroll(View.FOCUS_DOWN) }
        }
        LogBus.register(logListener)
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(ProxyForegroundService.ACTION_STATUS_BROADCAST)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }
        updateServiceUiState()
    }

    override fun onPause() {
        super.onPause()
        try {
            unregisterReceiver(statusReceiver)
        } catch (_: Exception) {
        }
    }

    override fun onDestroy() {
        LogBus.unregister(logListener)
        super.onDestroy()
    }

    private fun bindViews() {
        tvStatusBadge = findViewById(R.id.tvStatusBadge)
        btnToggleProxy = findViewById(R.id.btnToggleProxy)
        btnExportCa = findViewById(R.id.btnExportCa)
        etListenHost = findViewById(R.id.etListenHost)
        etListenPort = findViewById(R.id.etListenPort)
        etFronts = findViewById(R.id.etFronts)
        etFrontPort = findViewById(R.id.etFrontPort)
        spinnerSniMode = findViewById(R.id.spinnerSniMode)
        switchMitm = findViewById(R.id.switchMitm)
        switchInsecure = findViewById(R.id.switchInsecure)
        switchVerbose = findViewById(R.id.switchVerbose)
        etTimeout = findViewById(R.id.etTimeout)
        etRetry = findViewById(R.id.etRetry)
        etAuth = findViewById(R.id.etAuth)
        etBlacklist = findViewById(R.id.etBlacklist)
        etUserAgent = findViewById(R.id.etUserAgent)
        tvLogs = findViewById(R.id.tvLogs)
        scrollLogs = findViewById(R.id.scrollLogs)
        btnClearLogs = findViewById(R.id.btnClearLogs)
        btnCopyLogs = findViewById(R.id.btnCopyLogs)

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, sniModes)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerSniMode.adapter = adapter
    }

    private fun loadConfigIntoUi() {
        val cfg = ProxyConfig.load(this)
        etListenHost.setText(cfg.listenHost)
        etListenPort.setText(cfg.listenPort.toString())
        etFronts.setText(cfg.fronts)
        etFrontPort.setText(cfg.frontPort.toString())

        val sniIdx = sniModes.indexOf(cfg.sniMode).coerceAtLeast(0)
        spinnerSniMode.setSelection(sniIdx)

        switchMitm.isChecked = cfg.mitm
        switchInsecure.isChecked = cfg.insecure
        switchVerbose.isChecked = cfg.verbose

        etTimeout.setText(cfg.timeoutSec.toString())
        etRetry.setText(cfg.retryCount.toString())
        etAuth.setText(cfg.auth)
        etBlacklist.setText(cfg.blacklist)
        etUserAgent.setText(cfg.userAgent)
    }

    private fun readConfigFromUi(): ProxyConfig {
        val host = etListenHost.text.toString().trim().ifEmpty { "0.0.0.0" }
        val port = etListenPort.text.toString().toIntOrNull()?.coerceIn(1, 65535) ?: 8080
        val fronts = etFronts.text.toString().trim().ifEmpty { "google.com" }
        val frontPort = etFrontPort.text.toString().toIntOrNull()?.coerceIn(1, 65535) ?: 443
        val sniMode = sniModes[spinnerSniMode.selectedItemPosition]
        val timeout = etTimeout.text.toString().toIntOrNull()?.coerceIn(1, 120) ?: 20
        val retry = etRetry.text.toString().toIntOrNull()?.coerceIn(1, 10) ?: 2

        return ProxyConfig(
            listenHost = host,
            listenPort = port,
            fronts = fronts,
            frontPort = frontPort,
            sniMode = sniMode,
            mitm = switchMitm.isChecked,
            insecure = switchInsecure.isChecked,
            verbose = switchVerbose.isChecked,
            timeoutSec = timeout,
            retryCount = retry,
            auth = etAuth.text.toString().trim(),
            blacklist = etBlacklist.text.toString().trim(),
            userAgent = etUserAgent.text.toString().trim()
        )
    }

    private fun setupListeners() {
        btnToggleProxy.setOnClickListener {
            if (ProxyForegroundService.isServiceRunning) {
                val stopIntent = Intent(this, ProxyForegroundService::class.java).apply {
                    action = ProxyForegroundService.ACTION_STOP
                }
                startService(stopIntent)
            } else {
                val cfg = readConfigFromUi()
                ProxyConfig.save(this, cfg)
                val startIntent = Intent(this, ProxyForegroundService::class.java).apply {
                    action = ProxyForegroundService.ACTION_START
                }
                ContextCompat.startForegroundService(this, startIntent)
            }
        }

        btnExportCa.setOnClickListener {
            exportCaLauncher.launch("cf_fronting_ca.crt")
        }

        btnClearLogs.setOnClickListener {
            LogBus.clear()
            tvLogs.text = ""
        }

        btnCopyLogs.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("FrontGuard Logs", tvLogs.text.toString()))
            Toast.makeText(this, "تم نسخ السجل إلى الحافظة", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateServiceUiState() {
        val running = ProxyForegroundService.isServiceRunning
        if (running) {
            val cfg = ProxyConfig.load(this)
            tvStatusBadge.text = "متصل ويعمل في الخلفية (${cfg.listenHost}:${cfg.listenPort})"
            tvStatusBadge.setBackgroundColor(0xFF1B5E20.toInt())
            btnToggleProxy.text = "إيقاف البروكسي (STOP)"
            btnToggleProxy.setBackgroundColor(0xFFC62828.toInt())
            setInputsEnabled(false)
        } else {
            tvStatusBadge.text = "متوقف حالياً"
            tvStatusBadge.setBackgroundColor(0xFF37474F.toInt())
            btnToggleProxy.text = "تشغيل البروكسي (START)"
            btnToggleProxy.setBackgroundColor(0xFF0277BD.toInt())
            setInputsEnabled(true)
        }
    }

    private fun setInputsEnabled(enabled: Boolean) {
        etListenHost.isEnabled = enabled
        etListenPort.isEnabled = enabled
        etFronts.isEnabled = enabled
        etFrontPort.isEnabled = enabled
        spinnerSniMode.isEnabled = enabled
        switchMitm.isEnabled = enabled
        switchInsecure.isEnabled = enabled
        switchVerbose.isEnabled = enabled
        etTimeout.isEnabled = enabled
        etRetry.isEnabled = enabled
        etAuth.isEnabled = enabled
        etBlacklist.isEnabled = enabled
        etUserAgent.isEnabled = enabled
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    101
                )
            }
        }
    }
}
