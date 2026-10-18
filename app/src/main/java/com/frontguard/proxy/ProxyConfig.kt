package com.frontguard.proxy

import android.content.Context

data class ProxyConfig(
    val listenHost: String = "0.0.0.0",
    val listenPort: Int = 8080,
    val fronts: String = "google.com",
    val frontPort: Int = 443,
    val sniMode: String = "front", // front | target | auto
    val mitm: Boolean = true,
    val insecure: Boolean = false,
    val verbose: Boolean = true,
    val timeoutSec: Int = 20,
    val retryCount: Int = 2,
    val userAgent: String = ""
) {
    fun frontList(): List<String> =
        fronts.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    companion object {
        private const val PREFS_NAME = "frontguard_prefs"

        fun load(context: Context): ProxyConfig {
            val sp = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return ProxyConfig(
                listenHost = sp.getString("listenHost", "0.0.0.0") ?: "0.0.0.0",
                listenPort = sp.getInt("listenPort", 8080),
                fronts = sp.getString("fronts", "google.com") ?: "google.com",
                frontPort = sp.getInt("frontPort", 443),
                sniMode = sp.getString("sniMode", "front") ?: "front",
                mitm = sp.getBoolean("mitm", true),
                insecure = sp.getBoolean("insecure", false),
                verbose = sp.getBoolean("verbose", true),
                timeoutSec = sp.getInt("timeoutSec", 20),
                retryCount = sp.getInt("retryCount", 2),
                userAgent = sp.getString("userAgent", "") ?: ""
            )
        }

        fun save(context: Context, cfg: ProxyConfig) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().apply {
                putString("listenHost", cfg.listenHost)
                putInt("listenPort", cfg.listenPort)
                putString("fronts", cfg.fronts)
                putInt("frontPort", cfg.frontPort)
                putString("sniMode", cfg.sniMode)
                putBoolean("mitm", cfg.mitm)
                putBoolean("insecure", cfg.insecure)
                putBoolean("verbose", cfg.verbose)
                putInt("timeoutSec", cfg.timeoutSec)
                putInt("retryCount", cfg.retryCount)
                putString("userAgent", cfg.userAgent)
                apply()
            }
        }
    }
}
