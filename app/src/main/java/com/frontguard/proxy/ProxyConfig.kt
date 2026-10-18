package com.frontguard.proxy

import android.content.Context

private const val DEFAULT_GOOGLE_RELAY_URL = "https://script.google.com/macros/s/AKfycbx-WPwe3qUZozQJxzDEF2DRs3hYiIGMcmoeTjS2hC_7CKcTbXBm2cbxV4KKuryypp5NwQ/exec"
private const val DEFAULT_GOOGLE_RELAY_AUTH_KEY = "alrufaaey"

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
    val auth: String = "",
    val blacklist: String = "",
    val userAgent: String = "",
    val googleRelayEnabled: Boolean = false,
    val googleRelayUrl: String = DEFAULT_GOOGLE_RELAY_URL,
    val googleRelayAuthKey: String = DEFAULT_GOOGLE_RELAY_AUTH_KEY,
    val verifyRelayTls: Boolean = true
) {
    fun frontList(): List<String> =
        fronts.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    fun blacklistSet(): Set<String> =
        blacklist.split(",").map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()

    fun validate(): String? {
        if (listenPort !in 1..65535) return "منفذ الاستماع غير صحيح"
        if (frontPort !in 1..65535) return "منفذ Front غير صحيح"
        if (googleRelayEnabled) {
            if (!googleRelayUrl.startsWith("https://")) return "رابط Apps Script يجب أن يبدأ بـ https://"
            if (googleRelayAuthKey.isBlank()) return "أدخل AUTH_KEY المطابق لـ Code.gs"
            if (!mitm) return "فعّل MITM لكي يعمل Relay مع HTTPS؛ HTTP سيظل يعمل بدونه"
        }
        return null
    }

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
                auth = sp.getString("auth", "") ?: "",
                blacklist = sp.getString("blacklist", "") ?: "",
                userAgent = sp.getString("userAgent", "") ?: "",
                googleRelayEnabled = sp.getBoolean("googleRelayEnabled", false),
                googleRelayUrl = sp.getString("googleRelayUrl", DEFAULT_GOOGLE_RELAY_URL)
                    ?: DEFAULT_GOOGLE_RELAY_URL,
                googleRelayAuthKey = sp.getString("googleRelayAuthKey", DEFAULT_GOOGLE_RELAY_AUTH_KEY)
                    ?: DEFAULT_GOOGLE_RELAY_AUTH_KEY,
                verifyRelayTls = sp.getBoolean("verifyRelayTls", true)
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
                putString("auth", cfg.auth)
                putString("blacklist", cfg.blacklist)
                putString("userAgent", cfg.userAgent)
                putBoolean("googleRelayEnabled", cfg.googleRelayEnabled)
                putString("googleRelayUrl", cfg.googleRelayUrl)
                putString("googleRelayAuthKey", cfg.googleRelayAuthKey)
                putBoolean("verifyRelayTls", cfg.verifyRelayTls)
                apply()
            }
        }
    }
}
