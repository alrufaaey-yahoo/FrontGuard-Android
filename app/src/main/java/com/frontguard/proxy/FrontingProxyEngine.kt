package com.frontguard.proxy

import android.util.Base64
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import javax.net.ssl.HttpsURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.random.Random

/**
 * المحرك الأساسي للبروكسي (ترجمة كاملة ومحسّنة من سكربت بايثون الأصلي)
 */
class FrontingProxyEngine(
    private val config: ProxyConfig,
    private val filesDir: File,
    private val onStatsChanged: (Int) -> Unit = {},
    private val onRunningChanged: (Boolean) -> Unit = {}
) {
    companion object {
        private const val BUFFER_SIZE = 65536
        private const val MAX_HTTP_HEADER_BYTES = 64 * 1024
        private const val MAX_RELAY_REQUEST_BODY_BYTES = 16 * 1024 * 1024
        private const val MAX_RELAY_RESPONSE_JSON_BYTES = 24 * 1024 * 1024
    }

    private data class RelayHttpRequest(
        val method: String,
        val target: String,
        val headers: LinkedHashMap<String, String>,
        val body: ByteArray
    )
    private val running = AtomicBoolean(false)
    private val activeConnections = AtomicInteger(0)
    private var serverSocket: ServerSocket? = null
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private var ca: CertAuthority? = null
    private val relaxedClientSslContext: SSLContext = createRelaxedClientContext()

    fun isRunning(): Boolean = running.get()

    fun getCaAuthority(): CertAuthority? = ca

    fun start() {
        if (running.getAndSet(true)) return

        executor.execute {
            try {
                if (config.mitm) {
                    ca = CertAuthority(filesDir)
                    LogBus.log("شهادة CA جاهزة في: ${ca?.getCaFile()?.absolutePath}")
                }

                val srv = ServerSocket()
                srv.reuseAddress = true
                srv.bind(InetSocketAddress(config.listenHost, config.listenPort), 256)
                serverSocket = srv
                onRunningChanged(true)

                val fronts = config.frontList()
                val transportMode = if (config.transportMode == ProxyConfig.MODE_RELAY) "apps_script_relay" else "front"
                LogBus.log(
                    "بدء الاستماع ${config.listenHost}:${config.listenPort} | " +
                            "transport=$transportMode | front_domain=${if (config.transportMode == ProxyConfig.MODE_RELAY) "ignored" else fronts.joinToString(",")} | " +
                            "fronts=${fronts.size} | mitm=${config.mitm} | " +
                            "sni_mode=${config.sniMode} | insecure=${config.insecure} | " +
                            "google_relay=${config.transportMode == ProxyConfig.MODE_RELAY}"
                )

                while (running.get()) {
                    val client = try {
                        srv.accept()
                    } catch (e: Exception) {
                        if (running.get()) {
                            LogBus.log("خطأ في قبول الاتصال: ${e.message}", "ERR")
                        }
                        break
                    }

                    executor.execute {
                        val count = activeConnections.incrementAndGet()
                        onStatsChanged(count)
                        try {
                            handleClient(client)
                        } finally {
                            val rem = activeConnections.decrementAndGet()
                            onStatsChanged(rem)
                        }
                    }
                }
            } catch (e: Exception) {
                LogBus.log("فشل تشغيل الخادم: ${e.message}", "ERR")
                onRunningChanged(false)
                stop()
            }
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
        onRunningChanged(false)
        LogBus.log("تم إيقاف البروكسي")
    }

    private fun createRelaxedClientContext(): SSLContext {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, SecureRandom())
        return ctx
    }

    private fun configureRelaxedTlsSocket(sslSocket: SSLSocket, sniHostname: String?) {
        // تفعيل كافة نسخ TLS المتاحة في الجهاز
        val supportedProtocols = sslSocket.supportedProtocols.filter {
            it.startsWith("TLSv1") || it.startsWith("SSLv3")
        }
        if (supportedProtocols.isNotEmpty()) {
            sslSocket.enabledProtocols = supportedProtocols.toTypedArray()
        }

        // تفعيل كافة الـ Cipher Suites المدعومة
        val supportedCiphers = sslSocket.supportedCipherSuites
        if (supportedCiphers.isNotEmpty()) {
            sslSocket.enabledCipherSuites = supportedCiphers
        }

        val params: SSLParameters = sslSocket.sslParameters
        try {
            params.applicationProtocols = arrayOf("http/1.1")
        } catch (_: Throwable) {
        }

        if (!sniHostname.isNullOrBlank() && !isIpAddress(sniHostname)) {
            try {
                params.serverNames = listOf(SNIHostName(sniHostname))
            } catch (_: Exception) {
            }
        } else {
            try {
                params.serverNames = emptyList()
            } catch (_: Exception) {
            }
        }
        sslSocket.sslParameters = params
    }

    private fun isGoogle(host: String): Boolean {
        val h = host.lowercase()
        val suffixes = listOf(
            ".google.com", ".googleapis.com", ".gstatic.com",
            ".gvt1.com", ".gvt2.com", ".googlevideo.com",
            ".youtube.com", ".ytimg.com", ".googleusercontent.com",
            ".appspot.com", ".cloud.google.com"
        )
        return suffixes.any { h.contains(it) } || h.endsWith("google.com") || h.endsWith("googleapis.com")
    }

    private fun pickSni(front: String, target: String): String {
        return when (config.sniMode) {
            "front" -> front
            "target" -> target
            else -> {
                val frontG = isGoogle(front)
                val targetG = isGoogle(target)
                if (frontG && targetG) target
                else if (frontG && !targetG) front
                else target
            }
        }
    }

    private fun pickFront(): String {
        val list = config.frontList()
        if (list.isEmpty()) return "google.com"
        return list[Random.nextInt(list.size)]
    }

    private data class FrontTlsResult(
        val front: String,
        val socket: SSLSocket,
        val sni: String
    )

    private fun tlsToFront(targetHost: String): FrontTlsResult {
        val front = pickFront()
        val timeoutMs = config.timeoutSec * 1000
        val sni = if (config.mitm && config.sniMode == "auto") {
            front
        } else {
            pickSni(front, targetHost)
        }

        val raw = Socket()
        raw.tcpNoDelay = true
        raw.keepAlive = true
        raw.soTimeout = timeoutMs
        raw.connect(InetSocketAddress(front, config.frontPort), timeoutMs)

        try {
            val sslSock = relaxedClientSslContext.socketFactory.createSocket(
                raw,
                sni,
                config.frontPort,
                true
            ) as SSLSocket
            configureRelaxedTlsSocket(sslSock, sni)
            sslSock.startHandshake()
            return FrontTlsResult(front, sslSock, sni)
        } catch (e: SSLException) {
            try { raw.close() } catch (_: Exception) {}
            if (config.insecure) {
                val retryRaw = Socket()
                retryRaw.tcpNoDelay = true
                retryRaw.keepAlive = true
                retryRaw.soTimeout = timeoutMs
                retryRaw.connect(InetSocketAddress(front, config.frontPort), timeoutMs)
                try {
                    val sslFallback = relaxedClientSslContext.socketFactory.createSocket(
                        retryRaw,
                        "",
                        config.frontPort,
                        true
                    ) as SSLSocket
                    configureRelaxedTlsSocket(sslFallback, null)
                    sslFallback.startHandshake()
                    return FrontTlsResult(front, sslFallback, "none(insecure)")
                } catch (ex: Exception) {
                    try { retryRaw.close() } catch (_: Exception) {}
                    throw ex
                }
            } else {
                throw e
            }
        }
    }

    private fun isBlocked(host: String): Boolean {
        val h = host.lowercase()
        return config.blacklistSet().any { b -> h == b || h.endsWith(".$b") }
    }

    private fun checkAuth(requestBytes: ByteArray): Boolean {
        val expected = config.auth.trim()
        if (expected.isEmpty()) return true
        val headerStr = String(requestBytes, Charsets.ISO_8859_1)
        for (line in headerStr.split("\r\n")) {
            if (line.lowercase().startsWith("proxy-authorization:")) {
                val value = line.substringAfter(":").trim()
                return value == expected || value == "Basic $expected"
            }
        }
        return false
    }

    private fun rewriteRequest(requestBytes: ByteArray, targetHost: String): ByteArray {
        val rawStr = String(requestBytes, Charsets.ISO_8859_1)
        val sepIndex = rawStr.indexOf("\r\n\r\n")
        val headerPart = if (sepIndex >= 0) rawStr.substring(0, sepIndex) else rawStr
        val bodyOffset = if (sepIndex >= 0) sepIndex + 4 else requestBytes.size

        val lines = headerPart.split("\r\n")
        if (lines.isEmpty()) return requestBytes

        val outLines = mutableListOf<String>()
        outLines.add(lines[0])
        var hasHost = false

        for (i in 1 until lines.size) {
            val line = lines[i]
            val low = line.lowercase()
            when {
                low.startsWith("host:") -> {
                    outLines.add("Host: $targetHost")
                    hasHost = true
                }
                low.startsWith("proxy-connection:") || low.startsWith("proxy-authorization:") -> {
                    continue
                }
                config.userAgent.isNotBlank() && low.startsWith("user-agent:") -> {
                    outLines.add("User-Agent: ${config.userAgent.trim()}")
                }
                else -> outLines.add(line)
            }
        }

        if (!hasHost) {
            outLines.add(1, "Host: $targetHost")
        }

        val rebuiltHeaders = (outLines.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1)
        val out = ByteArrayOutputStream(rebuiltHeaders.size + (requestBytes.size - bodyOffset))
        out.write(rebuiltHeaders)
        if (bodyOffset < requestBytes.size) {
            out.write(requestBytes, bodyOffset, requestBytes.size - bodyOffset)
        }
        return out.toByteArray()
    }

    private fun readCompleteHttpRequest(input: InputStream, initial: ByteArray): RelayHttpRequest {
        val stream = SequenceInputStream(ByteArrayInputStream(initial), BufferedInputStream(input))
        val headerOut = ByteArrayOutputStream()
        var tail = 0
        var foundEnd = false
        while (headerOut.size() < MAX_HTTP_HEADER_BYTES) {
            val value = stream.read()
            if (value < 0) break
            headerOut.write(value)
            tail = (tail shl 8 or value) and 0xFFFFFFFF.toInt()
            if (tail == 0x0D0A0D0A) {
                foundEnd = true
                break
            }
        }
        if (!foundEnd) throw IOException("HTTP header is incomplete or exceeds 64 KiB")

        val headerBytes = headerOut.toByteArray()
        val headerText = String(headerBytes, 0, headerBytes.size - 4, Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        val requestParts = lines.firstOrNull().orEmpty().trim().split(Regex("\\s+"))
        if (requestParts.size < 2) throw IOException("Invalid HTTP request line")

        val headers = LinkedHashMap<String, String>()
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val name = line.substring(0, colon).trim()
            val value = line.substring(colon + 1).trim()
            val existingKey = headers.keys.firstOrNull { it.equals(name, ignoreCase = true) }
            if (existingKey == null) headers[name] = value
            else headers[existingKey] = "${headers[existingKey]}, $value"
        }

        val transferEncoding = headers.entries
            .firstOrNull { it.key.equals("transfer-encoding", ignoreCase = true) }
            ?.value.orEmpty().lowercase()
        val body = if (transferEncoding.split(',').any { it.trim() == "chunked" }) {
            readChunkedBody(stream)
        } else {
            val contentLength = headers.entries
                .firstOrNull { it.key.equals("content-length", ignoreCase = true) }
                ?.value?.trim()?.toLongOrNull() ?: 0L
            if (contentLength < 0 || contentLength > MAX_RELAY_REQUEST_BODY_BYTES) {
                throw IOException("Request body exceeds the 16 MiB relay limit")
            }
            readExactly(stream, contentLength.toInt())
        }

        return RelayHttpRequest(requestParts[0].uppercase(), requestParts[1], headers, body)
    }

    private fun readExactly(input: InputStream, length: Int): ByteArray {
        val result = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val count = input.read(result, offset, length - offset)
            if (count < 0) throw IOException("Unexpected end of HTTP request body")
            offset += count
        }
        return result
    }

    private fun readAsciiLine(input: InputStream, maxBytes: Int = 8192): String {
        val line = ByteArrayOutputStream()
        while (line.size() <= maxBytes) {
            val value = input.read()
            if (value < 0) throw IOException("Unexpected end of chunked request")
            if (value == 10) break
            if (value != 13) line.write(value)
        }
        if (line.size() > maxBytes) throw IOException("Chunk header is too long")
        return String(line.toByteArray(), Charsets.ISO_8859_1)
    }

    private fun readChunkedBody(input: InputStream): ByteArray {
        val body = ByteArrayOutputStream()
        while (true) {
            val line = readAsciiLine(input)
            val chunkLength = line.substringBefore(';').trim().toLongOrNull(16)
                ?: throw IOException("Invalid chunked request size")
            if (chunkLength < 0 || chunkLength > MAX_RELAY_REQUEST_BODY_BYTES - body.size()) {
                throw IOException("Chunked request body exceeds the 16 MiB relay limit")
            }
            if (chunkLength == 0L) {
                while (readAsciiLine(input).isNotEmpty()) { /* consume trailers */ }
                break
            }
            val chunk = readExactly(input, chunkLength.toInt())
            body.write(chunk)
            val cr = input.read()
            val lf = input.read()
            if (cr != 13 || lf != 10) throw IOException("Invalid chunk terminator")
        }
        return body.toByteArray()
    }

    private fun sendViaGoogleAppsScript(
        request: RelayHttpRequest,
        fallbackHost: String?,
        fallbackScheme: String
    ): ByteArray {
        val authKey = config.googleRelayAuthKey
        if (authKey.isBlank()) throw IOException("Enter the AUTH_KEY from Code.gs")

        val endpoint = URL(config.googleRelayUrl.trim())
        if (endpoint.protocol != "https") throw IOException("Apps Script endpoint must use HTTPS")
        val targetUrl = resolveTargetUrl(request, fallbackHost, fallbackScheme)
        val destinationHost = URI(targetUrl).host ?: throw IOException("Invalid target host")
        if (isBlocked(destinationHost)) return httpErrorResponse(403, "Blocked by FrontGuard")
        val requestHeaders = JSONObject()
        var contentType = ""
        val excluded = setOf(
            "host", "connection", "keep-alive", "proxy-connection", "proxy-authorization",
            "content-length", "transfer-encoding", "upgrade", "te", "trailer"
        )
        for ((name, value) in request.headers) {
            val lower = name.lowercase()
            if (lower == "content-type") contentType = value
            if (lower == "user-agent" && config.userAgent.isNotBlank()) continue
            if (lower in excluded || name.contains('\r') || name.contains('\n')) continue
            requestHeaders.put(name, value)
        }
        if (config.userAgent.isNotBlank()) requestHeaders.put("User-Agent", config.userAgent.trim())
        if (request.headers.keys.any { it.equals("upgrade", ignoreCase = true) }) {
            throw IOException("WebSocket Upgrade cannot be relayed through Apps Script")
        }

        val payload = JSONObject()
            .put("k", authKey)
            .put("m", request.method)
            .put("u", targetUrl)
            .put("r", true)
        if (requestHeaders.length() > 0) payload.put("h", requestHeaders)
        if (request.body.isNotEmpty()) {
            payload.put("b", Base64.encodeToString(request.body, Base64.NO_WRAP))
            if (contentType.isNotBlank()) payload.put("ct", contentType)
        }

        val (status, responseText) = postAppsScriptJson(
            endpoint,
            payload.toString().toByteArray(Charsets.UTF_8)
        )
        if (status !in 200..299) {
            throw IOException("Apps Script HTTP $status: ${responseText.take(180)}")
        }
        val envelope = parseRelayEnvelope(responseText)
        val relayError = envelope.optString("e", "")
        if (relayError.isNotBlank()) throw IOException("Apps Script rejected request: ${relayError.take(180)}")

        val upstreamStatus = envelope.optInt("s", 200).coerceIn(100, 599)
        val bodyText = envelope.optString("b", "")
        val responseBody = if (bodyText.isEmpty()) byteArrayOf() else try {
            Base64.decode(bodyText, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            throw IOException("Apps Script returned invalid base64 body")
        }
        val responseHeaders = envelope.optJSONObject("h") ?: JSONObject()
        if (config.verbose) {
            LogBus.log("Google Apps Script relay ${request.method} $destinationHost -> HTTP $upstreamStatus")
        }
        return buildHttpResponse(upstreamStatus, responseHeaders, responseBody)
    }

    private fun postAppsScriptJson(endpoint: URL, payload: ByteArray): Pair<Int, String> {
        var currentUrl = endpoint
        var method = "POST"

        for (hop in 0..5) {
            val connection = (currentUrl.openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = config.timeoutSec * 1000
                readTimeout = maxOf(config.timeoutSec * 1000, 60_000)
                instanceFollowRedirects = false
                useCaches = false
                setRequestProperty("Accept", "application/json")
                if (this is HttpsURLConnection) {
                    // Relay TLS is deliberately independent from Front TLS.
                    if (!config.verifyRelayTls) {
                        // Only the explicit Relay diagnostic switch uses the
                        // trust-all context. In verified mode Android's
                        // platform HttpsURLConnection remains untouched.
                        sslSocketFactory = relaxedClientSslContext.socketFactory
                        hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
                    }
                }
                if (method == "POST") {
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json; charset=utf-8")
                }
            }
            try {
                if (method == "POST") {
                    connection.outputStream.use { it.write(payload) }
                }
                val status = connection.responseCode
                val location = connection.getHeaderField("Location")
                if (status in 301..308 && !location.isNullOrBlank() && hop < 5) {
                    val nextUrl = URL(currentUrl, location)
                    val nextHost = nextUrl.host.lowercase()
                    val sameHost = nextHost == endpoint.host.lowercase()
                    val googleContentHost = nextHost == "googleusercontent.com" ||
                        nextHost.endsWith(".googleusercontent.com")
                    if (nextUrl.protocol != "https" || (!sameHost && !googleContentHost)) {
                        throw IOException("Apps Script redirect host is not trusted")
                    }
                    if (status == 301 || status == 302 || status == 303) method = "GET"
                    currentUrl = nextUrl
                    continue
                }
                val responseStream = if (status in 200..399) connection.inputStream else connection.errorStream
                val responseText = responseStream?.use {
                    readTextLimited(it, MAX_RELAY_RESPONSE_JSON_BYTES)
                }.orEmpty()
                return status to responseText
            } finally {
                connection.disconnect()
            }
        }
        throw IOException("Apps Script redirect limit exceeded")
    }

    private fun resolveTargetUrl(
        request: RelayHttpRequest,
        fallbackHost: String?,
        fallbackScheme: String
    ): String {
        val target = request.target
        val parsed = try { URI(target) } catch (_: Exception) { null }
        if (parsed != null && parsed.isAbsolute) {
            val scheme = parsed.scheme?.lowercase()
            if (scheme != "http" && scheme != "https") throw IOException("Only HTTP(S) URLs can be relayed")
            if (parsed.host.isNullOrBlank()) throw IOException("Invalid target URL")
            return parsed.toASCIIString()
        }
        val host = request.headers.entries
            .firstOrNull { it.key.equals("host", ignoreCase = true) }
            ?.value?.trim()?.ifBlank { null } ?: fallbackHost?.trim()?.ifBlank { null }
            ?: throw IOException("Missing target Host header")
        val path = if (target.startsWith("/")) target else "/$target"
        val url = "$fallbackScheme://$host$path"
        val uri = try { URI(url) } catch (_: Exception) { throw IOException("Invalid target URL") }
        if ((uri.scheme != "http" && uri.scheme != "https") || uri.host.isNullOrBlank()) {
            throw IOException("Invalid target URL")
        }
        return uri.toASCIIString()
    }

    private fun parseRelayEnvelope(text: String): JSONObject {
        val trimmed = text.trim()
        try {
            return JSONObject(trimmed)
        } catch (_: JSONException) {
            val start = trimmed.indexOf('{')
            val end = trimmed.lastIndexOf('}')
            if (start >= 0 && end > start) {
                try { return JSONObject(trimmed.substring(start, end + 1)) }
                catch (_: JSONException) { }
            }
            throw IOException("Apps Script returned non-JSON; check deployment and AUTH_KEY")
        }
    }

    private fun readTextLimited(input: InputStream, maxBytes: Int): String {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (output.size() + count > maxBytes) throw IOException("Apps Script response exceeds the 24 MiB JSON limit")
            output.write(buffer, 0, count)
        }
        return String(output.toByteArray(), Charsets.UTF_8)
    }

    private fun buildHttpResponse(status: Int, headers: JSONObject, body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(body.size + 1024)
        out.write("HTTP/1.1 $status ${reasonPhrase(status)}\r\n".toByteArray(Charsets.ISO_8859_1))
        val skip = setOf(
            "connection", "keep-alive", "transfer-encoding", "content-length",
            "proxy-authenticate", "proxy-authorization", "upgrade", "trailer"
        )
        val keys = headers.keys()
        while (keys.hasNext()) {
            val name = keys.next()
            if (name.contains('\r') || name.contains('\n') || name.contains(':') || name.lowercase() in skip) continue
            val value = headers.opt(name)
            if (value == null || value == JSONObject.NULL) continue
            if (value is JSONArray) {
                for (i in 0 until value.length()) writeResponseHeader(out, name, value.optString(i))
            } else {
                writeResponseHeader(out, name, value.toString())
            }
        }
        out.write("Content-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
        out.write(body)
        return out.toByteArray()
    }

    private fun writeResponseHeader(out: ByteArrayOutputStream, name: String, value: String) {
        val safeValue = value.replace('\r', ' ').replace('\n', ' ')
        out.write("$name: $safeValue\r\n".toByteArray(Charsets.ISO_8859_1))
    }

    private fun reasonPhrase(status: Int): String = when (status) {
        200 -> "OK"; 201 -> "Created"; 202 -> "Accepted"; 204 -> "No Content"
        206 -> "Partial Content"; 301 -> "Moved Permanently"; 302 -> "Found"
        303 -> "See Other"; 304 -> "Not Modified"; 307 -> "Temporary Redirect"
        308 -> "Permanent Redirect"; 400 -> "Bad Request"; 401 -> "Unauthorized"
        403 -> "Forbidden"; 404 -> "Not Found"; 405 -> "Method Not Allowed"
        408 -> "Request Timeout"; 413 -> "Payload Too Large"; 429 -> "Too Many Requests"
        500 -> "Internal Server Error"; 501 -> "Not Implemented"; 502 -> "Bad Gateway"
        503 -> "Service Unavailable"; 504 -> "Gateway Timeout"
        else -> "Upstream Response"
    }

    private fun httpErrorResponse(status: Int, message: String): ByteArray {
        val body = message.replace('\r', ' ').replace('\n', ' ').toByteArray(Charsets.UTF_8)
        val head = "HTTP/1.1 $status ${reasonPhrase(status)}\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n"
        return head.toByteArray(Charsets.ISO_8859_1) + body
    }

    private fun readInitialHttpPacket(input: InputStream): ByteArray? {
        val buf = ByteArray(BUFFER_SIZE)
        val n = input.read(buf)
        if (n <= 0) return null
        return buf.copyOfRange(0, n)
    }

    private fun handleClient(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.keepAlive = true
            client.soTimeout = config.timeoutSec * 1000

            val data = readInitialHttpPacket(client.getInputStream())
            if (data == null) {
                client.close()
                return
            }

            if (!checkAuth(data)) {
                val resp = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
                        "Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
                        "Content-Length: 0\r\n\r\n"
                client.getOutputStream().write(resp.toByteArray(Charsets.ISO_8859_1))
                client.close()
                return
            }

            val firstLine = String(data, Charsets.ISO_8859_1).substringBefore("\r\n")
            val parts = firstLine.split(" ")
            if (parts.size < 2) {
                client.close()
                return
            }

            val method = parts[0].uppercase()
            val url = parts[1]

            if (method == "CONNECT") {
                handleConnect(client, url)
            } else if (config.transportMode == ProxyConfig.MODE_RELAY) {
                try {
                    val request = readCompleteHttpRequest(client.getInputStream(), data)
                    val response = sendViaGoogleAppsScript(request, null, "http")
                    client.getOutputStream().write(response)
                    client.getOutputStream().flush()
                } catch (e: Exception) {
                    if (config.verbose) LogBus.log("Google relay HTTP: ${e.message}", "ERR")
                    client.getOutputStream().write(httpErrorResponse(502, e.message ?: "Google relay failed"))
                    client.getOutputStream().flush()
                } finally {
                    try { client.close() } catch (_: Exception) {}
                }
            } else {
                handleHttp(client, data, method, url)
            }
        } catch (e: Exception) {
            if (config.verbose) {
                LogBus.log("handle: ${e.message}", "ERR")
            }
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun handleConnect(client: Socket, url: String) {
        val hp = url.split(":")
        val targetHost = hp[0]
        val targetPort = if (hp.size > 1) hp[1].toIntOrNull() ?: 443 else 443

        if (isBlocked(targetHost)) {
            client.getOutputStream().write(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
            )
            client.close()
            return
        }

        if (config.transportMode == ProxyConfig.MODE_RELAY && (!config.mitm || targetPort != 443)) {
            val reason = if (!config.mitm) {
                "Google Apps Script relay requires MITM for HTTPS"
            } else {
                "Google Apps Script relay supports HTTPS CONNECT on port 443"
            }
            client.getOutputStream().write(httpErrorResponse(501, reason))
            client.close()
            return
        }

        if (config.mitm && targetPort == 443) {
            mitmConnect(client, targetHost)
        } else {
            rawConnect(client, targetHost, targetPort)
        }
    }

    private fun rawConnect(client: Socket, targetHost: String, targetPort: Int) {
        val retries = maxOf(1, config.retryCount)
        val timeoutMs = config.timeoutSec * 1000

        for (attempt in 1..retries) {
            val front = pickFront()
            try {
                val upstream = Socket()
                upstream.tcpNoDelay = true
                upstream.keepAlive = true
                upstream.soTimeout = timeoutMs
                upstream.connect(InetSocketAddress(front, config.frontPort), timeoutMs)

                client.getOutputStream().write(
                    "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
                )
                if (config.verbose) {
                    LogBus.log("CONNECT $targetHost:$targetPort -> raw via $front")
                }
                pump(client, upstream)
                return
            } catch (e: Exception) {
                if (config.verbose) {
                    LogBus.log("raw retry ($attempt/$retries): ${e.message}", "WARN")
                }
            }
        }

        try {
            client.getOutputStream().write(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
            )
            client.close()
        } catch (_: Exception) {
        }
    }

    private fun isIpAddress(host: String): Boolean {
        val ipv4Regex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        return ipv4Regex.matches(host) || host.contains(":")
    }

    private fun mitmConnect(client: Socket, targetHost: String) {
        if (isIpAddress(targetHost) && config.transportMode != ProxyConfig.MODE_RELAY) {
            try {
                InetAddress.getByName(targetHost)
                rawConnect(client, targetHost, 443)
                return
            } catch (_: Exception) {
            }
        }

        client.getOutputStream().write(
            "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        )

        val browserTls: SSLSocket = try {
            val serverCtx = ca!!.leafContextFor(targetHost)
            val sslSock = serverCtx.socketFactory.createSocket(
                client,
                client.inetAddress.hostAddress,
                client.port,
                true
            ) as SSLSocket
            sslSock.useClientMode = false
            configureRelaxedTlsSocket(sslSock, null)
            sslSock.startHandshake()
            sslSock
        } catch (e: Exception) {
            if (config.verbose) {
                LogBus.log("mitm handshake ($targetHost): ${e.message}", "ERR")
            }
            try { client.close() } catch (_: Exception) {}
            return
        }

        try {
            if (config.transportMode == ProxyConfig.MODE_RELAY) {
                try {
                    val request = readCompleteHttpRequest(browserTls.inputStream, byteArrayOf())
                    val response = sendViaGoogleAppsScript(request, targetHost, "https")
                    browserTls.outputStream.write(response)
                    browserTls.outputStream.flush()
                } catch (e: Exception) {
                    if (config.verbose) LogBus.log("Google relay HTTPS ($targetHost): ${e.message}", "ERR")
                    browserTls.outputStream.write(
                        httpErrorResponse(502, e.message ?: "Google relay failed")
                    )
                    browserTls.outputStream.flush()
                }
                return
            }

            val req = readInitialHttpPacket(browserTls.inputStream)
            if (req == null) {
                browserTls.close()
                return
            }

            val firstLine = String(req, Charsets.ISO_8859_1).substringBefore("\r\n")
            val method = firstLine.substringBefore(" ").ifEmpty { "GET" }
            val rebuilt = rewriteRequest(req, targetHost)

            val retries = maxOf(1, config.retryCount)
            for (attempt in 1..retries) {
                try {
                    val (front, upstream, sni) = tlsToFront(targetHost)
                    upstream.outputStream.write(rebuilt)
                    upstream.outputStream.flush()
                    if (config.verbose) {
                        LogBus.log("MITM $method $targetHost -> front=$front sni=$sni")
                    }
                    pump(browserTls, upstream)
                    return
                } catch (e: Exception) {
                    if (config.verbose) {
                        LogBus.log("mitm retry ($attempt/$retries): ${e.message}", "ERR")
                    }
                }
            }

            try {
                browserTls.outputStream.write(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
                )
            } catch (_: Exception) {
            }
        } finally {
            try { browserTls.close() } catch (_: Exception) {}
        }
    }

    private fun handleHttp(client: Socket, data: ByteArray, method: String, url: String) {
        val rawStr = String(data, Charsets.ISO_8859_1)
        val targetHost: String
        val path: String

        if (url.startsWith("http://")) {
            val uri = URI(url)
            targetHost = uri.host ?: ""
            val rawPath = uri.rawPath?.ifEmpty { "/" } ?: "/"
            path = if (uri.rawQuery != null) "$rawPath?${uri.rawQuery}" else rawPath
        } else {
            val hostLine = rawStr.split("\r\n").firstOrNull { it.lowercase().startsWith("host:") }
            if (hostLine == null) {
                client.getOutputStream().write(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
                )
                client.close()
                return
            }
            targetHost = hostLine.substringAfter(":").trim()
            path = url
        }

        if (isBlocked(targetHost)) {
            client.getOutputStream().write(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
            )
            client.close()
            return
        }

        val firstCrlf = rawStr.indexOf("\r\n")
        val restBytes = if (firstCrlf >= 0) {
            data.copyOfRange(firstCrlf, data.size)
        } else {
            "\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        }

        val firstLineBytes = "$method $path HTTP/1.1".toByteArray(Charsets.ISO_8859_1)
        val combined = ByteArray(firstLineBytes.size + restBytes.size)
        System.arraycopy(firstLineBytes, 0, combined, 0, firstLineBytes.size)
        System.arraycopy(restBytes, 0, combined, firstLineBytes.size, restBytes.size)

        val rebuilt = rewriteRequest(combined, targetHost)
        val retries = maxOf(1, config.retryCount)

        for (attempt in 1..retries) {
            try {
                val (front, upstream, sni) = tlsToFront(targetHost)
                upstream.outputStream.write(rebuilt)
                upstream.outputStream.flush()
                if (config.verbose) {
                    LogBus.log("$method $targetHost$path -> front=$front sni=$sni")
                }
                pump(client, upstream)
                return
            } catch (e: Exception) {
                if (config.verbose) {
                    LogBus.log("http retry ($attempt/$retries): ${e.message}", "ERR")
                }
            }
        }

        try {
            client.getOutputStream().write(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
            )
            client.close()
        } catch (_: Exception) {
        }
    }

    private fun pump(sockA: Socket, sockB: Socket) {
        val latch = CountDownLatch(1)

        val jobAtoB = Runnable {
            pipeStream(sockA, sockB)
            latch.countDown()
        }
        val jobBtoA = Runnable {
            pipeStream(sockB, sockA)
            latch.countDown()
        }

        executor.execute(jobAtoB)
        executor.execute(jobBtoA)

        try {
            latch.await(config.timeoutSec.toLong() * 6L, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
        } finally {
            closeQuietly(sockA)
            closeQuietly(sockB)
        }
    }

    private fun pipeStream(src: Socket, dst: Socket) {
        val buf = ByteArray(BUFFER_SIZE)
        try {
            val input: InputStream = src.getInputStream()
            val output: OutputStream = dst.getOutputStream()
            while (!src.isClosed && !dst.isClosed) {
                val n = input.read(buf)
                if (n <= 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (_: Exception) {
        }
    }

    private fun closeQuietly(s: Socket) {
        try { s.close() } catch (_: Exception) {}
    }
}
