package com.frontguard.proxy

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
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
    private val onStatsChanged: (Int) -> Unit = {}
) {
    companion object {
        private const val BUFFER_SIZE = 65536
    }

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

                val fronts = config.frontList()
                LogBus.log(
                    "بدء الاستماع ${config.listenHost}:${config.listenPort} | " +
                            "fronts=${fronts.size} | mitm=${config.mitm} | " +
                            "sni_mode=${config.sniMode} | insecure=${config.insecure}"
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
        for (line in headerStr.split("
")) {
            if (line.lowercase().startsWith("proxy-authorization:")) {
                val value = line.substringAfter(":").trim()
                return value == expected || value == "Basic $expected"
            }
        }
        return false
    }

    private fun rewriteRequest(requestBytes: ByteArray, targetHost: String): ByteArray {
        val rawStr = String(requestBytes, Charsets.ISO_8859_1)
        val sepIndex = rawStr.indexOf("

")
        val headerPart = if (sepIndex >= 0) rawStr.substring(0, sepIndex) else rawStr
        val bodyOffset = if (sepIndex >= 0) sepIndex + 4 else requestBytes.size

        val lines = headerPart.split("
")
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

        val rebuiltHeaders = (outLines.joinToString("
") + "

").toByteArray(Charsets.ISO_8859_1)
        val out = ByteArrayOutputStream(rebuiltHeaders.size + (requestBytes.size - bodyOffset))
        out.write(rebuiltHeaders)
        if (bodyOffset < requestBytes.size) {
            out.write(requestBytes, bodyOffset, requestBytes.size - bodyOffset)
        }
        return out.toByteArray()
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
                val resp = "HTTP/1.1 407 Proxy Authentication Required
" +
                        "Proxy-Authenticate: Basic realm="proxy"
" +
                        "Content-Length: 0

"
                client.getOutputStream().write(resp.toByteArray(Charsets.ISO_8859_1))
                client.close()
                return
            }

            val firstLine = String(data, Charsets.ISO_8859_1).substringBefore("
")
            val parts = firstLine.split(" ")
            if (parts.size < 2) {
                client.close()
                return
            }

            val method = parts[0].uppercase()
            val url = parts[1]

            if (method == "CONNECT") {
                handleConnect(client, url)
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
                "HTTP/1.1 403 Forbidden
Content-Length: 0

".toByteArray(Charsets.ISO_8859_1)
            )
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
                    "HTTP/1.1 200 Connection Established

".toByteArray(Charsets.ISO_8859_1)
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
                "HTTP/1.1 502 Bad Gateway
Content-Length: 0

".toByteArray(Charsets.ISO_8859_1)
            )
            client.close()
        } catch (_: Exception) {
        }
    }

    private fun isIpAddress(host: String): Boolean {
        val ipv4Regex = Regex("^\d{1,3}(\.\d{1,3}){3}$")
        return ipv4Regex.matches(host) || host.contains(":")
    }

    private fun mitmConnect(client: Socket, targetHost: String) {
        if (isIpAddress(targetHost)) {
            try {
                InetAddress.getByName(targetHost)
                rawConnect(client, targetHost, 443)
                return
            } catch (_: Exception) {
            }
        }

        client.getOutputStream().write(
            "HTTP/1.1 200 Connection Established

".toByteArray(Charsets.ISO_8859_1)
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
            val req = readInitialHttpPacket(browserTls.inputStream)
            if (req == null) {
                browserTls.close()
                return
            }

            val firstLine = String(req, Charsets.ISO_8859_1).substringBefore("
")
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
                    "HTTP/1.1 502 Bad Gateway
Content-Length: 0

".toByteArray(Charsets.ISO_8859_1)
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
            val hostLine = rawStr.split("
").firstOrNull { it.lowercase().startsWith("host:") }
            if (hostLine == null) {
                client.getOutputStream().write(
                    "HTTP/1.1 400 Bad Request
Content-Length: 0

".toByteArray(Charsets.ISO_8859_1)
                )
                client.close()
                return
            }
            targetHost = hostLine.substringAfter(":").trim()
            path = url
        }

        if (isBlocked(targetHost)) {
            client.getOutputStream().write(
                "HTTP/1.1 403 Forbidden
Content-Length: 0

".toByteArray(Charsets.ISO_8859_1)
            )
            client.close()
            return
        }

        val firstCrlf = rawStr.indexOf("
")
        val restBytes = if (firstCrlf >= 0) {
            data.copyOfRange(firstCrlf, data.size)
        } else {
            "

".toByteArray(Charsets.ISO_8859_1)
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
                "HTTP/1.1 502 Bad Gateway
Content-Length: 0

".toByteArray(Charsets.ISO_8859_1)
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
        try { s. close() } catch (_: Exception) {}
    }
}
