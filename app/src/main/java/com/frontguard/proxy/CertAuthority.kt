package com.frontguard.proxy

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * سلطة شهادات (CA) متوافقة مع OpenSSL 3.x
 * تولّد CA وشهادات فرعية (Leaf) تحتوي على SKI و AKI و SAN
 */
class CertAuthority(private val caDir: File) {

    private val bcProvider = BouncyCastleProvider()
    private val caKeyFile = File(caDir, "cf_fronting_ca.key")
    private val caCertFile = File(caDir, "cf_fronting_ca.pem")
    private val cache = ConcurrentHashMap<String, SSLContext>()

    private lateinit var caKey: PrivateKey
    private lateinit var caCert: X509Certificate

    init {
        if (!caDir.exists()) caDir.mkdirs()
        loadOrGenerateCA()
    }

    @Synchronized
    private fun loadOrGenerateCA() {
        if (caKeyFile.exists() && caCertFile.exists()) {
            try {
                PEMParser(FileReader(caKeyFile)).use { parser ->
                    val obj = parser.readObject()
                    val converter = JcaPEMKeyConverter().setProvider(bcProvider)
                    caKey = when (obj) {
                        is PEMKeyPair -> converter.getKeyPair(obj).private
                        is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> converter.getPrivateKey(obj)
                        else -> throw IllegalStateException("تنسيق مفتاح غير معروف")
                    }
                }
                PEMParser(FileReader(caCertFile)).use { parser ->
                    val holder = parser.readObject() as org.bouncycastle.cert.X509CertificateHolder
                    caCert = JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(holder)
                }
                // تحقق من وجود SKI للتوافق مع OpenSSL 3.x
                val ski = caCert.getExtensionValue(Extension.subjectKeyIdentifier.id)
                if (ski != null) {
                    LogBus.log("تم تحميل شهادة CA الموجودة (SKI/AKI متوافق)")
                    return
                } else {
                    LogBus.log("شهادة CA قديمة بدون SKI — سيتم إعادة توليدها", "WARN")
                }
            } catch (e: Exception) {
                LogBus.log("تعذر قراءة CA الحالي (${e.message}) — سيتم توليد جديد", "WARN")
            }
        }
        regenerateCA()
    }

    @Synchronized
    private fun regenerateCA() {
        LogBus.log("جاري توليد شهادة CA جديدة متوافقة مع OpenSSL 3.x...")
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val kp: KeyPair = kpg.generateKeyPair()
        caKey = kp.private

        val issuer = X500Name("CN=CF Fronting CA")
        val subject = issuer
        val serial = BigInteger(159, SecureRandom()).abs().max(BigInteger.ONE)
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 86400_000L)
        val notAfter = Date(now + 3650L * 86400_000L)

        val extUtils = JcaX509ExtensionUtils()
        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, kp.public
        )

        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            extUtils.createSubjectKeyIdentifier(kp.public)
        )
        builder.addExtension(
            Extension.keyUsage,
            true,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign)
        )

        val signer = JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(bcProvider)
            .build(caKey)

        val holder = builder.build(signer)
        caCert = JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(holder)

        JcaPEMWriter(FileWriter(caKeyFile)).use { it.writeObject(caKey) }
        JcaPEMWriter(FileWriter(caCertFile)).use { it.writeObject(caCert) }

        cache.clear()
        LogBus.log("تم توليد وحفظ شهادة CA بنجاح: ${caCertFile.absolutePath}")
    }

    fun leafContextFor(rawHostname: String): SSLContext {
        val hostname = rawHostname.substringBefore(":").lowercase().trim()
        cache[hostname]?.let { return it }

        synchronized(this) {
            cache[hostname]?.let { return it }

            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048, SecureRandom())
            val leafKp = kpg.generateKeyPair()

            val now = System.currentTimeMillis()
            val notBefore = Date(now - 86400_000L)
            val notAfter = Date(now + 365L * 86400_000L)
            val serial = BigInteger(159, SecureRandom()).abs().max(BigInteger.ONE)

            val subject = X500Name("CN=$hostname")
            val issuer = X500Name(caCert.subjectX500Principal.name)

            val sanList = mutableListOf(GeneralName(GeneralName.dNSName, hostname))
            val parts = hostname.split(".")
            if (parts.size > 2) {
                sanList.add(GeneralName(GeneralName.dNSName, parts.drop(1).joinToString(".")))
            }

            val extUtils = JcaX509ExtensionUtils()
            val builder = JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, leafKp.public
            )

            builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(sanList.toTypedArray())
            )
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(leafKp.public)
            )
            builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(caCert.publicKey)
            )
            builder.addExtension(
                Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
            )
            builder.addExtension(
                Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
            )

            val signer = JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(bcProvider)
                .build(caKey)

            val leafCert = JcaX509CertificateConverter()
                .setProvider(bcProvider)
                .getCertificate(builder.build(signer))

            val ks = KeyStore.getInstance("PKCS12")
            ks.load(null, null)
            val password = "changeit".toCharArray()
            ks.setKeyEntry("leaf", leafKp.private, password, arrayOf(leafCert, caCert))

            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, password)

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(kmf.keyManagers, null, SecureRandom())

            // حفظ في الذاكرة المؤقتة (بحد أقصى 250 نطاق لمنع استهلاك الذاكرة)
            if (cache.size > 250) {
                cache.clear()
            }
            cache[hostname] = sslContext
            return sslContext
        }
    }

    fun getCaPemString(): String {
        val sw = StringWriter()
        JcaPEMWriter(sw).use { it.writeObject(caCert) }
        return sw.toString()
    }

    fun getCaFile(): File = caCertFile
}
