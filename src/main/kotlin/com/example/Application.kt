package com.example

import org.apache.http.ssl.SSLContexts
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.eclipse.paho.mqttv5.client.MqttClient
import org.eclipse.paho.mqttv5.client.MqttConnectionOptions
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence
import org.eclipse.paho.mqttv5.common.MqttMessage
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringReader
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Certificates were generated following guide
 * https://thingsboard.io/docs/pe/user-guide/certificates/
 *
 * Replace all *_PATH variables with the locations of the certificates generated on your machine.
 *
 * publishes telemetry with X509 authentication. Replicating mosquitto_pub command
 * mosquitto_pub --cafile ca-root.pem -d -q 1 -h "mqtt.thingsboard.cloud" -p "8883" -t "v1/devices/me/telemetry" --key deviceKey.pem --cert chain.pem -m {"temperature":350}
 * NOTE: No Passwords for keys were used in this example.
 */

const val DEVICEKEY_PEM_PATH: String = "deviceKey.pem"

const val CERTIFICATE_CHAIN_PATH: String = "chain.pem"

// ca-root provided by thingsboard at https://thingsboard.io/docs/paas/user-guide/resources/mqtt-over-ssl/ca-root.pem
const val ROOT_CA_PATH: String = "ca-root.pem"

fun main() {
    val broker = "ssl://mqtt.thingsboard.cloud:8883"

    // replace file paths with the location of the certificates generated in https://thingsboard.io/docs/pe/user-guide/certificates/
    val privateKeyPEM = File(DEVICEKEY_PEM_PATH).readText()
    val clientCertPEM = File(CERTIFICATE_CHAIN_PATH).readText()

    val caCertPEM = File(ROOT_CA_PATH).readText()

    val key = getPrivateKey(privateKeyPEM)
    val clientCert = getCertificate(clientCertPEM)
    val caCert = getCertificate(caCertPEM)

    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(null, null)
    keyStore.setCertificateEntry("certificate", clientCert)

    // important that the alias used when loading the private key into the keystore is the same that is returned by
    // [PrivateKeyStrategy] provided to [SSLContext] loadKeyMaterial method.
    val privateKeyAlias = "private-key-alias"

    keyStore.setKeyEntry(privateKeyAlias, key, null, arrayOf(clientCert))

    val trustStore = KeyStore.getInstance("PKCS12")
    trustStore.load(null, null)
    trustStore.setCertificateEntry("ca-certificate", caCert)

    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    keyManagerFactory.init(keyStore, null)

    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(trustStore)

    // Use org.apache.httpcomponents to construct SSLContext that will use the private key in keystore to
    // handle 2 way TLS connection.
    val sslContext: SSLContext = SSLContexts.custom()
        .loadKeyMaterial(
            keyStore, null
        ) { p0, p1 -> privateKeyAlias }
        .loadTrustMaterial(trustStore, null)
        .build()

    try {
        val mqttOpts = MqttConnectionOptions()
        // override default socket factory to handle 2 way TLS Connection.
        mqttOpts.socketFactory = sslContext.socketFactory

        val client = MqttClient(broker, null, MemoryPersistence())

        client.connect(mqttOpts)

        val payload = """{"temperature": 350}"""
        val message = MqttMessage(payload.toByteArray(Charsets.UTF_8))
        message.qos = 2

        client.publish("v1/devices/me/telemetry", message)
        println("Message published! Message: $payload")
        client.disconnect()

    } catch (exp: Exception) {
        exp.printStackTrace()
    }
}

/**
 * Retrieves the private key from a PEM format.
 *
 * @param pem The PEM-formatted private key string.
 * @return The private key object.
 */
fun getPrivateKey(pem: String): PrivateKey {
    val reader = PEMParser(StringReader(pem))
    val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider())
    return converter.getPrivateKey(reader.readObject() as PrivateKeyInfo)
}

/**
 * Retrieves an X509 certificate from a PEM-encoded string.
 *
 * @param pem The PEM-encoded string representing the certificate.
 * @return The X509 certificate.
 */
fun getCertificate(pem: String): X509Certificate {
    val reader = ByteArrayInputStream(pem.toByteArray())
    val cf = CertificateFactory.getInstance("X.509")
    return cf.generateCertificate(reader) as X509Certificate
}