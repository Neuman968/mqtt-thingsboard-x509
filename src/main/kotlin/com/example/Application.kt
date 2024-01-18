package com.example
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.eclipse.paho.mqttv5.client.*
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence
import org.eclipse.paho.mqttv5.common.MqttException
import org.eclipse.paho.mqttv5.common.MqttMessage
import org.eclipse.paho.mqttv5.common.packet.MqttProperties
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
 * Attempting to publish telemetry with X509 authentication. Replicating mosquitto_pub command
 * mosquitto_pub --cafile thingsboard-root.pem -d -q 1 -h "mqtt.thingsboard.cloud" -p "8883" -t "v1/devices/me/telemetry" --key deviceKey.pem --cert chain.pem -m {"temperature":25}
 * NOTE: No Passwords for keys were used.
 */
fun main() {
    val broker = "ssl://mqtt.thingsboard.cloud:8883"


    val privateKeyPEM = File("deviceKey.pem").readText()
    val clientCertPEM = File("chain.pem").readText()

    // thingsboard certificate provided in guide, renamaed from "ca-cert.pem" in user guide.
    val caCertPEM = File("thingsboard-root.pem").readText()

    val key = getPrivateKey(privateKeyPEM)
    val clientCert = getCertificate(clientCertPEM)
    val caCert = getCertificate(caCertPEM)

    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(null, null)
    keyStore.setCertificateEntry("certificate", clientCert)
    keyStore.setKeyEntry("private-key", key, null, arrayOf(clientCert))

    val trustStore = KeyStore.getInstance("PKCS12")
    trustStore.load(null, null)
    trustStore.setCertificateEntry("ca-certificate", caCert)

    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    keyManagerFactory.init(keyStore, null)

    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(trustStore)

    val sslContext = SSLContext.getInstance("TLSv1.2")
    sslContext.init(keyManagerFactory.keyManagers, trustManagerFactory.trustManagers, null)

    try {
        val mqttOpts = MqttConnectionOptions()
        mqttOpts.socketFactory = sslContext.socketFactory
        mqttOpts.setAutomaticReconnect(true)
        mqttOpts.setKeepAliveInterval(10000)
        mqttOpts.setConnectionTimeout(30)

        val client = MqttClient(broker, null, MemoryPersistence())

        client.setCallback(object : MqttCallback {
            override fun disconnected(disconnectResponse: MqttDisconnectResponse) {
                println("Disconnected!")
            }

            override fun mqttErrorOccurred(exception: MqttException) {
                println("Disconnected!")
            }

            override fun messageArrived(topic: String, message: MqttMessage) {
                println("Message Arrived!")
            }

            override fun deliveryComplete(p0: IMqttToken?) {
                println("Delivery Complete!")
            }

            override fun connectComplete(reconnect: Boolean, serverURI: String) {
                println("Disconnected!")
            }

            override fun authPacketArrived(auth: Int, mqttAuth: MqttProperties) {
                println("Auth Packed Arrived!")
            }
        })

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

fun getPrivateKey(pem: String): PrivateKey {
    val reader = PEMParser(StringReader(pem))
    val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider())
    return converter.getPrivateKey(reader.readObject() as PrivateKeyInfo)
}

fun getCertificate(pem: String): X509Certificate {
    val reader = ByteArrayInputStream(pem.toByteArray())
    val cf = CertificateFactory.getInstance("X.509")
    return cf.generateCertificate(reader) as X509Certificate
}