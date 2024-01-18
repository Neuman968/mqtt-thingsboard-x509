val kotlin_version: String by project
val logback_version: String by project

plugins {
    kotlin("jvm") version "1.9.22"
}

group = "com.example"
version = "0.0.1"

repositories {
    mavenCentral()
}

dependencies {
    implementation("ch.qos.logback:logback-classic:$logback_version")

    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")
    implementation("org.eclipse.paho:org.eclipse.paho.mqttv5.client:1.2.5")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlin_version")
}
