plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
}

group = "com.fsociety.auth"
version = "0.0.1-SNAPSHOT"
description = "smal-ms"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
    maven { url = uri("https://build.shibboleth.net/maven/releases/") }
}

dependencies {
    implementation(libs.spring.boot.starter.webmvc)
    implementation(libs.kotlin.reflect)
    implementation(libs.jackson.kotlin)
    implementation(libs.bundles.opensaml)

    testImplementation(libs.spring.boot.starter.webmvc.test)
    testImplementation(libs.kotlin.test.junit)
    testRuntimeOnly(libs.junit.platform.launcher)
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict", "-Xannotation-default-target=param-property")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
