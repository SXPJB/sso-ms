package com.fsociety.auth.sso.ms.core.config

import jakarta.annotation.PostConstruct
import org.opensaml.core.config.InitializationService
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Configuration

@Configuration
class OpenSamlBootstrapper {

    private val log = LoggerFactory.getLogger(OpenSamlBootstrapper::class.java)

    @PostConstruct
    fun init() {
        InitializationService.initialize()
        log.info("OpenSAML 5 initialized successfully")
    }
}