package com.fsociety.auth.sso.ms.core.helper

import jakarta.annotation.PostConstruct
import org.opensaml.core.config.InitializationService
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Component
class OpenSamlBootstrapper {

    private val log = LoggerFactory.getLogger(OpenSamlBootstrapper::class.java)

    @PostConstruct
    fun init() {
        InitializationService.initialize()
        log.info("OpenSAML 5 initialized successfully")
    }
}
