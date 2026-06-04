package com.fsociety.auth.sso.ms.core.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.time.Clock
import java.time.ZoneId

@Configuration
class CoreConfig {

    @Bean
    fun clock(): Clock = Clock.system(ZoneId.of("America/Mexico_City"))
}
