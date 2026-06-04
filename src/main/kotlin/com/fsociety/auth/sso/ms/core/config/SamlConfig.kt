package com.fsociety.auth.sso.ms.core.config

import net.shibboleth.shared.xml.ParserPool
import net.shibboleth.shared.xml.impl.BasicParserPool
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class SamlConfig {

    @Bean
    fun parserPool(): ParserPool {
        val pool = BasicParserPool()
        pool.maxPoolSize = 100
        pool.initialize()
        return pool
    }
}
