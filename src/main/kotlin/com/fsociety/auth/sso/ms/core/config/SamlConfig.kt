package com.fsociety.auth.sso.ms.core.config

import net.shibboleth.shared.xml.ParserPool
import net.shibboleth.shared.xml.impl.BasicParserPool
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import javax.xml.XMLConstants

private const val FEATURE_DISALLOW_DOCTYPE_DECL = "http://apache.org/xml/features/disallow-doctype-decl"
private const val FEATURE_EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities"
private const val FEATURE_EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities"
private const val FEATURE_LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd"

private const val EMPTY_STRING = ""

@Configuration
class SamlConfig(
    private val maxPoolSize: Int = 100
) {

    @Bean
    fun parserPool(): ParserPool {
        val pool = BasicParserPool()

        pool.maxPoolSize = maxPoolSize
        pool.isNamespaceAware = true
        pool.isXincludeAware = false
        pool.isExpandEntityReferences = false

        pool.setBuilderFeatures(
            mapOf(
                FEATURE_DISALLOW_DOCTYPE_DECL to true,
                FEATURE_EXTERNAL_GENERAL_ENTITIES to false,
                FEATURE_EXTERNAL_PARAMETER_ENTITIES to false,
                FEATURE_LOAD_EXTERNAL_DTD to false,
                XMLConstants.FEATURE_SECURE_PROCESSING to true,
            )
        )

        pool.setBuilderAttributes(
            mapOf(
                XMLConstants.ACCESS_EXTERNAL_DTD to EMPTY_STRING,
                XMLConstants.ACCESS_EXTERNAL_SCHEMA to EMPTY_STRING,
            )
        )

        pool.initialize()
        return pool
    }
}
