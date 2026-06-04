package com.fsociety.auth.sso.ms.common.request

data class GenerateTokenRequest(
    val issuer: String,
    val audience: String,
    val validitySeconds: Long,
    val attributes: Map<String, String>
)
