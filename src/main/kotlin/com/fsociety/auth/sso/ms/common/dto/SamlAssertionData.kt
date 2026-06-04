package com.fsociety.auth.sso.ms.common.dto

import java.time.Instant

data class SamlAssertionData(
    val issuer: String,
    val audience: String?,
    val notBefore: Instant?,
    val notOnOrAfter: Instant?,
    val attributes: Map<String, String>
)
