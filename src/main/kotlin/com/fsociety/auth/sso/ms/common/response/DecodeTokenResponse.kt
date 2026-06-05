package com.fsociety.auth.sso.ms.common.response

import java.time.ZonedDateTime

data class DecodeTokenResponse(
    val issuer: String,
    val audience: String?,
    val notBefore: ZonedDateTime?,
    val notOnOrAfter: ZonedDateTime?,
    val attributes: Map<String, String>
)
