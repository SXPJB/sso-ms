package com.fsociety.auth.sso.ms.common.response

import java.time.ZonedDateTime

data class GenerateTokenResponse(
    val token: String,
    val tokenType: String,
    val expiresAt: ZonedDateTime
)
