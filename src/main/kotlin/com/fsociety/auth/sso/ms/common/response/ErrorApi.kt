package com.fsociety.auth.sso.ms.common.response

import java.time.Instant

data class ErrorApi(
    val timestamp: Instant,
    val message: String,
    val status: Int
)
