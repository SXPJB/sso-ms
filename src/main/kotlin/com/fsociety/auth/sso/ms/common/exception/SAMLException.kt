package com.fsociety.auth.sso.ms.common.exception

import org.springframework.http.HttpStatus
import org.springframework.http.HttpStatus.BAD_REQUEST

class SAMLException(
    message: String,
    val status: HttpStatus = BAD_REQUEST,
) : RuntimeException(message)
