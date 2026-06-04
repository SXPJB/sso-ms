package com.fsociety.auth.sso.ms.common.exception

import org.springframework.http.HttpStatus

class SAMLException(message: String, val status: HttpStatus) : RuntimeException(message)
