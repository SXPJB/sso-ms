package com.fsociety.auth.sso.ms.app.controller.handler

import com.fsociety.auth.sso.ms.common.exception.SAMLException
import com.fsociety.auth.sso.ms.common.response.ErrorApi
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.time.Instant

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(SAMLException::class)
    fun handleSAMLException(ex: SAMLException): ResponseEntity<ErrorApi> =
        ResponseEntity
            .status(ex.status)
            .body(
                ErrorApi(
                    timestamp = Instant.now(),
                    message = ex.message ?: "SAML error",
                    status = ex.status.value()
                )
            )

    @ExceptionHandler(Exception::class)
    fun handleGenericException(ex: Exception): ResponseEntity<ErrorApi> =
        ResponseEntity
            .status(500)
            .body(
                ErrorApi(
                    timestamp = Instant.now(),
                    message = ex.message ?: "Internal server error",
                    status = 500
                )
            )
}
