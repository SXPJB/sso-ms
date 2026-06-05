package com.fsociety.auth.sso.ms.app.controller

import com.fsociety.auth.sso.ms.common.request.GenerateTokenRequest
import com.fsociety.auth.sso.ms.common.request.DecodeTokenRequest
import com.fsociety.auth.sso.ms.common.response.DecodeTokenResponse
import com.fsociety.auth.sso.ms.common.response.GenerateTokenResponse
import com.fsociety.auth.sso.ms.core.service.SsoService
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/v1/sso", produces = [MediaType.APPLICATION_JSON_VALUE])
class SsoController(
    private val ssoService: SsoService
) {

    @PostMapping(
        "/generate-token",
        consumes = [MediaType.APPLICATION_JSON_VALUE]
    )
    fun generateToken(
        @RequestBody request: GenerateTokenRequest
    ): ResponseEntity<GenerateTokenResponse> {
        return ResponseEntity.ok(ssoService.generateToken(request))
    }

    @PostMapping(
        "/decode",
        consumes = [MediaType.APPLICATION_JSON_VALUE]
    )
    fun decodeToken(
        @RequestBody
        request: DecodeTokenRequest,
        @RequestHeader("X-Ignore-Signature-Validation", required = false)
        ignoreSignatureValidation: Boolean,
        @RequestHeader("X-Ignore-Conditions-Validation", required = false)
        ignoreConditionsValidation: Boolean
    ): ResponseEntity<DecodeTokenResponse> {
        return ResponseEntity.ok(ssoService.decodeToken(request, ignoreSignatureValidation, ignoreConditionsValidation))
    }

    @PostMapping(
        "/decode/xml",
        consumes = [MediaType.APPLICATION_JSON_VALUE],
        produces = [MediaType.APPLICATION_XML_VALUE]
    )
    fun decodeTokenXml(
        @RequestBody
        request: DecodeTokenRequest,
        @RequestHeader("X-Include-Decrypted-Assertion", required = false)
        includeDecryptedAssertion: Boolean = false
    ): ResponseEntity<String> {
        return ResponseEntity.ok(ssoService.decodeTokenXml(request, includeDecryptedAssertion))
    }
}
