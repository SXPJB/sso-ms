package com.fsociety.auth.sso.ms.app.controller

import com.fsociety.auth.sso.ms.common.request.GenerateTokenRequest
import com.fsociety.auth.sso.ms.common.request.VerifyTokenRequest
import com.fsociety.auth.sso.ms.common.response.GenerateTokenResponse
import com.fsociety.auth.sso.ms.common.response.VerifyTokenResponse
import com.fsociety.auth.sso.ms.core.service.SsoService
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/v1/sso", produces = [MediaType.APPLICATION_JSON_VALUE])
class SsoController(
    private val ssoService: SsoService
) {

    @PostMapping("/generate-token", consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun generateToken(@RequestBody request: GenerateTokenRequest): ResponseEntity<GenerateTokenResponse> =
        ResponseEntity.ok(ssoService.generateToken(request))

    @PostMapping("/verify", consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun verifyToken(@RequestBody request: VerifyTokenRequest): ResponseEntity<VerifyTokenResponse> =
        ResponseEntity.ok(ssoService.verifyToken(request))
}
