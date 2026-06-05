package com.fsociety.auth.sso.ms.core.delegate

import com.fsociety.auth.sso.ms.common.request.GenerateTokenRequest
import com.fsociety.auth.sso.ms.common.response.GenerateTokenResponse
import com.fsociety.auth.sso.ms.core.helper.SamlTokenHelper
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.ZonedDateTime

private const val TOKEN_TYPE = "SAML2.0"

@Component
class GenerateSsoTokenDelegate(
    private val samlTokenHelper: SamlTokenHelper,
    private val clock: Clock
) {
    fun run(request: GenerateTokenRequest): GenerateTokenResponse {
        val token = samlTokenHelper.buildToken(
            issuer = request.issuer,
            audience = request.audience,
            validitySeconds = request.validitySeconds,
            attributes = request.attributes
        )
        return GenerateTokenResponse(
            token = token,
            tokenType = TOKEN_TYPE,
            expiresAt = ZonedDateTime.now(clock).plusSeconds(request.validitySeconds)
        )
    }
}