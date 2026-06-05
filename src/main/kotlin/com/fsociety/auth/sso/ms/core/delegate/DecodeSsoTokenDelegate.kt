package com.fsociety.auth.sso.ms.core.delegate

import com.fsociety.auth.sso.ms.common.dto.SamlAssertionData
import com.fsociety.auth.sso.ms.common.request.DecodeTokenRequest
import com.fsociety.auth.sso.ms.common.response.DecodeTokenResponse
import com.fsociety.auth.sso.ms.core.helper.SamlTokenHelper
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.Conditions
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime

@Component
class DecodeSsoTokenDelegate(
    private val samlTokenHelper: SamlTokenHelper,
    private val clock: Clock
) {

    fun run(
        request: DecodeTokenRequest,
        ignoreSignatureValidation: Boolean,
        ignoreConditionsValidation: Boolean
    ): DecodeTokenResponse {
        val token = decryptToken(request.token)
        verifySignature(token, ignoreSignatureValidation)
        verifyConditions(token.conditions, ignoreConditionsValidation)
        val assertionData = extractAssertionData(token)
        return assertionData.toResponse()
    }

    private fun decryptToken(tokenB64: String): Assertion {
        return samlTokenHelper.extractDecryptedAssertion(tokenB64)
    }

    private fun verifySignature(token: Assertion, ignoreSignatureValidation: Boolean) {
        if (!ignoreSignatureValidation) {
            samlTokenHelper.verifySignature(token)
        }
    }

    private fun verifyConditions(conditions: Conditions?, ignoreConditionsValidation: Boolean) {
        if (!ignoreConditionsValidation) {
            samlTokenHelper.validateConditions(conditions)
        }
    }

    private fun extractAssertionData(token: Assertion): SamlAssertionData {
        return samlTokenHelper.extractAssertionData(token)
    }

    private fun SamlAssertionData.toResponse(): DecodeTokenResponse {
        return DecodeTokenResponse(
            issuer = issuer,
            audience = audience,
            notBefore = notBefore?.toZonedDateTime(),
            notOnOrAfter = notOnOrAfter?.toZonedDateTime(),
            attributes = attributes
        )
    }


    private fun Instant.toZonedDateTime(): ZonedDateTime = atZone(clock.zone)
}
