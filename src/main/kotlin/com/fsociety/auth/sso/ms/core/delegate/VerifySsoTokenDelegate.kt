package com.fsociety.auth.sso.ms.core.delegate

import com.fsociety.auth.sso.ms.common.exception.SAMLException
import com.fsociety.auth.sso.ms.common.request.VerifyTokenRequest
import com.fsociety.auth.sso.ms.common.response.VerifyTokenResponse
import com.fsociety.auth.sso.ms.core.helper.RsaAssertionHelper
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.time.ZonedDateTime

@Component
class VerifySsoTokenDelegate(
    private val rsaAssertionHelper: RsaAssertionHelper,
    private val clock: Clock
) {
    private val log = LoggerFactory.getLogger(VerifySsoTokenDelegate::class.java)

    fun execute(request: VerifyTokenRequest): VerifyTokenResponse {
        return try {
            val data = rsaAssertionHelper.verifyAndDecode(request.tokenB64)
            VerifyTokenResponse(
                issuer = data.issuer,
                audience = data.audience,
                notBefore = data.notBefore?.toZonedDateTime(),
                notOnOrAfter = data.notOnOrAfter?.toZonedDateTime(),
                attributes = data.attributes
            )
        } catch (ex: Exception) {
            log.warn("Token verification failed: ${ex.message}")
            throw SAMLException(ex.message ?: "Token verification failed", HttpStatus.UNAUTHORIZED)
        }
    }

    private fun Instant.toZonedDateTime(): ZonedDateTime = atZone(clock.zone)
}
