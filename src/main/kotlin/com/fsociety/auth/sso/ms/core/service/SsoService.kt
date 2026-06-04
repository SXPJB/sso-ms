package com.fsociety.auth.sso.ms.core.service

import com.fsociety.auth.sso.ms.common.request.GenerateTokenRequest
import com.fsociety.auth.sso.ms.common.request.VerifyTokenRequest
import com.fsociety.auth.sso.ms.common.response.GenerateTokenResponse
import com.fsociety.auth.sso.ms.common.response.VerifyTokenResponse
import com.fsociety.auth.sso.ms.core.delegate.GenerateSsoTokenDelegate
import com.fsociety.auth.sso.ms.core.delegate.VerifySsoTokenDelegate
import org.springframework.stereotype.Service

@Service
class SsoService(
    private val generateSsoTokenDelegate: GenerateSsoTokenDelegate,
    private val verifySsoTokenDelegate: VerifySsoTokenDelegate
) {
    fun generateToken(request: GenerateTokenRequest): GenerateTokenResponse =
        generateSsoTokenDelegate.execute(request)

    fun verifyToken(request: VerifyTokenRequest): VerifyTokenResponse =
        verifySsoTokenDelegate.execute(request)
}
