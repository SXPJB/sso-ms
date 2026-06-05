package com.fsociety.auth.sso.ms.core.service

import com.fsociety.auth.sso.ms.common.request.DecodeTokenRequest
import com.fsociety.auth.sso.ms.common.request.GenerateTokenRequest
import com.fsociety.auth.sso.ms.common.response.DecodeTokenResponse
import com.fsociety.auth.sso.ms.common.response.GenerateTokenResponse
import com.fsociety.auth.sso.ms.core.delegate.DecodeSsoTokenDelegate
import com.fsociety.auth.sso.ms.core.delegate.DecodeSsoTokenXmlDelegate
import com.fsociety.auth.sso.ms.core.delegate.GenerateSsoTokenDelegate
import org.springframework.stereotype.Service

@Service
class SsoService(
    private val generateSsoTokenDelegate: GenerateSsoTokenDelegate,
    private val decodeSsoTokenDelegate: DecodeSsoTokenDelegate,
    private val decodeSsoTokenXmlDelegate: DecodeSsoTokenXmlDelegate,
) {
    fun generateToken(request: GenerateTokenRequest): GenerateTokenResponse {
        return generateSsoTokenDelegate.run(request)
    }

    fun decodeToken(
        request: DecodeTokenRequest,
        ignoreSignatureValidation: Boolean,
        ignoreConditionsValidation: Boolean
    ): DecodeTokenResponse {
        return decodeSsoTokenDelegate.run(request, ignoreSignatureValidation, ignoreConditionsValidation)
    }

    fun decodeTokenXml(
        request: DecodeTokenRequest,
        includeDecryptedAssertion: Boolean
    ): String {
        return decodeSsoTokenXmlDelegate.run(request, includeDecryptedAssertion)
    }
}
