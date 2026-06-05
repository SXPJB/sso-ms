package com.fsociety.auth.sso.ms.core.delegate

import com.fsociety.auth.sso.ms.common.request.DecodeTokenRequest
import com.fsociety.auth.sso.ms.core.helper.SamlTokenHelper
import com.fsociety.auth.sso.ms.core.helper.SamlXmlHelper
import org.opensaml.saml.saml2.core.Response
import org.springframework.stereotype.Component

@Component
class DecodeSsoTokenXmlDelegate(
    private val samlTokenHelper: SamlTokenHelper,
    private val xmlHelper: SamlXmlHelper
) {
    fun run(
        request: DecodeTokenRequest,
        includeDecryptedAssertion: Boolean
    ): String {
        val token = decryptToken(request.token, includeDecryptedAssertion)
        return getXmlToken(token)
    }

    private fun decryptToken(tokenB64: String, includeDecryptedAssertion: Boolean): Response {
        return samlTokenHelper.extractResponse(tokenB64, includeDecryptedAssertion)
    }

    private fun getXmlToken(response: Response): String {
        return xmlHelper.parseToXml(response)
    }

}