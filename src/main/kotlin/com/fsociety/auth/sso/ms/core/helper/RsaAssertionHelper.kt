package com.fsociety.auth.sso.ms.core.helper

import com.fsociety.auth.sso.ms.common.dto.SamlAssertionData
import net.shibboleth.shared.xml.SerializeSupport
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.EncryptedAssertion
import org.opensaml.saml.saml2.encryption.Decrypter
import org.opensaml.saml.saml2.encryption.Encrypter
import org.opensaml.security.credential.BasicCredential
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters
import org.opensaml.xmlsec.encryption.support.EncryptionConstants
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver
import org.opensaml.xmlsec.signature.Signature
import org.opensaml.xmlsec.signature.support.SignatureConstants
import org.opensaml.xmlsec.signature.support.SignatureValidator
import org.opensaml.xmlsec.signature.support.Signer
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * Helper class responsible for signing, encrypting, decrypting, and verifying SAML Assertions and Responses.
 * It uses RSA keys (Private Key for signing and public Certificate for encryption/verification)
 * to secure the tokens before encoding them into Base64 format.
 */
@Component
class RsaAssertionHelper(
    @Value("\${app.saml.rsa.private-key}")
    privateKeyB64: String,
    @Value("\${app.saml.rsa.certificate}")
    certificateB64: String,
    private val samlXmlHelper: SamlXmlHelper
) {
    private val privateKey: RSAPrivateKey = KeyFactory.getInstance("RSA")
        .generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64))) as RSAPrivateKey

    private val publicKey: RSAPublicKey = (
            CertificateFactory.getInstance("X.509")
                .generateCertificate(Base64.getDecoder().decode(certificateB64).inputStream()) as X509Certificate
            ).publicKey as RSAPublicKey

    /**
     * Builds, signs, encrypts, and wraps a SAML assertion into a signed Response,
     * returning the final payload encoded in Base64.
     *
     * @param issuer The entity issuing the token.
     * @param audience The intended recipient or audience for the token.
     * @param validitySeconds The duration in seconds that the token remains valid.
     * @param attributes Key-value pairs of attributes to be embedded into the assertion.
     * @return Base64-encoded string representing the SAML Response XML.
     */
    fun buildToken(issuer: String, audience: String, validitySeconds: Long, attributes: Map<String, String>): String {
        val assertion = samlXmlHelper.buildAssertionObject(issuer, audience, validitySeconds, attributes)

        signAssertion(assertion)
        val encryptedAssertion = encryptAssertion(assertion)
        val response = samlXmlHelper.wrapInResponse(issuer, encryptedAssertion)
        val responseXml = serializeResponse(response)

        return Base64.getEncoder().encodeToString(responseXml.toByteArray(Charsets.UTF_8))
    }

    /**
     * Decodes a Base64 SAML token, extracts and decrypts the assertion,
     * validates its cryptographic signature, and extracts the payload.
     *
     * @param token Base64-encoded SAML Response XML string.
     * @return Decoded assertion data including issuer, audience, and custom attributes.
     */
    fun verifyAndDecode(token: String): SamlAssertionData {
        val responseXml = String(Base64.getDecoder().decode(token), Charsets.UTF_8)
        val response = samlXmlHelper.parseResponse(responseXml)

        val encryptedAssertion = response.encryptedAssertions.firstOrNull()
            ?: error("Response contains no EncryptedAssertion")

        val assertion = decryptAssertion(encryptedAssertion)
        verifySignature(assertion)

        return samlXmlHelper.extractAssertionData(assertion)
    }

    /**
     * Attaches an RSA signature block to the assertion and signs it.
     */
    private fun signAssertion(assertion: Assertion) {
        assertion.signature = buildSignature()
        val assertionMarshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
            .getMarshaller(assertion) ?: error("No marshaller for Assertion")
        assertionMarshaller.marshall(assertion)
        Signer.signObject(assertion.signature ?: error("Assertion has no signature"))
    }

    /**
     * Serializes the completed SAML Response object into its raw XML string format.
     */
    private fun serializeResponse(response: org.opensaml.saml.saml2.core.Response): String {
        val responseMarshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
            .getMarshaller(response) ?: error("No marshaller for Response")
        return SerializeSupport.nodeToString(responseMarshaller.marshall(response))
    }

    /**
     * Constructs the XML signature configuration structure containing cryptographic metadata and credentials.
     */
    private fun buildSignature(): Signature {
        val bf = XMLObjectProviderRegistrySupport.getBuilderFactory()
        return bf.ensureBuilder<Signature>(Signature.DEFAULT_ELEMENT_NAME)
            .buildObject(Signature.DEFAULT_ELEMENT_NAME).apply {
                signingCredential = BasicCredential(publicKey, privateKey)
                signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256
                canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
            }
    }

    /**
     * Marshals the assertion to XML structure and validates its signature block against the trusted public key.
     */
    private fun verifySignature(assertion: Assertion) {
        val assertionMarshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
            .getMarshaller(assertion) ?: error("No marshaller for Assertion")
        assertionMarshaller.marshall(assertion)

        val sig = assertion.signature ?: error("Assertion has no signature")
        SignatureValidator.validate(sig, BasicCredential(publicKey))
    }

    /**
     * Encrypts the raw SAML Assertion using AES-256 GCM symmetric encryption,
     * wrapping the key with RSA-OAEP key transport.
     */
    private fun encryptAssertion(assertion: Assertion): EncryptedAssertion {
        val dataEncParams = DataEncryptionParameters().apply {
            algorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM
        }
        val keyEncParams = KeyEncryptionParameters().apply {
            encryptionCredential = BasicCredential(publicKey)
            algorithm = EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP
        }
        val encrypter = Encrypter(dataEncParams, listOf(keyEncParams))
        encrypter.keyPlacement = Encrypter.KeyPlacement.INLINE
        return encrypter.encrypt(assertion)
    }

    /**
     * Decrypts an encrypted SAML assertion using the RSA Private Key.
     */
    private fun decryptAssertion(encryptedAssertion: EncryptedAssertion): Assertion {
        val credential = BasicCredential(publicKey, privateKey)
        val kekResolver = StaticKeyInfoCredentialResolver(listOf(credential))
        val decrypter = Decrypter(null, kekResolver, InlineEncryptedKeyResolver())
        return decrypter.decrypt(encryptedAssertion)
    }
}