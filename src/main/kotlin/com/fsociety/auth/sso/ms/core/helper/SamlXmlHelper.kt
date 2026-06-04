package com.fsociety.auth.sso.ms.core.helper

import com.fsociety.auth.sso.ms.common.dto.SamlAssertionData
import net.shibboleth.shared.xml.ParserPool
import org.opensaml.core.xml.XMLObjectBuilderFactory
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.core.xml.schema.XSString
import org.opensaml.core.xml.schema.impl.XSStringBuilder
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.Attribute
import org.opensaml.saml.saml2.core.AttributeStatement
import org.opensaml.saml.saml2.core.AttributeValue
import org.opensaml.saml.saml2.core.Audience
import org.opensaml.saml.saml2.core.AudienceRestriction
import org.opensaml.saml.saml2.core.Conditions
import org.opensaml.saml.saml2.core.EncryptedAssertion
import org.opensaml.saml.saml2.core.Issuer
import org.opensaml.saml.saml2.core.NameID
import org.opensaml.saml.saml2.core.Response
import org.opensaml.saml.saml2.core.Status
import org.opensaml.saml.saml2.core.StatusCode
import org.opensaml.saml.saml2.core.Subject
import org.opensaml.saml.saml2.core.SubjectConfirmation
import org.opensaml.saml.saml2.core.SubjectConfirmationData
import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * Helper class responsible for constructing, wrapping, parsing, and extracting data from
 * raw SAML XML objects (such as assertions, subjects, conditions, and responses).
 */
@Component
class SamlXmlHelper(
    private val parserPool: ParserPool,
    private val clock: Clock
) {

    /**
     * Builds a structured SAML [Assertion] with specified parameters, subject credentials, conditions, and attributes.
     *
     * @param issuer The entity issuing the assertion.
     * @param audience The restricted audience URI for the token.
     * @param validitySeconds The duration in seconds that the assertion remains valid.
     * @param attributes Map of attributes to include in the assertion.
     * @return Constructed and unmarshalled [Assertion] object.
     */
    fun buildAssertionObject(
        issuer: String,
        audience: String,
        validitySeconds: Long,
        attributes: Map<String, String>
    ): Assertion {
        val bf = XMLObjectProviderRegistrySupport.getBuilderFactory()
        val now = Instant.now(clock)
        val notOnOrAfter = now.plusSeconds(validitySeconds)

        val issuerObj = buildIssuer(bf, issuer)
        val subjectObj = buildSubject(bf, attributes, notOnOrAfter)
        val conditionsObj = buildConditions(bf, audience, now, notOnOrAfter)
        val attributeStatementObj = buildAttributeStatement(bf, attributes)

        return bf.ensureBuilder<Assertion>(Assertion.DEFAULT_ELEMENT_NAME)
            .buildObject(Assertion.DEFAULT_ELEMENT_NAME).apply {
                id = "_${UUID.randomUUID().toString().replace("-", "")}"
                version = SAMLVersion.VERSION_20
                this.issuer = issuerObj
                this.subject = subjectObj
                this.conditions = conditionsObj
                attributeStatements.add(attributeStatementObj)
                issueInstant = now
            }
    }

    /**
     * Wraps an [EncryptedAssertion] inside a new standard SAML [Response] container.
     *
     * @param issuer The entity issuing the response container.
     * @param encryptedAssertion The pre-encrypted SAML assertion to wrap inside.
     * @return Prepared [Response] XML object structure.
     */
    fun wrapInResponse(issuer: String, encryptedAssertion: EncryptedAssertion): Response {
        val bf = XMLObjectProviderRegistrySupport.getBuilderFactory()
        val now = Instant.now(clock)

        val issuerObj = buildIssuer(bf, issuer)
        val statusObj = buildSuccessStatus(bf)

        return bf.ensureBuilder<Response>(Response.DEFAULT_ELEMENT_NAME)
            .buildObject(Response.DEFAULT_ELEMENT_NAME).apply {
                id = "_${UUID.randomUUID()}"
                issueInstant = now
                version = SAMLVersion.VERSION_20
                this.issuer = issuerObj
                this.status = statusObj
                encryptedAssertions.add(encryptedAssertion)
            }
    }

    /**
     * Parses a raw SAML Response XML string into an OpenSAML [Response] object representation.
     *
     * @param xml Raw XML content string.
     * @return Unmarshalled [Response] object.
     * @throws IllegalArgumentException If unmarshalling fails or if the root element is invalid.
     */
    fun parseResponse(xml: String): Response {
        val document = parserPool.parse(xml.byteInputStream(Charsets.UTF_8))
        val element = document.documentElement

        val unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
            .getUnmarshaller(element)
            ?: throw IllegalArgumentException("No unmarshaller for: ${element.localName}")

        return unmarshaller.unmarshall(element) as? Response
            ?: throw IllegalArgumentException("Root element is not a SAML Response")
    }

    /**
     * Validates assertion conditions (timing restrictions) and extracts key SAML fields into a simple data transfer object.
     *
     * @param assertion Target [Assertion] to extract data from.
     * @return [SamlAssertionData] structured payload.
     * @throws IllegalArgumentException If validation fails or critical fields are missing.
     */
    fun extractAssertionData(assertion: Assertion): SamlAssertionData {
        validateConditions(assertion.conditions)

        val issuer = assertion.issuer?.value
            ?: throw IllegalArgumentException("Missing issuer in assertion")

        val audience = assertion.conditions
            ?.audienceRestrictions
            ?.firstOrNull()
            ?.audiences
            ?.firstOrNull()
            ?.uri

        val attributes = assertion.attributeStatements
            .flatMap { it.attributes }
            .mapNotNull { attr ->
                attr.name?.let { name ->
                    name to ((attr.attributeValues.firstOrNull() as? XSString)?.value ?: "")
                }
            }
            .toMap()

        return SamlAssertionData(
            issuer = issuer,
            audience = audience,
            notBefore = assertion.conditions?.notBefore,
            notOnOrAfter = assertion.conditions?.notOnOrAfter,
            attributes = attributes
        )
    }

    private fun buildIssuer(bf: XMLObjectBuilderFactory, value: String): Issuer =
        bf.ensureBuilder<Issuer>(Issuer.DEFAULT_ELEMENT_NAME)
            .buildObject(Issuer.DEFAULT_ELEMENT_NAME).apply { this.value = value }

    private fun buildSuccessStatus(bf: XMLObjectBuilderFactory): Status {
        val statusCode = bf.ensureBuilder<StatusCode>(StatusCode.DEFAULT_ELEMENT_NAME)
            .buildObject(StatusCode.DEFAULT_ELEMENT_NAME).apply { value = StatusCode.SUCCESS }

        return bf.ensureBuilder<Status>(Status.DEFAULT_ELEMENT_NAME)
            .buildObject(Status.DEFAULT_ELEMENT_NAME).apply { this.statusCode = statusCode }
    }

    private fun buildSubject(
        bf: XMLObjectBuilderFactory,
        attributes: Map<String, String>,
        notOnOrAfter: Instant
    ): Subject {
        val subjectValue = attributes["subject"] ?: attributes["user_id"] ?: "_anon"
        val nameId = bf.ensureBuilder<NameID>(NameID.DEFAULT_ELEMENT_NAME)
            .buildObject(NameID.DEFAULT_ELEMENT_NAME).apply {
                value = subjectValue
                format = NameID.UNSPECIFIED
            }

        val subjectConfirmationData =
            bf.ensureBuilder<SubjectConfirmationData>(SubjectConfirmationData.DEFAULT_ELEMENT_NAME)
                .buildObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME).apply {
                    this.notOnOrAfter = notOnOrAfter
                }

        val subjectConfirmation =
            bf.ensureBuilder<SubjectConfirmation>(SubjectConfirmation.DEFAULT_ELEMENT_NAME)
                .buildObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME).apply {
                    method = SubjectConfirmation.METHOD_BEARER
                    this.subjectConfirmationData = subjectConfirmationData
                }

        return bf.ensureBuilder<Subject>(Subject.DEFAULT_ELEMENT_NAME)
            .buildObject(Subject.DEFAULT_ELEMENT_NAME).apply {
                this.nameID = nameId
                subjectConfirmations.add(subjectConfirmation)
            }
    }

    private fun buildConditions(
        bf: XMLObjectBuilderFactory,
        audience: String,
        now: Instant,
        notOnOrAfter: Instant
    ): Conditions {
        val audienceObj = bf.ensureBuilder<Audience>(Audience.DEFAULT_ELEMENT_NAME)
            .buildObject(Audience.DEFAULT_ELEMENT_NAME).apply { uri = audience }

        val audienceRestriction =
            bf.ensureBuilder<AudienceRestriction>(AudienceRestriction.DEFAULT_ELEMENT_NAME)
                .buildObject(AudienceRestriction.DEFAULT_ELEMENT_NAME).apply {
                    audiences.add(audienceObj)
                }

        return bf.ensureBuilder<Conditions>(Conditions.DEFAULT_ELEMENT_NAME)
            .buildObject(Conditions.DEFAULT_ELEMENT_NAME).apply {
                notBefore = now
                this.notOnOrAfter = notOnOrAfter
                audienceRestrictions.add(audienceRestriction)
            }
    }

    private fun buildAttributeStatement(
        bf: XMLObjectBuilderFactory,
        attributes: Map<String, String>
    ): AttributeStatement =
        bf.ensureBuilder<AttributeStatement>(AttributeStatement.DEFAULT_ELEMENT_NAME)
            .buildObject(AttributeStatement.DEFAULT_ELEMENT_NAME).apply {
                attributes.forEach { (name, value) ->
                    this.attributes.add(buildStringAttribute(name, value))
                }
            }

    private fun buildStringAttribute(name: String, value: String): Attribute {
        val bf = XMLObjectProviderRegistrySupport.getBuilderFactory()
        val attrValue = (bf.ensureBuilder<XSString>(XSString.TYPE_NAME) as XSStringBuilder)
            .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME)
        attrValue.value = value

        return bf.ensureBuilder<Attribute>(Attribute.DEFAULT_ELEMENT_NAME)
            .buildObject(Attribute.DEFAULT_ELEMENT_NAME).apply {
                this.name = name
                attributeValues.add(attrValue)
            }
    }

    private fun validateConditions(conditions: Conditions?) {
        val now = Instant.now(clock)
        conditions?.notBefore?.let {
            if (now.isBefore(it)) throw IllegalArgumentException("Assertion not yet valid (NotBefore: $it)")
        }
        conditions?.notOnOrAfter?.let {
            if (!now.isBefore(it)) throw IllegalArgumentException("Assertion has expired (NotOnOrAfter: $it)")
        }
    }
}