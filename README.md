# SSO-AUTH-MS

Microservice for generating and verifying signed and encrypted SAML 2.0 tokens. Exposes a REST API for issuing dynamic assertions and decoding them, powered by OpenSAML 5 as the cryptographic engine.

> For architecture diagrams and a full design walkthrough see [`docs/SSO-ARCHITECTURE.md`](docs/SSO-ARCHITECTURE.md).


## Stack

| Layer | Technology |
|---|---|
| Runtime | Java 17 |
| Framework | Spring Boot 4 + Spring Web MVC |
| Language | Kotlin 2 |
| SAML | OpenSAML 5.2 |
| Serialization | Jackson (Kotlin module) |
| Build | Gradle (Kotlin DSL) |

---

## Project structure

```
src/main/kotlin/com/fsociety/auth/sso/ms/
├── app/
│   └── controller/
│       ├── handler/
│       │   └── GlobalExceptionHandler.kt # Maps SAMLException → ErrorApi
│       └── SsoController.kt              # REST endpoints /v1/sso
├── common/
│   ├── dto/
│   │   └── SamlAssertionData.kt          # Internal DTO with extracted assertion data
│   ├── exception/
│   │   └── SAMLException.kt              # Domain exception carrying HttpStatus
│   ├── request/
│   │   ├── GenerateTokenRequest.kt
│   │   └── DecodeTokenRequest.kt
│   └── response/
│       ├── ErrorApi.kt
│       ├── GenerateTokenResponse.kt
│       └── DecodeTokenResponse.kt
├── core/
│   ├── config/
│   │   ├── CoreConfig.kt                 # Clock bean (America/Mexico_City)
│   │   ├── OpenSamlBootstrapper.kt       # Initializes OpenSAML on startup
│   │   └── SamlConfig.kt                 # OpenSAML ParserPool bean
│   ├── delegate/
│   │   ├── GenerateSsoTokenDelegate.kt
│   │   ├── DecodeSsoTokenDelegate.kt
│   │   └── DecodeSsoTokenXmlDelegate.kt
│   ├── helper/
│   │   ├── SamlTokenHelper.kt            # RSA signing, encryption and decryption
│   │   └── SamlXmlHelper.kt              # SAML XML construction and parsing
│   └── service/
│       └── SsoService.kt
└── Application.kt                        # Main Application entry point
```

---

## Configuration

The application reads cryptographic keys from environment variables. Use the included script to generate them.

### Generate keys

```bash
bash scripts/generate-keys.sh
```

This creates `local.env` at the project root with:

```env
PRIVATE_KEY=<PKCS8 DER Base64-encoded>
PUBLIC_CERTIFICATE=<X.509 DER Base64-encoded>
```

### Required environment variables

| Variable | Description |
|---|---|
| `PRIVATE_KEY` | RSA-2048 private key in PKCS8 DER format, Base64-encoded |
| `PUBLIC_CERTIFICATE` | Self-signed X.509 certificate in DER format, Base64-encoded |

### application.yaml

```yaml
server:
  port: 8081

spring:
  application:
    name: saml-ms
  jackson:
    property-naming-strategy: SNAKE_CASE

app:
  saml:
    rsa:
      private-key: ${PRIVATE_KEY}
      certificate: ${PUBLIC_CERTIFICATE}
    token:
      validity-seconds: 300
```

> `validity-seconds` is the application-level default, but each request can specify its own value.

---

## Running the service

```bash
source local.env && export PRIVATE_KEY PUBLIC_CERTIFICATE
./gradlew bootRun
```

The service will be available at `http://localhost:8081`.

---

## API

### POST `/v1/sso/generate-token`

Generates a signed (RSA-SHA256) and encrypted (AES-256-GCM) SAML 2.0 token.

**Request**
```json
{
  "issuer": "https://auth.fsociety.com/sso",
  "audience": "https://app.fsociety.com",
  "validity_seconds": 300,
  "attributes": {
    "user_id": "usr-001",
    "external_id": "99",
    "role": "admin"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `issuer` | `String` | Entity issuing the token |
| `audience` | `String` | Restricted audience for the token |
| `validity_seconds` | `Long` | Token validity duration in seconds |
| `attributes` | `Map<String, String>` | Dynamic attributes embedded in the assertion |

**Response `200`**
```json
{
  "token": "<Base64 SAML Response XML>",
  "token_type": "SAML2.0",
  "expires_at": "2026-06-03T20:18:00.266-06:00"
}
```

---

### POST `/v1/sso/decode`

Decrypts and decodes a SAML token. Returns the assertion data if valid.

**Request**
```json
{
  "token": "<Base64 SAML Response XML>"
}
```

**Optional headers**

| Header | Type | Description |
|---|---|---|
| `X-Ignore-Signature-Validation` | `Boolean` | Skip RSA signature verification (default: `false`) |
| `X-Ignore-Conditions-Validation` | `Boolean` | Skip `NotBefore` / `NotOnOrAfter` time checks (default: `false`) |

**Response `200`**
```json
{
  "issuer": "https://auth.fsociety.com/sso",
  "audience": "https://app.fsociety.com",
  "not_before": "2026-06-03T20:13:00.000-06:00",
  "not_on_or_after": "2026-06-03T20:18:00.000-06:00",
  "attributes": {
    "user_id": "usr-001",
    "external_id": "99",
    "role": "admin"
  }
}
```

**Response `401`** — invalid, expired or tampered token
```json
{
  "timestamp": "2026-06-03T20:19:00.123-06:00",
  "message": "Assertion has expired (NotOnOrAfter: ...)",
  "status": 401
}
```

---

### POST `/v1/sso/decode/xml`

Decrypts a SAML token and returns the raw SAML Response XML.

**Request**
```json
{
  "token": "<Base64 SAML Response XML>"
}
```

**Optional headers**

| Header | Type | Description |
|---|---|---|
| `X-Include-Decrypted-Assertion` | `Boolean` | Replace the encrypted assertion with the decrypted one in the returned XML (default: `false`) |

**Response `200`** — `Content-Type: application/xml`
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  ...
</samlp:Response>
```

---

## Cryptographic flow

```
Generate:
  Attributes → SAML Assertion
           → RSA-SHA256 signature
           → AES-256-GCM encryption (session key wrapped with RSA-OAEP)
           → SAML Response XML
           → Base64

Decode:
  Base64 → SAML Response XML
         → AES-256-GCM decryption
         → RSA-SHA256 signature validation
         → Time condition validation (NotBefore / NotOnOrAfter)
         → Attribute extraction
```

---

## Timezone

All timestamps (`expires_at`, `not_before`, `not_on_or_after`) are expressed in Mexico City time (`America/Mexico_City`). The `Clock` is an injectable Spring bean, making it straightforward to replace in tests.
