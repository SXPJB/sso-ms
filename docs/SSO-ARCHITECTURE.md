# smal-ms — SSO Authentication Service

> **Audience:** Engineers, architects, and technical stakeholders who need to understand what this service does and how it fits into the system — no deep cryptography knowledge required.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Context — The Problem It Solves](#2-context--the-problem-it-solves)
3. [How It Works](#3-how-it-works)
   - [Generating a Token](#31-generating-a-token)
   - [Decoding a Token](#32-decoding-a-token)
   - [Decoding a Token as XML](#33-decoding-a-token-as-xml)
4. [Architecture](#4-architecture)
   - [Component Responsibilities](#41-component-responsibilities)
   - [Technology Stack](#42-technology-stack)
5. [Security Design](#5-security-design)
6. [API Reference](#6-api-reference)
7. [Configuration](#7-configuration)
8. [Conclusion](#8-conclusion)

---

## 1. Overview

`smal-ms` is a **Single Sign-On (SSO) microservice** that issues and validates security tokens following the **SAML 2.0** standard. Its sole responsibility is to act as a trusted authority: it can stamp a token that proves who a user is and what they are allowed to access, and it can later decode and verify that a token it previously issued has not been tampered with and has not expired.

Think of it as a **digital notary**: any system in the ecosystem can ask `smal-ms` to create a signed, sealed document certifying a user's identity, and any system can later bring that document back to have it verified.

---

## 2. Context — The Problem It Solves

In a multi-service architecture, users interact with several applications at once. Without a central trust mechanism, each application would need to manage its own authentication, leading to duplicated logic, inconsistent security standards, and a poor user experience.

`smal-ms` solves this by providing a **single source of truth for token issuance and verification**:

- A backend service that needs to assert a user's identity creates a token through `smal-ms`.
- Any downstream service that receives that token can verify its authenticity through `smal-ms` — without needing to know the user's credentials or hold any secret keys.
- The token carries a built-in expiry, so access is time-bounded by design.

This pattern is well-established in enterprise systems and is the foundation of standards like SAML, OIDC, and JOSE.

---

## 3. How It Works

The service exposes three operations: **generate**, **decode**, and **decode/xml**. All are HTTP endpoints that accept JSON (the XML endpoint returns XML).

### 3.1 Generating a Token

A caller provides the following information:

| Field | Description |
|---|---|
| `issuer` | The identity of the system creating the request (e.g., `payments-ms`) |
| `audience` | The intended recipient of the token (e.g., `reporting-ms`) |
| `validitySeconds` | How long the token should be valid, in seconds |
| `attributes` | A free-form map of key-value pairs to embed in the token (e.g., `user_id`, `role`) |

The service then performs the following steps internally:

```
Receive Request
      │
      ▼
Build a structured SAML Assertion
(encodes issuer, audience, expiry window, and all attributes)
      │
      ▼
Sign the Assertion
(a digital signature is applied so any modification would be detectable)
      │
      ▼
Encrypt the Assertion
(the content is sealed so only this service can read it back)
      │
      ▼
Wrap it in a SAML Response envelope
      │
      ▼
Encode as Base64 string
      │
      ▼
Return to caller: { token, tokenType, expiresAt }
```

The returned token is an opaque Base64 string. Callers do not need to parse it — they simply store and forward it.

---

### 3.2 Decoding a Token

A caller presents the Base64 token they received earlier. Two optional headers control validation strictness:

- `X-Ignore-Signature-Validation` — bypass RSA signature check (e.g., for debugging)
- `X-Ignore-Conditions-Validation` — bypass `NotBefore` / `NotOnOrAfter` time checks

```
Receive Token (Base64 string)
      │
      ▼
Decode and parse the SAML Response XML
      │
      ▼
Decrypt the embedded Assertion
      │
      ▼
Verify digital signature?  ──── X-Ignore-Signature-Validation: true ──→ skip
      │
      ▼
Check time conditions?  ──────── X-Ignore-Conditions-Validation: true ──→ skip
(NotBefore / NotOnOrAfter)
      │
      ┌──────────────┐
      │              │
   Valid?         Invalid / Expired
      │              │
      ▼              ▼
Extract data    Return 401 UNAUTHORIZED
and return      (SAMLException with reason)
```

On success, the caller receives back the original data embedded in the token: issuer, audience, custom attributes, and the validity timestamps.

---

### 3.3 Decoding a Token as XML

A caller presents the Base64 token and receives back the raw SAML Response XML. An optional header controls whether the encrypted assertion node is replaced with its decrypted form.

```
Receive Token (Base64 string)
      │
      ▼
Decode and parse the SAML Response XML
      │
      ▼
Include decrypted assertion?  ─── X-Include-Decrypted-Assertion: true ──→ decrypt & replace node
      │
      ▼
Marshal Response object → XML string
      │
      ▼
Return XML to caller  (Content-Type: application/xml)
```

This endpoint is intended for inspection and debugging. No signature or time validation is applied.

---

## 4. Architecture

The service is a Spring Boot microservice with a clean layered architecture. The diagram below summarises the component hierarchy (see `SSO-Architecture.drawio` for the full visual).

```
External Client
      │  HTTP POST (JSON / XML)
      ▼
┌──────────────────────────────────────────────────────┐
│  smal-ms  [Spring Boot Microservice]                 │
│                                                      │
│  SsoController              ← REST layer             │
│        │                                             │
│  SsoService                 ← Orchestration          │
│     ╱      │      ╲                                  │
│ Generate  Decode  DecodeXml ← Operation Delegates    │
│ Delegate  Delegate Delegate                          │
│         ╲   │    ╱                                   │
│      SamlTokenHelper        ← Crypto & encoding      │
│              │                                       │
│      SamlXmlHelper          ← XML construction       │
└──────────────────────────────────────────────────────┘
```

### 4.1 Component Responsibilities

| Component | Layer | Responsibility |
|---|---|---|
| `SsoController` | REST | Exposes the three HTTP endpoints. Validates content types and delegates immediately. |
| `SsoService` | Orchestration | Routes the request to the correct operation delegate. |
| `GenerateSsoTokenDelegate` | Operation | Coordinates token creation and assembles the response DTO with the calculated expiry. |
| `DecodeSsoTokenDelegate` | Operation | Decrypts the token, optionally verifies signature and time conditions, and returns structured assertion data. |
| `DecodeSsoTokenXmlDelegate` | Operation | Decrypts the token and returns the raw SAML Response XML, optionally with the decrypted assertion node inlined. |
| `SamlTokenHelper` | Cryptography | Owns all signing, encryption, decryption, and signature verification. Handles Base64 encoding and decoding. |
| `SamlXmlHelper` | XML | Constructs and parses raw SAML XML objects: assertions, conditions, subjects, and response envelopes. |

### 4.2 Technology Stack

| Technology | Purpose |
|---|---|
| **Kotlin + Spring Boot** | Service runtime and dependency injection |
| **OpenSAML 5** | SAML 2.0 XML object model and marshalling |
| **Java Security (JCE)** | RSA key loading from PKCS8 private key and X.509 certificate |
| **AES-256-GCM** | Symmetric encryption of the assertion content |
| **RSA-OAEP** | Asymmetric key transport to protect the AES session key |
| **RSA-SHA256** | Digital signature algorithm for assertion integrity |

---

## 5. Security Design

The service applies **two independent security layers** to every token it issues:

### Signature (Integrity)
The assertion is **digitally signed** using the service's RSA private key before it is stored inside the token. When the token is later decoded, the signature is checked against the corresponding public certificate. This guarantees:
- The token was genuinely issued by this service.
- Nothing inside the token has been modified after issuance.

### Encryption (Confidentiality)
The assertion content is **encrypted** using AES-256-GCM (a strong symmetric cipher). The symmetric key itself is wrapped using RSA-OAEP, which means only the holder of the private key can decrypt it. This guarantees:
- The attributes and user data embedded in the token cannot be read by third parties who intercept the token.

### Time Conditions
Every token encodes a **validity window** (`NotBefore` and `NotOnOrAfter`). The decode step rejects any token that is:
- Presented before its intended start time.
- Presented after it has expired.

This limits the blast radius of a stolen token to the validity window defined at issuance.

> The private key and certificate are loaded at application startup from configuration properties and are never exposed through any endpoint.

---

## 6. API Reference

All endpoints are under the base path `/v1/sso` and communicate in JSON over HTTPS (except `/decode/xml` which returns XML).

### POST `/v1/sso/generate-token`

Creates a new signed and encrypted SAML token.

**Request:**
```json
{
  "issuer": "payments-ms",
  "audience": "reporting-ms",
  "validitySeconds": 300,
  "attributes": {
    "user_id": "usr-42",
    "role": "ADMIN"
  }
}
```

**Response `200 OK`:**
```json
{
  "token": "PHNhbWxwOlJlc3BvbnNl...",
  "tokenType": "SAML2.0",
  "expiresAt": "2026-06-04T15:30:00Z"
}
```

---

### POST `/v1/sso/decode`

Decrypts a previously issued token and returns its embedded assertion data.

**Request:**
```json
{
  "token": "PHNhbWxwOlJlc3BvbnNl..."
}
```

**Optional headers:**

| Header | Default | Description |
|---|---|---|
| `X-Ignore-Signature-Validation` | `false` | Skip RSA signature verification |
| `X-Ignore-Conditions-Validation` | `false` | Skip `NotBefore` / `NotOnOrAfter` time checks |

**Response `200 OK`:**
```json
{
  "issuer": "payments-ms",
  "audience": "reporting-ms",
  "notBefore": "2026-06-04T15:25:00Z",
  "notOnOrAfter": "2026-06-04T15:30:00Z",
  "attributes": {
    "user_id": "usr-42",
    "role": "ADMIN"
  }
}
```

**Response `401 UNAUTHORIZED`** (expired, tampered, or malformed token):
```json
{
  "timestamp": "2026-06-04T15:31:00.123Z",
  "message": "Assertion has expired (NotOnOrAfter: ...)",
  "status": 401
}
```

---

### POST `/v1/sso/decode/xml`

Decrypts a previously issued token and returns the raw SAML Response XML. Intended for inspection and debugging.

**Request:**
```json
{
  "token": "PHNhbWxwOlJlc3BvbnNl..."
}
```

**Optional headers:**

| Header | Default | Description |
|---|---|---|
| `X-Include-Decrypted-Assertion` | `false` | Replace the encrypted assertion node with the decrypted one in the returned XML |

**Response `200 OK`** — `Content-Type: application/xml`:
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  ...
</samlp:Response>
```

---

## 7. Configuration

The service requires two configuration properties at startup. Both values are Base64-encoded strings injected via environment variables or a secrets manager.

| Property | Format | Description |
|---|---|---|
| `app.saml.rsa.private-key` | Base64-encoded PKCS8 | RSA private key used for signing and decryption |
| `app.saml.rsa.certificate` | Base64-encoded X.509 DER | Public certificate used for encryption and signature verification |

These keys must be generated as an RSA key pair. The private key stays with this service only; the certificate can be shared with any consumer that needs to perform its own out-of-band verification.

---

## 8. Conclusion

`smal-ms` provides a focused, standards-compliant solution for SSO token issuance and verification within a microservice ecosystem. By centralising cryptographic trust into a single service, downstream systems stay simple: they request a token when a user authenticates, pass it along with requests, and verify it at trust boundaries — without ever handling user credentials or managing cryptographic keys.

The combination of RSA signing for integrity and AES-256-GCM encryption for confidentiality means the token is both tamper-evident and opaque, making it safe to transmit across service boundaries even over partially-trusted channels.

The `/decode/xml` endpoint provides an additional inspection surface for debugging and integration testing, with optional assertion decryption controlled by a single request header.

---

*Diagrams: see `SSO-Architecture.drawio` in the `docs/` folder (requires draw.io or a compatible viewer).*
