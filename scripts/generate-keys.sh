#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="$PROJECT_DIR/local.env"
TMP_DIR="$(mktemp -d)"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "Generating RSA-2048 private key..."
openssl genrsa -out "$TMP_DIR/private.pem" 2048 2>/dev/null

echo "Generating self-signed X.509 certificate (1 year)..."
openssl req -new -x509 -key "$TMP_DIR/private.pem" \
  -out "$TMP_DIR/cert.pem" \
  -days 365 \
  -subj "/CN=smal-ms/O=fsociety/C=US" 2>/dev/null

echo "Converting private key to PKCS8 DER..."
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt \
  -in "$TMP_DIR/private.pem" \
  -out "$TMP_DIR/private_pkcs8.der"

echo "Converting certificate to DER..."
openssl x509 -outform DER \
  -in "$TMP_DIR/cert.pem" \
  -out "$TMP_DIR/cert.der"

PRIVATE_KEY=$(base64 -i "$TMP_DIR/private_pkcs8.der" | tr -d '\n')
PUBLIC_CERTIFICATE=$(base64 -i "$TMP_DIR/cert.der" | tr -d '\n')

cat > "$OUTPUT_FILE" <<EOF
PRIVATE_KEY=${PRIVATE_KEY}
PUBLIC_CERTIFICATE=${PUBLIC_CERTIFICATE}
EOF

echo "Done. Keys written to: $OUTPUT_FILE"
