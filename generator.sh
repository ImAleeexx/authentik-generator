#!/bin/bash
set -euo pipefail

# Directory structure
CA_DIR="demoCA"
mkdir -p "$CA_DIR/newcerts"
echo 1000 > "$CA_DIR/serial" 2>/dev/null || true
touch "$CA_DIR/index.txt"

# Generate new EC private key (secp384r1)
openssl ecparam -name secp384r1 -genkey -noout -out rootCA.key
chmod 600 rootCA.key

# Create self-signed root certificate (100 years validity, SHA-384)
openssl req -x509 -new -nodes -key rootCA.key \
  -config root-openssl.cnf \
  -extensions v3_ca \
  -days 36500 -sha384 \
  -out rootCA.crt

echo "Generated:"
echo "  - rootCA.key (private key)"
echo "  - rootCA.crt (root certificate)"
openssl x509 -in rootCA.crt -noout -text | head -n 20

