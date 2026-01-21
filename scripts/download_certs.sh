#!/bin/sh
# Downloads CERN CA certificates for embedding in the binary.
# Run this script to update outdated certificates, then commit the changes.
#
# Certificates:
# - CERN Root Certification Authority 2 (DER format, converted to PEM)
# - CERN Grid Certification Authority
# - CERN Certification Authority

set -e

# Get script directory (POSIX-compatible)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../pkg/auth/certs"

mkdir -p "${CERTS_DIR}"

echo "Downloading CERN CA certificates..."

# CERN Root CA 2 (DER format, needs conversion)
curl -fsSL 'https://cafiles.cern.ch/cafiles/certificates/CERN%20Root%20Certification%20Authority%202.crt' \
  | openssl x509 -inform DER -out "${CERTS_DIR}/cern_root_ca2.pem"
echo "  ✓ CERN Root Certification Authority 2"

# CERN Grid CA (PEM format)
curl -fsSL 'https://cafiles.cern.ch/cafiles/certificates/CERN%20Grid%20Certification%20Authority(1).crt' \
  -o "${CERTS_DIR}/cern_grid_ca.pem"
echo "  ✓ CERN Grid Certification Authority"

# CERN CA (PEM format)
curl -fsSL 'https://cafiles.cern.ch/cafiles/certificates/CERN%20Certification%20Authority.crt' \
  -o "${CERTS_DIR}/cern_ca.pem"
echo "  ✓ CERN Certification Authority"

echo "Done! Certificates saved to ${CERTS_DIR}"
