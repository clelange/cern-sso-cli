#!/bin/sh
# Checks if local CERN CA certificates match == ones on CERN CA website.
# Returns exit code 0 if all match, 1 if any differ, 2 on error.

set -e

# Get script directory (POSIX-compatible)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../pkg/auth/certs"

# Use color codes if supported
if [ -t 1 ] && [ -n "${TERM:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Track if any certificates differ
HAS_DIFF=0
HAS_ERROR=0

echo "Checking CERN CA certificates against CERN CA website..."

# Function to compare certificates
# Args: $1=name, $2=local_file, $3=remote_url, $4=remote_openssl_args (for reading remote format)
compare_cert() {
    name="$1"
    local_file="$2"
    remote_url="$3"
    remote_openssl_args="$4"

    if [ ! -f "$local_file" ]; then
        printf "  ${RED}✗${NC} %s\n" "$name"
        echo "    Local file not found: $local_file"
        HAS_DIFF=1
        return
    fi

    # Get local fingerprint (always PEM since download_certs.sh converts to PEM)
    local_fp=$(openssl x509 -in "$local_file" -noout -fingerprint -sha256 2>/dev/null || echo "ERROR")

    if [ "$local_fp" = "ERROR" ]; then
        printf "  ${RED}✗${NC} %s\n" "$name"
        echo "    Failed to read local certificate: $local_file"
        HAS_ERROR=1
        return
    fi

    # Get remote fingerprint (remote may be DER or PEM)
    remote_fp=$(curl -fsSL "$remote_url" | openssl x509 $remote_openssl_args -noout -fingerprint -sha256 2>/dev/null || echo "ERROR")

    if [ "$remote_fp" = "ERROR" ]; then
        printf "  ${RED}✗${NC} %s\n" "$name"
        echo "    Failed to download remote certificate: $remote_url"
        HAS_ERROR=1
        return
    fi

    # Compare fingerprints (extract just the hash part after "Fingerprint=")
    local_hash=$(echo "$local_fp" | sed 's/sha256 Fingerprint=//;s/://g')
    remote_hash=$(echo "$remote_fp" | sed 's/sha256 Fingerprint=//;s/://g')

    if [ "$local_hash" = "$remote_hash" ]; then
        printf "  ${GREEN}✓${NC} %s\n" "$name"

        # Print validity info (informational only, local is always PEM)
        local_dates=$(openssl x509 -in "$local_file" -noout -dates 2>/dev/null || echo "")
        if [ -n "$local_dates" ]; then
            echo "    $local_dates"
        fi
    else
        printf "  ${YELLOW}✗${NC} %s\n" "$name"
        echo "    Local:  $local_hash"
        echo "    Remote: $remote_hash"
        HAS_DIFF=1
    fi
}

# CERN Root CA 2 (remote is DER format, converted to PEM locally)
compare_cert \
    "CERN Root Certification Authority 2" \
    "${CERTS_DIR}/cern_root_ca2.pem" \
    'https://cafiles.cern.ch/cafiles/certificates/CERN%20Root%20Certification%20Authority%202.crt' \
    "-inform DER"

# CERN Grid CA (PEM format)
compare_cert \
    "CERN Grid Certification Authority" \
    "${CERTS_DIR}/cern_grid_ca.pem" \
    'https://cafiles.cern.ch/cafiles/certificates/CERN%20Grid%20Certification%20Authority(1).crt'

# CERN CA (PEM format)
compare_cert \
    "CERN Certification Authority" \
    "${CERTS_DIR}/cern_ca.pem" \
    'https://cafiles.cern.ch/cafiles/certificates/CERN%20Certification%20Authority.crt'

# Summary
echo ""
if [ $HAS_ERROR -eq 1 ]; then
    printf "${RED}Error: Certificate verification failed!${NC}\n"
    echo ""
    echo "To update certificates, run:"
    echo "  ./scripts/download_certs.sh"
    exit 2
elif [ $HAS_DIFF -eq 1 ]; then
    printf "${YELLOW}Warning: Certificates are out of date!${NC}\n"
    echo ""
    echo "To update certificates, run:"
    echo "  ./scripts/download_certs.sh"
    echo ""
    echo "Then commit the changes:"
    echo "  git add pkg/auth/certs/*.pem"
    echo '  git commit -m "Update CERN CA certificates"'
    exit 1
else
    printf "${GREEN}All certificates are up to date!${NC}\n"
    exit 0
fi
