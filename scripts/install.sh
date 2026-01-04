#!/bin/bash

set -e

REPO="clelange/cern-sso-cli"
BINARY_NAME="cern-sso-cli"

echo "Installing ${BINARY_NAME}..."

detect_os() {
    case "$(uname -s)" in
        Linux*)     OS=linux;;
        Darwin*)    OS=darwin;;
        *)          echo "Unsupported OS: $(uname -s)"; exit 1;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)     ARCH=amd64;;
        arm64|aarch64) ARCH=arm64;;
        *)          echo "Unsupported architecture: $(uname -m)"; exit 1;;
    esac
}

detect_os
detect_arch

echo "Detected OS: ${OS}"
echo "Detected architecture: ${ARCH}"

check_libfido2() {
    if [ "$OS" = "linux" ]; then
        if ldconfig -p 2>/dev/null | grep -q libfido2 || \
           dpkg -l 2>/dev/null | grep -q libfido2-dev || \
           rpm -qa 2>/dev/null | grep -q libfido2; then
            return 0
        fi
    elif [ "$OS" = "darwin" ]; then
        if brew list libfido2 &>/dev/null || pkg-config --exists libfido2 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

if check_libfido2; then
    echo "libfido2 detected, WebAuthn support available"
    HAS_WEBAUTHN=true
else
    echo "libfido2 not found, installing without WebAuthn support"
    echo "Install libfido2 for WebAuthn support:"
    echo "  macOS: brew install libfido2"
    echo "  Linux: apt install libfido2-dev (Debian/Ubuntu) or dnf install libfido2-devel (Fedora)"
    HAS_WEBAUTHN=false
fi

get_latest_release() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

LATEST_VERSION=$(get_latest_release)
if [ -z "$LATEST_VERSION" ]; then
    echo "Failed to fetch latest release version"
    exit 1
fi

echo "Latest version: ${LATEST_VERSION}"

if [ "$HAS_WEBAUTHN" = true ]; then
    BINARY_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${OS}-${ARCH}-webauthn"
else
    BINARY_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
fi

echo "Downloading from: ${BINARY_URL}"

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/checksums.txt"
if ! curl -fsSL "${CHECKSUMS_URL}" -o "${TEMP_DIR}/checksums.txt"; then
    echo "Warning: Failed to download checksums file, skipping verification"
else
    echo "Downloaded checksums file"
fi

if ! curl -fsSL "${BINARY_URL}" -o "${TEMP_DIR}/${BINARY_NAME}"; then
    echo "Failed to download binary, trying without webauthn suffix..."
    BINARY_URL="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
    if ! curl -fsSL "${BINARY_URL}" -o "${TEMP_DIR}/${BINARY_NAME}"; then
        echo "Failed to download binary"
        exit 1
    fi
fi

verify_checksum() {
    if [ ! -f "${TEMP_DIR}/checksums.txt" ]; then
        echo "Checksums file not found, skipping verification"
        return 0
    fi

    BINARY_FILE="${BINARY_NAME}-${OS}-${ARCH}"
    if [ "$HAS_WEBAUTHN" = true ]; then
        BINARY_FILE="${BINARY_FILE}-webauthn"
    fi

    EXPECTED_CHECKSUM=$(grep "${BINARY_FILE}$" "${TEMP_DIR}/checksums.txt" | awk '{print $1}')
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        echo "Warning: Checksum not found for ${BINARY_FILE}, skipping verification"
        return 0
    fi

    if command -v sha256sum &>/dev/null; then
        ACTUAL_CHECKSUM=$(sha256sum "${TEMP_DIR}/${BINARY_NAME}" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
        ACTUAL_CHECKSUM=$(shasum -a 256 "${TEMP_DIR}/${BINARY_NAME}" | awk '{print $1}')
    else
        echo "sha256sum/shasum not found, skipping checksum verification"
        return 0
    fi

    if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
        echo "Checksum verification failed!"
        echo "Expected: ${EXPECTED_CHECKSUM}"
        echo "Actual:   ${ACTUAL_CHECKSUM}"
        exit 1
    fi

    echo "Checksum verified: ${ACTUAL_CHECKSUM}"
}

verify_checksum

chmod +x "${TEMP_DIR}/${BINARY_NAME}"

determine_install_dir() {
    if [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    elif [ -w "${HOME}/bin" ] || mkdir -p "${HOME}/bin" 2>/dev/null; then
        INSTALL_DIR="${HOME}/bin"
    elif [ -w "${HOME}/.local/bin" ] || mkdir -p "${HOME}/.local/bin" 2>/dev/null; then
        INSTALL_DIR="${HOME}/.local/bin"
    else
        echo "No writeable installation directory found. Please specify one with INSTALL_DIR environment variable."
        exit 1
    fi
}

if [ -z "${INSTALL_DIR}" ]; then
    determine_install_dir
fi

echo "Installing to: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

verify_installation() {
    if [ ! -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        echo "Installation verification failed"
        exit 1
    fi
    echo "Installation successful!"
    "${INSTALL_DIR}/${BINARY_NAME}" --version
}

verify_installation

configure_path() {
    SHELL_NAME=$(basename "${SHELL}")
    PATH_ENTRY="export PATH=\"${INSTALL_DIR}:\$PATH\""

    case ":$PATH:" in
        *:"${INSTALL_DIR}":*)
            echo "${INSTALL_DIR} is already in PATH"
            return 0
            ;;
    esac

    echo "${INSTALL_DIR} is not in PATH"

    case "${SHELL_NAME}" in
        bash)
            CONFIG_FILE="${HOME}/.bashrc"
            ;;
        zsh)
            CONFIG_FILE="${HOME}/.zshrc"
            ;;
        fish)
            PATH_ENTRY="fish_add_path ${INSTALL_DIR}"
            CONFIG_FILE="${HOME}/.config/fish/config.fish"
            ;;
        *)
            CONFIG_FILE="${HOME}/.profile"
            ;;
    esac

    if [ ! -f "${CONFIG_FILE}" ] && [ "${SHELL_NAME}" != "fish" ]; then
        CONFIG_FILE="${HOME}/.profile"
    fi

    if grep -q "${INSTALL_DIR}" "${CONFIG_FILE}" 2>/dev/null; then
        echo "PATH entry already exists in ${CONFIG_FILE}"
        return 0
    fi

    echo "" >> "${CONFIG_FILE}"
    echo "# Added by ${BINARY_NAME} installer" >> "${CONFIG_FILE}"
    echo "${PATH_ENTRY}" >> "${CONFIG_FILE}"
    echo "Added ${INSTALL_DIR} to PATH in ${CONFIG_FILE}"
    echo "Please restart your shell or run: source ${CONFIG_FILE}"
}

configure_path

echo ""
echo "Installation complete!"
echo "You can now use: ${BINARY_NAME}"
