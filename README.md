# cern-sso-cli

A Go implementation of CERN SSO authentication tools. This is the Go equivalent of [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie).

## Features

- Save SSO session cookies for use with curl, wget, etc.
- Check cookie expiration status (with optional HTTP verification)
- Get OIDC access tokens via Authorisation Code flow
- Device Authorisation Grant flow for headless environments
- Cookie reuse: Existing auth.cern.ch cookies are reused for new CERN subdomains, avoiding redundant Kerberos authentication
- Support for skipping certificate validation via `--insecure` or `-k`
- 2FA support for CERN primary accounts (OTP & WebAuthn/YubiKey)
- Shell completion for bash, zsh, fish, and PowerShell

## Installation

To use the tool without typing `./` or worrying about paths, install it to your system PATH.

**Option 1: One-line install (Recommended)**
The fastest way to install on Linux or macOS:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/clelange/cern-sso-cli/main/scripts/install.sh)"
```

This script will:
- Detect your OS and architecture
- Check for libfido2 availability and download the appropriate binary (with or without WebAuthn support)
- Install to `/usr/local/bin`, `~/bin`, or `~/.local/bin` (based on permissions)
- Automatically configure your PATH if needed

**Option 2: Using Go**
If you have Go installed on macOS or Linux:

```bash
go install github.com/clelange/cern-sso-cli@latest
```
Make sure `$(go env GOPATH)/bin` is in your `$PATH`.

**Option 3: Download Binary**
Two binary types are available for each platform:
- **WebAuthn-enabled binaries** (default, `*-webauthn` suffix): Support hardware keys (YubiKey), require libfido2 on your system. Available for all platforms.
- **Portable binaries** (no suffix): Work on all systems without libfido2, WebAuthn disabled. Available for all platforms (macOS Intel/ARM64, Linux AMD64/ARM64).

**Note for remote systems**: Use the portable binaries when running on a remote server or headless environment, as WebAuthn hardware keys won't work without direct access to the device. Use OTP instead.

1. Download the latest release for your OS from [GitHub Releases](https://github.com/clelange/cern-sso-cli/releases).
2. Choose the binary type based on your needs (e.g., `cern-sso-cli-linux-amd64` for portable or `cern-sso-cli-linux-amd64-webauthn` for WebAuthn support)
3. Rename the file to `cern-sso-cli`.
4. Make it executable and move it to your path:

```bash
chmod +x cern-sso-cli
sudo mv cern-sso-cli /usr/local/bin/
```

Now you can run it from anywhere:
```bash
cern-sso-cli --version
```

### WebAuthn Requirements (YubiKey)
If you intend to use hardware security keys (WebAuthn), you need to:
1. Download a WebAuthn-enabled binary (default, `*-webauthn` suffix)
2. Install `libfido2` on your system

*   **macOS**: `brew install libfido2`
*   **Ubuntu/Debian**: `sudo apt install libfido2-dev`
*   **RHEL/AlmaLinux/Fedora**: `sudo dnf install libfido2-devel`

**Note**: WebAuthn is disabled in portable binaries. Use portable binaries with OTP or WebAuthn-enabled binaries with hardware keys.

## Quick Start
The most common usage is getting cookies for a website:

```bash
cern-sso-cli cookie --url https://gitlab.cern.ch
```
*   **Primary Accounts**: You will be prompted for your 2FA OTP (authenticator app) or can use your YubiKey (WebAuthn).
*   **Service Accounts**: You will just be logged in (no 2FA required).

## Concepts: Authentication & Account Types

It is important to know which type of account you are using, as the authentication flow differs.

### Primary Accounts (Standard User)
*   **2FA is MANDATORY**. You cannot skip this.
*   **Methods**:
    *   **OTP**: Enter the 6-digit code from your authenticator app.
    *   **WebAuthn**: Use a hardware key (YubiKey) or TouchID.
*   **Kerberos**: If you have a valid Kerberos ticket (`kinit`), the tool detects it and avoids asking for your password, but you **still need to provide 2FA**.

### Service Accounts
*   **2FA is OPTIONAL** (usually disabled).
*   **Ideal for Scripts/CI**: Since no human interaction is needed for 2FA, these are best for automation.
*   **Usage**: The tool will simply authenticate using the Kerberos ticket or Password.

For more details on CERN account types, see [CERN Authentication and Authorisation Services](https://auth.docs.cern.ch/).

## Usage

### 1. Authenticate & Save Cookies (curl/wget)

Get cookies for a generic CERN SSO site and save them to `cookies.txt`:

```bash
cern-sso-cli cookie --url https://gitlab.cern.ch --file cookies.txt
```

Use them with curl:
```bash
curl -b cookies.txt https://gitlab.cern.ch/api/v4/user
```

### 2. Get OIDC Access Token

For OAuth/OIDC flows:

```bash
cern-sso-cli token --url https://redirect-uri --client-id my-client-id
```

### 3. Check Cookie Status

Check if your cookies are still valid:

```bash
cern-sso-cli status --file cookies.txt
```

Verify them against the server:
```bash
cern-sso-cli status --url https://gitlab.cern.ch --file cookies.txt
```

### 4. Device Grant (Headless/SSH)
For machines without a browser or input method:

```bash
cern-sso-cli device --client-id my-client-id
```

## Advanced Authentication

### Kerberos Integration (Automatic)
The tool prefers existing Kerberos tickets.

*   **Linux**: Detects `/tmp/krb5cc_...` automatically.
*   **macOS**: Detects API-based system cache. If needed, it may ask you to run `kinit --keychain youruser@CERN.CH` once to synchronise.

### Environment Variables (CI/CD)
If you don't have a Kerberos ticket, you can pass credentials:

```bash
export KRB_USERNAME="myuser"
export KRB_PASSWORD="mypassword"
cern-sso-cli cookie --url ...
```

### WebAuthn (FIDO2 / YubiKey)
If your account supports WebAuthn, it may prompt you to touch your key.

**Flags**:
*   `--use-webauthn`: Force WebAuthn usage.
*   `--webauthn-pin 1234`: Provide PIN if required.

## Global Options

| Flag | Description |
| ---- | ----------- |
| `--quiet`, `-q` | Suppress output (exit 0 = success). |
| `--user`, `-u` | Specify username (e.g. `--user alice`). |
| `--krb5-config` | Kerberos config source: `embedded` (default), `system`, or file path. |
| `--otp` | Provide OTP code directly (e.g. `--otp 123456`). |
| `--otp-command` | Command to fetch OTP (e.g. 1Password CLI). |
| `--otp-retries` | Max OTP retry attempts (default 3). |
| `--use-otp` | Use OTP even if WebAuthn is default. |
| `--use-webauthn` | Use WebAuthn even if OTP is default. |
| `--webauthn-device` | Path to specific FIDO2 device (auto-detect if empty). |
| `--webauthn-pin` | PIN for FIDO2 security key (alternative to prompt). |
| `--webauthn-timeout` | Timeout in seconds for FIDO2 device interaction (default 30). |

## Subcommand Options

### Cookie Command

| Flag | Description |
| ---- | ----------- |
| `--url` | Target URL to authenticate against (required). |
| `--file` | Output cookie file (default "cookies.txt"). |
| `--auth-host` | Authentication hostname (default "auth.cern.ch"). |
| `--force` | Force refresh of cookies, bypassing validation. |
| `--insecure`, `-k` | Skip certificate validation. |

### Token Command

| Flag | Description |
| ---- | ----------- |
| `--url` | OAuth redirect URI (required). |
| `--client-id` | OAuth client ID (required). |
| `--auth-host` | Authentication hostname (default "auth.cern.ch"). |
| `--realm` | Authentication realm (default "cern"). |
| `--insecure`, `-k` | Skip certificate validation. |

### Device Command

| Flag | Description |
| ---- | ----------- |
| `--client-id` | OAuth client ID (required). |
| `--auth-host` | Authentication hostname (default "auth.cern.ch"). |
| `--realm` | Authentication realm (default "cern"). |
| `--insecure`, `-k` | Skip certificate validation. |

### Status Command

| Flag | Description |
| ---- | ----------- |
| `--file` | Cookie file to check (default "cookies.txt"). |
| `--json` | Output as JSON instead of table format. |
| `--url` | URL to verify cookies against (makes HTTP request). |
| `--auth-host` | Authentication hostname for verification (default "auth.cern.ch"). |
| `--insecure`, `-k` | Skip certificate validation when verifying. |

## Container Support

Run via Docker:

```bash
docker run --rm -v $(pwd):/output ghcr.io/clelange/cern-sso-cli \
  cookie --url https://gitlab.cern.ch --file /output/cookies.txt
```

### YubiKey/WebAuthn in Docker

**macOS Limitation**: Due to macOS Docker/OrbStack limitations, USB devices (including YubiKey) cannot be passed through to containers. On macOS, you must use OTP-based 2FA when running in Docker.

**Linux**: USB passthrough is supported. To use YubiKey in Docker on Linux:

```bash
# Find your YubiKey device
lsusb

# Pass through the USB device
docker run --rm --device=/dev/bus/usb/XXX/YYY -v $(pwd):/output \
  ghcr.io/clelange/cern-sso-cli:latest-webauthn \
  cookie --url https://gitlab.cern.ch --file /output/cookies.txt
```

Replace XXX/YYY with your YubiKey's bus/device numbers from `lsusb`.

## Shell Completion

Generate completion scripts for bash, zsh, fish, or powershell.

```bash
# Bash example
source <(cern-sso-cli completion bash)

# Zsh example
source <(cern-sso-cli completion zsh)
```

## Comparison to Python Version
This is a Go port of [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie).

| Feature | Python | Go |
| ------- | ------ | -- |
| Dependencies | requests, beautifulsoup4, requests-gssapi | None (single binary) |
| Kerberos | System GSS-API | Built-in (gokrb5) |
| Insecure | Supported (`verify=verify_cert`) | Supported (`--insecure`) |
| QR Codes | Supported | Not yet |
