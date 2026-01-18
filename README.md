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

**Option 2: Homebrew (macOS)**
Using Homebrew on macOS:

```bash
brew tap clelange/particle-physics
brew install cern-sso-cli
```

**Option 3: Using Go**
If you have Go installed on macOS or Linux:

```bash
go install github.com/clelange/cern-sso-cli@latest
```
Make sure `$(go env GOPATH)/bin` is in your `$PATH`.

**Option 4: Download Binary**
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

### 5. Get Harbor CLI Secret

Get your CLI secret for Docker login to CERN Harbor registry:

```bash
cern-sso-cli harbor
```

Use it with Docker:
```bash
docker login registry.cern.ch -u <username> -p <secret>
```

### 6. Get OpenShift Token

Get your API token for OpenShift/OKD at CERN:

```bash
cern-sso-cli openshift
```

Or get the full `oc login` command:
```bash
cern-sso-cli openshift --login-command
```

Use with `oc`:
```bash
oc login --token=$(cern-sso-cli openshift) --server=https://api.paas.okd.cern.ch
```

## Advanced Authentication

### Authentication Methods

By default, the tool automatically selects an authentication method in this order:
1. **Password** - if `KRB5_USERNAME` and `KRB5_PASSWORD` are set
2. **Keytab** - if `KRB5_KTNAME` is set (fails immediately if invalid)
3. **Credential cache** - if you have an existing Kerberos ticket
4. **Default keytab** - `~/.keytab` or `/etc/krb5.keytab`

You can force a specific method using flags:

```bash
# Force password authentication
cern-sso-cli cookie --url ... --use-password

# Force keytab (uses KRB5_KTNAME or default locations)
cern-sso-cli cookie --url ... --use-keytab

# Force keytab with explicit path
cern-sso-cli cookie --url ... --keytab ~/.keytab

# Force credential cache
cern-sso-cli cookie --url ... --use-ccache
```

When a `--use-*` flag is specified, the command fails immediately if that method cannot be used.

### Kerberos Integration (Automatic)
The tool prefers existing Kerberos tickets when no credentials or keytab are configured.

*   **Linux**: Detects `/tmp/krb5cc_...` automatically.
*   **macOS**: Detects API-based system cache. If needed, it may ask you to run `kinit --keychain youruser@CERN.CH` once to synchronise.

### Environment Variables (CI/CD)
If you don't have a Kerberos ticket or keytab, you can pass credentials:

```bash
export KRB5_USERNAME="myuser"
export KRB5_PASSWORD="mypassword"
cern-sso-cli cookie --url ...
```

### Keytab Authentication

For automated environments or when you prefer not to store passwords:

```bash
# Using CLI flag (highest priority)
cern-sso-cli cookie --url https://gitlab.cern.ch --keytab ~/.keytab

# Using environment variable
export KRB5_KTNAME=~/.keytab
cern-sso-cli cookie --url https://gitlab.cern.ch
```

**Creating a keytab at CERN:**

> **Note**: CERN's Active Directory requires keytabs to be registered with the KDC.
> You cannot create a working keytab by simply deriving a key from your password
> (e.g., using `ktutil`). Instead, use the CERN-provided `cern-get-keytab` tool.

```bash
# On a CERN Linux machine
cern-get-keytab --user --login youruser --keytab ~/.keytab
```

For more information, see [Generating a user keytab at CERN](https://cern.service-now.com/service-portal?id=kb_article&n=KB0003405).


### WebAuthn (FIDO2 / YubiKey / Touch ID)
If your account supports WebAuthn, you can use:
1.  **Hardware Keys (YubiKey)**: Supported natively via `libfido2`.
2.  **Platform Authenticators (Touch ID / iCloud Keychain)**: Supported via **Browser Authentication**.

#### Browser Authentication (Chrome / Touch ID)
This mode opens a visible Google Chrome window to perform the authentication. This is powerful because:

1.  **Kerberos SSO**: It automatically uses your existing Kerberos tickets (from `kinit`), often logging you in without typing a password.
2.  **Flexible 2FA**: If 2FA is required, you can use any method supported by the browser:
    *   **OTP** (Authenticator App)
    *   **USB Security Keys** (YubiKey)
    *   **Touch ID / Fingerprint** (Exclusive to this mode; not supported in CLI-only mode)

**Requirements**:
*   Google Chrome installed

**Usage**:
```bash
cern-sso-cli cookie --browser --url https://gitlab.cern.ch
```

#### Hardware Keys (Headless)
**Important**: Native hardware key support uses `libfido2`, which only supports USB/NFC security keys (e.g., YubiKey).

**List available devices:**
```bash
cern-sso-cli webauthn list
```

**Select a specific device by index:**
```bash
cern-sso-cli --webauthn-device-index 0 cookie --url https://gitlab.cern.ch
```

**Flags**:
*   `--browser`: Use visual browser (supports Touch ID / iCloud Keychain).
*   `--use-webauthn`: Force WebAuthn usage.
*   `--webauthn-pin 1234`: Provide PIN if required.
*   `--webauthn-device-index N`: Select device by index (see `webauthn list`).

## Global Options

| Flag | Description |
| ---- | ----------- |
| `--quiet`, `-q` | Suppress output (exit 0 = success). |
| `--user`, `-u` | Specify username (e.g. `--user alice`). |
| `--krb5-config` | Kerberos config source: `embedded` (default), `system`, or file path. |
| `--keytab` | Path to keytab file (implies --use-keytab). |
| `--use-password` | Force password authentication. |
| `--use-keytab` | Force keytab authentication. |
| `--use-ccache` | Force credential cache authentication. |
| `--otp` | Provide OTP code directly (e.g. `--otp 123456`). |
| `--otp-command` | Command to fetch OTP (e.g. 1Password CLI). |
| `--otp-retries` | Max OTP retry attempts (default 3). |
| `--use-otp` | Use OTP even if WebAuthn is default. |
| `--use-webauthn` | Use WebAuthn even if OTP is default. |
| `--browser` | Use browser for authentication (supports WebAuthn, Touch ID, etc.). |
| `--webauthn-device` | Path to specific FIDO2 device (auto-detect if empty). |
| `--webauthn-device-index` | Index of FIDO2 device to use (see `webauthn list`), -1 for auto. |
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

### Harbor Command

| Flag | Description |
| ---- | ----------- |
| `--url` | Harbor registry URL (default "https://registry.cern.ch"). |
| `--auth-host` | Authentication hostname (default "auth.cern.ch"). |
| `--insecure`, `-k` | Skip certificate validation. |
| `--json` | Output result as JSON. |

### OpenShift Command

| Flag | Description |
| ---- | ----------- |
| `--url` | OpenShift cluster URL (default "https://paas.cern.ch"). |
| `--auth-host` | Authentication hostname (default "auth.cern.ch"). |
| `--login-command` | Output full `oc login` command instead of just the token. |
| `--insecure`, `-k` | Skip certificate validation. |
| `--json` | Output result as JSON. |

### Update Command

| Flag | Description |
| ---- | ----------- |
| `--check` | Only check for updates, don't install. |

Check for and install updates:

```bash
# Check for updates without installing
cern-sso-cli update --check

# Download and install the latest version
cern-sso-cli update
```

**Note**: If installed via Homebrew, the command will suggest using `brew upgrade` instead.

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
