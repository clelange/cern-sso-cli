# cern-sso-cli

A Go implementation of CERN SSO authentication tools. This is the Go equivalent of [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie).

## Features

- Save SSO session cookies for use with curl, wget, etc.
- Check cookie expiration status (with optional HTTP verification)
- Get OIDC access tokens via Authorization Code flow
- Device Authorization Grant flow for headless environments
- Cookie reuse: Existing auth.cern.ch cookies are reused for new CERN subdomains, avoiding redundant Kerberos authentication
- Support for skipping certificate validation via `--insecure` or `-k`
- 2FA/OTP support for CERN primary accounts (software tokens only)
- Shell completion for bash, zsh, fish, and PowerShell

## Installation

```bash
go install github.com/clelange/cern-sso-cli@latest
```

### Build from Source

```bash
git clone https://github.com/clelange/cern-sso-cli.git
cd cern-sso-cli
make download-certs  # Downloads CERN CA certificates
make build
```

### Cross-Compilation

To build binaries for macOS and Linux (amd64 and arm64):

```bash
make build-all
```

Binaries will be placed in the `dist/` directory.

### Container Image

Multi-architecture container images (amd64/arm64) are available from GitHub Container Registry:

```bash
docker pull ghcr.io/clelange/cern-sso-cli:latest
```

Run with a Kerberos credential cache:

```bash
# Linux (file-based cache) - mount your ticket to /tmp/krb5cc
docker run --rm \
  -v /tmp/krb5cc_$(id -u):/tmp/krb5cc \
  -v $(pwd):/output \
  ghcr.io/clelange/cern-sso-cli cookie --url https://gitlab.cern.ch --file /output/cookies.txt

# With password authentication
docker run --rm \
  -e KRB_USERNAME=your-username \
  -e KRB_PASSWORD=your-password \
  -v $(pwd):/output \
  ghcr.io/clelange/cern-sso-cli cookie --url https://gitlab.cern.ch --file /output/cookies.txt
```

Build locally:

```bash
make docker-build
```

## Usage

### Authentication

The tool supports two authentication methods, tried in this order:

#### 1. Kerberos Credential Cache (Recommended for Linux)

If you already have a valid Kerberos ticket (from `kinit`), the tool will use it automatically:

```bash
# Get a Kerberos ticket first
kinit your-username@CERN.CH

# Verify your ticket
klist

# Run the tool - no environment variables needed!
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

**Linux:** Works automatically with the default credential cache (`/tmp/krb5cc_<UID>`).

**macOS:** The default macOS credential cache uses an API-based storage (`API:xxx`). The tool can **automatically convert** this to a file-based cache, but requires one-time keychain setup:

```bash
# One-time setup: save password to macOS Keychain
kinit --keychain your-username@CERN.CH

# Now the tool works automatically
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

The tool uses `kinit --keychain` internally to create a file cache from your keychain-stored password.

**Alternative:** If you prefer not to use keychain, manually create a file-based cache:

```bash
kinit -c /tmp/krb5cc_custom your-username@CERN.CH
export KRB5CCNAME=/tmp/krb5cc_custom
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

#### 2. Username/Password (Fallback)

If no valid credential cache is found, set these environment variables:

```bash
export KRB_USERNAME='your-cern-username'
export KRB_PASSWORD='your-cern-password'
```

Or use [direnv](https://direnv.net/) with a `.envrc` file.

#### Multiple Kerberos Credentials

On macOS, you may have multiple Kerberos tickets from different accounts (visible via `klist -l`). Use the `--user` flag to select a specific CERN.CH account:

```bash
# Use a specific account
./cern-sso-cli -u alice cookie --url https://gitlab.cern.ch

# With full principal
./cern-sso-cli --user alice@CERN.CH cookie --url https://gitlab.cern.ch
```

If no matching cache is found but `KRB_PASSWORD` is set, the tool will authenticate using the specified username with that password.

If the specified user is not found, the error message lists available CERN.CH caches:

```shell
Error: no Kerberos cache found for user 'baduser@CERN.CH'
Available CERN.CH caches:
  alice@CERN.CH (expires Jan 3 22:26:00)
  bob@CERN.CH (expires Jan 3 22:26:01)
```

#### 2FA/OTP Support

If your CERN account has 2FA enabled (recommended for primary accounts), the tool will automatically prompt for a 6-digit OTP code during authentication:

```bash
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

The tool will display:

```shell
Logging in with Kerberos...
Enter your 6-digit OTP code for alice@CERN.CH: 123456
```

##### Password Manager Integration

You can automate OTP entry using password manager CLI tools:

**1Password:**

```bash
# Using --otp-command flag
./cern-sso-cli cookie --url https://gitlab.cern.ch --otp-command "op item get CERN --otp"

# Using environment variable (set once)
export CERN_SSO_OTP_COMMAND="op item get CERN --otp"
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

**Bitwarden:**

```bash
./cern-sso-cli cookie --url https://gitlab.cern.ch --otp-command "bw get totp CERN"
```

**Direct OTP Value:**

```bash
# Provide OTP directly (useful for scripts)
./cern-sso-cli cookie --url https://gitlab.cern.ch --otp 123456

# Or via environment variable
export CERN_SSO_OTP=123456
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

**Priority Order:** The tool checks OTP sources in this order:

1. `--otp` flag
2. `--otp-command` flag
3. `CERN_SSO_OTP` environment variable
4. `CERN_SSO_OTP_COMMAND` environment variable
5. Interactive prompt (default)

##### OTP Retry

If an OTP fails (expired or typo), the tool automatically retries:

- **Command sources** (`--otp-command`): Waits 3 seconds for TOTP window rollover, then re-executes the command
- **Interactive prompt**: Re-prompts with "Invalid OTP. Try again (2/3):"
- **Static values** (`--otp` flag): Cannot retry (fails immediately)

Use `--otp-retries` to configure retry behavior:

```bash
# Custom retry count
./cern-sso-cli cookie --url https://gitlab.cern.ch --otp-retries 5

# Disable retry (fail on first error)
./cern-sso-cli cookie --url https://gitlab.cern.ch --otp-retries 1
```

**Important Notes:**

- OTP codes are validated to be exactly 6 digits

#### WebAuthn/FIDO2 Support (YubiKey)

For accounts with hardware security keys (YubiKey, etc.) as 2FA, the tool supports WebAuthn authentication:

**Requirements:**

- **macOS**: `brew install libfido2`
- **Linux**: `sudo apt install libfido2-dev` (Ubuntu/Debian)
- **Windows**: `scoop install libfido2`

**Direct FIDO2 Authentication (Default):**

```bash
# Insert your security key and run
./cern-sso-cli cookie --url https://gitlab.cern.ch

# When prompted, touch your security key
```

**With PIN (if your key requires one):**

```bash
# Via flag
./cern-sso-cli cookie --url https://gitlab.cern.ch --webauthn-pin 123456

# Via environment variable
export CERN_SSO_WEBAUTHN_PIN=123456
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

**WebAuthn Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--webauthn-pin` | (prompt) | PIN for security key |
| `--webauthn-device` | (auto) | Path to specific FIDO2 device |
| `--webauthn-timeout` | `30s` | Timeout for device interaction |
| `--prefer-webauthn` | `false` | Prefer WebAuthn over OTP |

**Building Without WebAuthn:**

If you don't need WebAuthn support (to avoid the libfido2 dependency):

```bash
make build-no-webauthn
# Or directly:
go build -tags nowebauthn -o cern-sso-cli .
```

### Save SSO Cookies

Authenticate to a CERN SSO-protected URL and save cookies in Netscape format:

```bash
./cern-sso-cli cookie --url https://your-app.cern.ch --file cookies.txt
```

Use the cookies with curl:

```bash
curl -b cookies.txt https://your-app.cern.ch/api/resource
```

### Get Access Token

Get an OIDC access token using Kerberos authentication:

```bash
./cern-sso-cli token --url https://redirect-uri --client-id your-client-id
```

### Device Authorization

For environments without Kerberos, use Device Authorization Grant:

```bash
./cern-sso-cli device --client-id your-client-id
```

### Check Cookie Status

Display the expiration information of stored cookies:

```bash
./cern-sso-cli status [--file cookies.txt] [--json]
```

**Important**: By default, `status` only checks cookie expiration times stored in the file **without making network requests**. This is fast but doesn't verify if cookies actually work.

To verify cookies by making an actual HTTP request to a target URL:

```bash
./cern-sso-cli status --url https://gitlab.cern.ch [--file cookies.txt]
```

In quiet mode (`--quiet`), exits with code 0 if cookies are valid (and verified if `--url` is provided), 1 otherwise.

Shows:

- Cookie name, domain, and path
- Expiration date/time
- Status: ✓ Valid, ✗ Expired, or Session
- Remaining time for valid cookies
- Security flags: [S] for Secure, [H] for HttpOnly
- Verification status (when `--url` is used)

Use `--json` flag for machine-readable output:

```bash
./cern-sso-cli status --json
# With verification:
./cern-sso-cli status --url https://gitlab.cern.ch --json
```

### Global Options

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--quiet` or `-q` | `false` | Suppress all output (except critical errors). Exit code 0 on success, non-zero otherwise. |
| `--user` or `-u` | (none) | Use specific CERN.CH Kerberos principal (e.g., `clange` or `clange@CERN.CH`). See [Multiple Kerberos Credentials](#multiple-kerberos-credentials). |
| `--krb5-config` | `embedded` | Kerberos config source: `embedded` (built-in CERN.CH config), `system` (uses `/etc/krb5.conf` or `KRB5_CONFIG` env var), or a file path |
| `--otp` | (none) | 6-digit OTP code for 2FA (alternative to interactive prompt) |
| `--otp-command` | (none) | Command to execute to get OTP (e.g., `op item get CERN --otp`) |
| `--otp-retries` | `3` | Max OTP retry attempts (0 to disable retry) |

### Cookie Command

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--url` | (required) | Target URL to authenticate against |
| `--file` | `cookies.txt` | Output cookie file |
| `--auth-host` | `auth.cern.ch` | Keycloak hostname |
| `--force` | `false` | Force refresh of cookies, bypassing validation |
| `--insecure` or `-k` | `false` | Skip certificate validation |

### Token Command

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--url` | (required) | OAuth redirect URI |
| `--client-id` | (required) | OAuth client ID |
| `--auth-host` | `auth.cern.ch` | Keycloak hostname |
| `--realm` | `cern` | Keycloak realm |
| `--insecure` or `-k` | `false` | Skip certificate validation |

### Device Command

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--client-id` | (required) | OAuth client ID |
| `--auth-host` | `auth.cern.ch` | Keycloak hostname |
| `--realm` | `cern` | Keycloak realm |
| `--insecure` or `-k` | `false` | Skip certificate validation |

### Status Command

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--file` | `cookies.txt` | Cookie file to check |
| `--json` | `false` | Output as JSON instead of table format |
| `--url` | (none) | URL to verify cookies against (makes HTTP request) |
| `--insecure` or `-k` | `false` | Skip certificate validation when verifying |
| `--auth-host` | `auth.cern.ch` | Authentication hostname for verification |

### Shell Completion

Generate shell completion scripts for tab completion:

```bash
cern-sso-cli completion [bash|zsh|fish|powershell]
```

**Bash:**

```bash
# Add to current session
source <(cern-sso-cli completion bash)

# Install permanently (Linux)
cern-sso-cli completion bash > /etc/bash_completion.d/cern-sso-cli

# Install permanently (macOS with Homebrew)
cern-sso-cli completion bash > $(brew --prefix)/etc/bash_completion.d/cern-sso-cli
```

**Zsh:**

```bash
# Enable completion if not already
echo "autoload -U compinit; compinit" >> ~/.zshrc

# Install
cern-sso-cli completion zsh > "${fpath[1]}/_cern-sso-cli"
```

**Fish:**

```bash
cern-sso-cli completion fish > ~/.config/fish/completions/cern-sso-cli.fish
```

## Requirements

- Valid CERN credentials
- Network access to CERN Kerberos (cerndc.cern.ch) and SSO (auth.cern.ch)
- **Optional**: System krb5.conf (only needed if using `--krb5-config system`)

## Environment Variables

| Variable | Description |
| -------- | ----------- |
| `KRB_USERNAME` | Kerberos username (fallback if no credential cache) |
| `KRB_PASSWORD` | Kerberos password |
| `KRB5CCNAME` | Path to Kerberos credential cache |
| `KRB5_CONFIG` | Path to system krb5.conf (used with `--krb5-config system`) |
| `CERN_SSO_OTP` | 6-digit OTP code for 2FA |
| `CERN_SSO_OTP_COMMAND` | Command to execute to get OTP code |

## Comparison to Python Version

This tool is a Go port of the [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie) Python package. Key differences:

| Feature | Python | Go |
| ------- | ------ | -- |
| Dependencies | requests, beautifulsoup4, requests-gssapi | None (single binary) |
| Kerberos | System GSS-API | Built-in (gokrb5) |
| Insecure | Supported (`verify=verify_cert`) | Supported (`--insecure`) |
| QR Codes | Supported | Not yet |

## Testing

Run integration tests (requires CERN credentials and network access):

```bash
export KRB_USERNAME='your-username'
export KRB_PASSWORD='your-password'
make test-integration
```

The integration tests verify cookie generation and authentication against:

- account.web.cern.ch
- gitlab.cern.ch
