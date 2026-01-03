# cern-sso-cli

A Go implementation of CERN SSO authentication tools. This is the Go equivalent of [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie).

## Features

- Save SSO session cookies for use with curl, wget, etc.
- Check cookie validity and expiration status
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

**Important Notes:**

- Only software token-based 2FA is supported
- Hardware dongles (e.g., YubiKey) are **not currently supported**
- The OTP code is entered interactively and is not stored anywhere

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

Display the validity and expiration information of stored cookies:

```bash
./cern-sso-cli status [--file cookies.txt] [--json]
```

In quiet mode (`--quiet`), exits with code 0 if any valid cookies exist, 1 otherwise.

Shows:

- Cookie name, domain, and path
- Expiration date/time
- Status: ✓ Valid, ✗ Expired, or Session
- Remaining time for valid cookies
- Security flags: [S] for Secure, [H] for HttpOnly

Use `--json` flag for machine-readable output:

```bash
./cern-sso-cli status --json
```

### Global Options

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--quiet` or `-q` | `false` | Suppress all output (except critical errors). Exit code 0 on success, non-zero otherwise. |
| `--user` or `-u` | (none) | Use specific CERN.CH Kerberos principal (e.g., `clange` or `clange@CERN.CH`). See [Multiple Kerberos Credentials](#multiple-kerberos-credentials). |
| `--krb5-config` | `embedded` | Kerberos config source: `embedded` (built-in CERN.CH config), `system` (uses `/etc/krb5.conf` or `KRB5_CONFIG` env var), or a file path |

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
