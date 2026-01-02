# cern-sso-cli

A Go implementation of CERN SSO authentication tools. This is the Go equivalent of [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie).

## Features

- Save SSO session cookies for use with curl, wget, etc.
- Get OIDC access tokens via Authorization Code flow
- Device Authorization Grant flow for headless environments

## Installation

```bash
go install github.com/clelange/cern-sso-cli@latest
```

### Build from Source

```bash
git clone https://github.com/clelange/cern-sso-cli.git
cd cern-sso-cli
make build
```

### Cross-Compilation

To build binaries for macOS and Linux (amd64 and arm64):

```bash
make build-all
```
Binaries will be placed in the `dist/` directory.

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

**macOS:** The default macOS credential cache uses an API-based storage (`API:xxx`) that is not directly accessible from Go. To use credential caching on macOS, you need to create a file-based cache:

```bash
# Create a file-based cache on macOS
kinit -c /tmp/krb5cc_custom your-username@CERN.CH

# Set the environment variable to use it
export KRB5CCNAME=/tmp/krb5cc_custom

# Now run the tool
./cern-sso-cli cookie --url https://gitlab.cern.ch
```

#### 2. Username/Password (Fallback)

If no valid credential cache is found, set these environment variables:

```bash
export KRB_USERNAME='your-cern-username'
export KRB_PASSWORD='your-cern-password'
```

Or use [direnv](https://direnv.net/) with a `.envrc` file.

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

## Options

### Cookie Command

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | (required) | Target URL to authenticate against |
| `--file` | `cookies.txt` | Output cookie file |
| `--auth-host` | `auth.cern.ch` | Keycloak hostname |

### Token Command

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | (required) | OAuth redirect URI |
| `--client-id` | (required) | OAuth client ID |
| `--auth-host` | `auth.cern.ch` | Keycloak hostname |
| `--realm` | `cern` | Keycloak realm |

### Device Command

| Flag | Default | Description |
|------|---------|-------------|
| `--client-id` | (required) | OAuth client ID |
| `--auth-host` | `auth.cern.ch` | Keycloak hostname |
| `--realm` | `cern` | Keycloak realm |

## Requirements

- Valid CERN credentials
- Network access to CERN Kerberos (cerndc.cern.ch) and SSO (auth.cern.ch)

## Comparison to Python Version

This tool is a Go port of the [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie) Python package. Key differences:

| Feature | Python | Go |
|---------|--------|-----|
| Dependencies | requests, beautifulsoup4, requests-gssapi | None (single binary) |
| Kerberos | System GSS-API | Built-in (gokrb5) |
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

## License

See [LICENSE](LICENSE) for details.
