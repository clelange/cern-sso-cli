# cern-krb-cookie

A Go implementation of CERN SSO authentication tools. This is the Go equivalent of [auth-get-sso-cookie](https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie).

## Features

- Save SSO session cookies for use with curl, wget, etc.
- Get OIDC access tokens via Authorization Code flow
- Device Authorization Grant flow for headless environments

## Installation

```bash
go install github.com/clelange/cern-krb-cookie@latest
```

### Build from Source

```bash
git clone https://github.com/clelange/cern-krb-cookie.git
cd cern-krb-cookie
make build
```

### Cross-Compilation

To build binaries for macOS and Linux (amd64 and arm64):

```bash
make build-all
```
Binaries will be placed in the `dist/` directory.

## Usage

### Environment Variables

```bash
export KRB_USERNAME='your-cern-username'
export KRB_PASSWORD='your-cern-password'
```

Or use [direnv](https://direnv.net/) with a `.envrc` file.

### Save SSO Cookies

Authenticate to a CERN SSO-protected URL and save cookies in Netscape format:

```bash
./cern-krb-cookie cookie --url https://your-app.cern.ch --file cookies.txt
```

Use the cookies with curl:

```bash
curl -b cookies.txt https://your-app.cern.ch/api/resource
```

### Get Access Token

Get an OIDC access token using Kerberos authentication:

```bash
./cern-krb-cookie token --url https://redirect-uri --client-id your-client-id
```

### Device Authorization

For environments without Kerberos, use Device Authorization Grant:

```bash
./cern-krb-cookie device --client-id your-client-id
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
