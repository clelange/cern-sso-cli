# Developing cern-sso-cli

This guide is for contributors who want to build, test, and develop cern-sso-cli.

## Prerequisites

- Go 1.21 or later
- Make
- Docker (for container builds, optional)

## Build from Source

```bash
git clone https://github.com/clelange/cern-sso-cli.git
cd cern-sso-cli
make download-certs  # Downloads CERN CA certificates
make build           # Builds binary with WebAuthn support
```

## Cross-Compilation

Build portable binaries without WebAuthn for macOS and Linux (no libfido2 dependency):

```bash
make build-all
```

Binaries will be placed in the `dist/` directory with names like `cern-sso-cli-linux-amd64`.

Build WebAuthn-enabled binaries for all platforms:

```bash
# Platform-specific builds - must be built on target platform
make build-darwin-amd64-webauthn     # macOS Intel (requires macOS + libfido2)
make build-darwin-arm64-webauthn     # macOS Apple Silicon (requires macOS + libfido2)
make build-linux-amd64-webauthn      # Linux AMD64 (requires libfido2-dev)
make build-linux-arm64-webauthn      # Linux ARM64 (requires libfido2-dev)
```

All WebAuthn variants are built in releases using dedicated runners:
- Linux AMD64 (ubuntu-latest)
- Linux ARM64 (ubuntu-22.04-arm)
- macOS ARM64 (macos-latest)
- macOS Intel (macos-15-intel)

Or build all WebAuthn variants at once (note: must run on each target platform):

```bash
make build-all-webauthn
```

Binaries will be placed in the `dist/` directory with names like `cern-sso-cli-linux-amd64`.



**Note**: WebAuthn builds for Linux ARM64 and macOS Intel are available for manual builds but not included in releases due to CI limitations.

Or build all WebAuthn variants at once (note: must run on each target platform):

```bash
make build-all-webauthn
```

## Container Image

Build locally:

```bash
make docker-build
```

Multi-architecture container images (amd64/arm64) are available from GitHub Container Registry.

## Testing

Run integration tests (requires CERN credentials and network access):

```bash
export KRB5_USERNAME='your-username'
export KRB5_PASSWORD='your-password'
make test-integration
```

The integration tests verify cookie generation and authentication against:
- account.web.cern.ch
- gitlab.cern.ch
- account.web.cern.ch

### Testing Browser Authentication

Browser-based authentication (Touch ID, Kerberos integration) is difficult to test in CI/CD. It requires manual verification:

**Requirements:**
- Google Chrome installed on your machine
- macOS (for Touch ID / native Kerberos) or Linux (Chrome required)

**Run the test:**
```bash
# 1. Standard browser auth (WebAuthn/Touch ID)
go run . cookie --browser --url https://gitlab.cern.ch

# 2. Kerberos integration (if you have valid kinit tickets)
# Ensure you run 'kinit' first
DEBUG=1 go run . cookie --browser --url https://gitlab.cern.ch
```

Verify that:
1. Chrome launch is visible.
2. The "Sign in with Kerberos" button is clicked automatically (if using Kerberos).
3. The flow completes and cookies are saved.

## Building Without WebAuthn

If you don't need WebAuthn support (to avoid the libfido2 dependency):

```bash
make build-no-webauthn
# Or directly:
CGO_ENABLED=0 go build -tags nowebauthn -o cern-sso-cli .
```

## Building With WebAuthn (Default)

The default build includes WebAuthn support:

```bash
make build
# Or directly:
go build -o cern-sso-cli .
```

### Platform-Specific Builds

- **macOS**: `brew install libfido2` then `go build -o cern-sso-cli .`
- **Linux**: `sudo apt install libfido2-dev` then `CGO_ENABLED=1 go build -o cern-sso-cli .`

### Build Options Summary

| Build Target | WebAuthn | libfido2 | Platforms |
| ------------ | -------- | -------- | ---------- |
| `make build` | ✅ | Required | Current platform only |
| `make build-no-webauthn` | ❌ | Not required | Current platform only |
| `make build-all` | ❌ | Not required | macOS/Linux (amd64/arm64) |
| `make build-*-webauthn` | ✅ | Required | Target platform only |
| `make build-all-webauthn` | ✅ | Required | Target platform only |
