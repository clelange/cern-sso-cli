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
make build
```

## Cross-Compilation

To build binaries for macOS and Linux (amd64 and arm64):

```bash
make build-all
```

Binaries will be placed in the `dist/` directory.

## Container Image

Build locally:

```bash
make docker-build
```

Multi-architecture container images (amd64/arm64) are available from GitHub Container Registry.

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

## Building Without WebAuthn

If you don't need WebAuthn support (to avoid the libfido2 dependency):

```bash
make build-no-webauthn
# Or directly:
go build -tags nowebauthn -o cern-sso-cli .
```
