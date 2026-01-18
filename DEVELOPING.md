# Developing cern-sso-cli

This guide is for contributors who want to build, test, and develop cern-sso-cli.

## Prerequisites

- Go 1.21 or later
- Make
- Docker (for container builds, optional)

## Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com) hooks to ensure code quality. We recommend using [prek](https://github.com/j178/prek), a faster Rust-based alternative.

### Installation

#### macOS

```bash
# Install required tools
brew install golangci-lint gosec
go install golang.org/x/tools/cmd/goimports@latest

# Install hook runner (prek is recommended)
cargo install prek     # Rust-based (faster)
# OR
pip install pre-commit # Python-based
```

#### Linux

```bash
# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Install gosec
curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Install goimports
go install golang.org/x/tools/cmd/goimports@latest

# Install hook runner (prek is recommended)
cargo install prek     # Rust-based (faster)
# OR
pip install pre-commit # Python-based
```

### Setup

```bash
# Install the git hooks
make download-certs # Download required certificates (needed for linting)
prek install        # or: pre-commit install
prek install --hook-type commit-msg  # Enable conventional commit checks
```

### Usage

```bash
# Run all hooks on staged files (automatic on git commit)
prek run

# Run all hooks on all files
prek run --all-files

# Run specific hook
prek run golangci-lint --all-files

# Run linting manually (without pre-commit)
make lint
```

### Conventional Commits

Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

**Examples:**
```bash
git commit -m "feat: add WebAuthn device selection"
git commit -m "fix(auth): handle expired Kerberos tickets"
git commit -m "docs: update installation instructions"
```

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

The integration tests verify:
- Kerberos authentication flow
- Cookie generation and management
- Multi-domain cookie handling
- Authorization Code Flow (OIDC)
- SPA fallback mechanisms (Harbor, OpenShift)
- CLI secret extraction (Harbor)
- Token retrieval (OpenShift)

**Verified services:**
- `account.web.cern.ch` (Standard SSO)
- `gitlab.cern.ch` (Standard SSO)
- `paas.cern.ch` (OpenShift - SPA)
- `registry.cern.ch` (Harbor - SPA/OIDC)

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
