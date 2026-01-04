# Build stage
FROM golang:1.25-alpine AS builder

# Build arguments
ARG ENABLE_WEBAUTHN=false

# Install build dependencies
# libfido2-dev needed for WebAuthn support, openssl-dev for crypto
RUN apk add --no-cache curl openssl git make && \
    if [ "$ENABLE_WEBAUTHN" = "true" ]; then \
    apk add --no-cache libfido2-dev openssl-dev musl-dev gcc; \
    fi

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Download CERN CA certificates and build
RUN make download-certs

# Build with or without WebAuthn support
RUN if [ "$ENABLE_WEBAUTHN" = "true" ]; then \
    echo "Building with WebAuthn support..." && \
    CGO_ENABLED=1 GOOS=linux go build -ldflags "-X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" -o cern-sso-cli .; \
    else \
    echo "Building without WebAuthn support..." && \
    CGO_ENABLED=0 GOOS=linux go build -tags nowebauthn -ldflags "-X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" -o cern-sso-cli .; \
    fi

# Runtime stage
FROM alpine:latest

# Build arguments (need to redeclare in this stage)
ARG ENABLE_WEBAUTHN=false

# Install runtime dependencies
# ca-certificates: for TLS connections
# krb5: Kerberos tools (kinit, klist) for credential cache support
# libfido2: for FIDO2/WebAuthn support (if enabled)
RUN apk add --no-cache ca-certificates krb5 && \
    if [ "$ENABLE_WEBAUTHN" = "true" ]; then \
    apk add --no-cache libfido2; \
    fi

# Copy the binary
COPY --from=builder /app/cern-sso-cli /usr/local/bin/cern-sso-cli

# Set default KRB5CCNAME so users only need to mount the file
ENV KRB5CCNAME=/tmp/krb5cc

# Set entrypoint
ENTRYPOINT ["cern-sso-cli"]
