# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache curl openssl git make

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Download CERN CA certificates and build
RUN make download-certs
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" -o cern-sso-cli .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
# ca-certificates: for TLS connections
# krb5: Kerberos tools (kinit, klist) for credential cache support
RUN apk add --no-cache ca-certificates krb5

# Copy the binary
COPY --from=builder /app/cern-sso-cli /usr/local/bin/cern-sso-cli

# Set default KRB5CCNAME so users only need to mount the file
ENV KRB5CCNAME=/tmp/krb5cc

# Set entrypoint
ENTRYPOINT ["cern-sso-cli"]
