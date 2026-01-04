BINARY_NAME=cern-sso-cli
# Get version from git tag, or fallback to short hash + dirty flag
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
# Container image name (override with IMAGE_NAME=ghcr.io/user/repo make docker-build)
IMAGE_NAME ?= cern-sso-cli

# CGO flags for WebAuthn/libfido2 support (macOS with Homebrew)
# These can be overridden via environment variables
CGO_CFLAGS ?= -I$(shell brew --prefix openssl 2>/dev/null || echo /usr/include)/include
CGO_LDFLAGS ?= -L$(shell brew --prefix openssl 2>/dev/null || echo /usr/lib)/lib

LDFLAGS = -X main.version=$(VERSION)

.PHONY: all build build-no-webauthn clean test-integration build-all download-certs docker-build docker-push

all: build

# Default build with WebAuthn support (requires libfido2 and OpenSSL)
build:
	CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

# Build without WebAuthn support (no libfido2 dependency)
build-no-webauthn:
	go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

test-integration:
	go test -tags=integration -v ./...

test:
	go test -v ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f pkg/auth/certs/*.pem

# Download CERN CA certificates for embedding
download-certs:
	./scripts/download_certs.sh

# Cross-platform builds (without WebAuthn for portability)
build-all: download-certs build-darwin-amd64 build-darwin-arm64 build-linux-amd64 build-linux-arm64

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-amd64 .

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-arm64 .

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 .

# Docker targets (with WebAuthn support)
docker-build:
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-push:
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest
