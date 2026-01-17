BINARY_NAME=cern-sso-cli
# Get version from git tag, or fallback to short hash + dirty flag
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
# Container image name (override with IMAGE_NAME=ghcr.io/user/repo make docker-build)
IMAGE_NAME ?= cern-sso-cli

LDFLAGS = -X main.version=$(VERSION)

.PHONY: all build build-no-webauthn clean test-integration lint build-all build-no-webauthn download-certs docker-build docker-push

all: build

# Default build with WebAuthn support (requires libfido2)
# Install: macOS: brew install libfido2 | Linux: apt install libfido2-dev
build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

# Build without WebAuthn support (portable, no libfido2 dependency)
build-no-webauthn:
	CGO_ENABLED=0 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

test-integration:
	go test -tags=integration -v ./...

test:
	go test -v ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
	rm -f pkg/auth/certs/*.pem

# Download CERN CA certificates for embedding
download-certs:
	./scripts/download_certs.sh

# Cross-platform builds without WebAuthn (portable, no libfido2 dependency)
build-all: download-certs build-darwin-amd64 build-darwin-arm64 build-linux-amd64 build-linux-arm64

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-amd64 .

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-arm64 .

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 .

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags nowebauthn -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64 .

# Build with WebAuthn support for all platforms
# Platform-specific builds that can only be built on the target platform
build-darwin-amd64-webauthn:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-amd64-webauthn .

build-darwin-arm64-webauthn:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-darwin-arm64-webauthn .

build-linux-amd64-webauthn:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64-webauthn .

build-linux-arm64-webauthn:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-arm64-webauthn .

# Build all WebAuthn variants
build-all-webauthn: download-certs build-darwin-amd64-webauthn build-darwin-arm64-webauthn build-linux-amd64-webauthn build-linux-arm64-webauthn

# Docker targets (without WebAuthn by default for smaller image)
docker-build:
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

# Docker with WebAuthn support
docker-build-webauthn:
	docker build --build-arg ENABLE_WEBAUTHN=true -t $(IMAGE_NAME):$(VERSION)-webauthn -t $(IMAGE_NAME):latest-webauthn .

docker-push:
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest
