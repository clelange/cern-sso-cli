BINARY_NAME=cern-sso-cli
# Get version from git tag, or fallback to short hash + dirty flag
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
# Container image name (override with IMAGE_NAME=ghcr.io/user/repo make docker-build)
IMAGE_NAME ?= cern-sso-cli

.PHONY: all build clean test-integration build-all download-certs docker-build docker-push

all: build

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .

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

# Cross-platform builds
build-all: download-certs build-darwin-amd64 build-darwin-arm64 build-linux-amd64 build-linux-arm64

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)-darwin-amd64 .

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)-darwin-arm64 .

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o dist/$(BINARY_NAME)-linux-arm64 .

# Docker targets
docker-build:
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-push:
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest

