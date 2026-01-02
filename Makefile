BINARY_NAME=cern-sso-cli
# Get version from git tag, or fallback to short hash + dirty flag
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: all build clean test-integration build-all

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

# Cross-platform builds
build-all: build-darwin-amd64 build-darwin-arm64 build-linux-amd64 build-linux-arm64

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -o dist/$(BINARY_NAME)-darwin-amd64 .

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o dist/$(BINARY_NAME)-darwin-arm64 .

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o dist/$(BINARY_NAME)-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o dist/$(BINARY_NAME)-linux-arm64 .
