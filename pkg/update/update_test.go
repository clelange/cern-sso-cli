// Package update provides self-update functionality for cern-sso-cli.
package update

import (
	"runtime"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		latest   string
		expected int
	}{
		{"equal versions", "v1.0.0", "v1.0.0", 0},
		{"current older", "v1.0.0", "v1.0.1", -1},
		{"current newer", "v1.0.1", "v1.0.0", 1},
		{"major difference", "v1.0.0", "v2.0.0", -1},
		{"minor difference", "v1.1.0", "v1.2.0", -1},
		{"dev is older", "dev", "v1.0.0", -1},
		{"dev-xxx is older", "dev-abc123", "v1.0.0", -1},
		{"latest dev means current is newer", "v1.0.0", "dev", 1},
		{"without v prefix", "1.0.0", "1.0.1", -1},
		{"mixed v prefix", "v1.0.0", "1.0.1", -1},
		{"pre-release ignored", "v1.0.0-rc1", "v1.0.0", 0},
		{"different lengths", "v1.0", "v1.0.0", 0},
		{"three digits newer", "v0.18.0", "v0.19.0", -1},
		{"three digits older", "v0.20.0", "v0.19.0", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersions(tt.current, tt.latest)
			if result != tt.expected {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.current, tt.latest, result, tt.expected)
			}
		})
	}
}

func TestGetAssetForCurrentPlatform(t *testing.T) {
	release := &ReleaseInfo{
		TagName: "v1.0.0",
		Assets: []ReleaseAsset{
			{Name: "cern-sso-cli-darwin-amd64", BrowserDownloadURL: "https://example.com/darwin-amd64"},
			{Name: "cern-sso-cli-darwin-arm64", BrowserDownloadURL: "https://example.com/darwin-arm64"},
			{Name: "cern-sso-cli-linux-amd64", BrowserDownloadURL: "https://example.com/linux-amd64"},
			{Name: "cern-sso-cli-linux-arm64", BrowserDownloadURL: "https://example.com/linux-arm64"},
			{Name: "cern-sso-cli-darwin-amd64-webauthn", BrowserDownloadURL: "https://example.com/darwin-amd64-webauthn"},
			{Name: "cern-sso-cli-darwin-arm64-webauthn", BrowserDownloadURL: "https://example.com/darwin-arm64-webauthn"},
			{Name: "cern-sso-cli-linux-amd64-webauthn", BrowserDownloadURL: "https://example.com/linux-amd64-webauthn"},
			{Name: "cern-sso-cli-linux-arm64-webauthn", BrowserDownloadURL: "https://example.com/linux-arm64-webauthn"},
			{Name: "checksums.txt", BrowserDownloadURL: "https://example.com/checksums.txt"},
		},
	}

	binaryURL, checksumURL, err := GetAssetForCurrentPlatform(release)
	if err != nil {
		t.Fatalf("GetAssetForCurrentPlatform() error = %v", err)
	}

	// Verify we get a URL for the current platform
	expectedPrefix := "https://example.com/" + runtime.GOOS + "-" + runtime.GOARCH
	if binaryURL == "" {
		t.Error("GetAssetForCurrentPlatform() binaryURL is empty")
	}
	if checksumURL != "https://example.com/checksums.txt" {
		t.Errorf("GetAssetForCurrentPlatform() checksumURL = %q, want %q", checksumURL, "https://example.com/checksums.txt")
	}
	t.Logf("Got binaryURL: %s (expected prefix: %s)", binaryURL, expectedPrefix)
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("test data")
	// SHA256 of "test data" is 916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9
	validChecksum := "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
	invalidChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	t.Run("valid checksum", func(t *testing.T) {
		if err := VerifyChecksum(data, validChecksum); err != nil {
			t.Errorf("VerifyChecksum() with valid checksum returned error: %v", err)
		}
	})

	t.Run("invalid checksum", func(t *testing.T) {
		if err := VerifyChecksum(data, invalidChecksum); err == nil {
			t.Error("VerifyChecksum() with invalid checksum should return error")
		}
	})
}

func TestIsHomebrewInstall(t *testing.T) {
	// This test mainly documents expected behaviour
	// Actual result depends on where the test binary is located
	result := IsHomebrewInstall()
	t.Logf("IsHomebrewInstall() = %v", result)
}
