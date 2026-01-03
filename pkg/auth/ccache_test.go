package auth

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestFindCCachePath_WithEnvVar(t *testing.T) {
	// Save and restore original env
	original := os.Getenv("KRB5CCNAME")
	defer os.Setenv("KRB5CCNAME", original)

	// Test FILE: prefix handling
	os.Setenv("KRB5CCNAME", "FILE:/tmp/test_ccache")
	path := FindCCachePath()
	// Note: this returns empty if file doesn't exist, so we just verify prefix stripping
	if path != "" && path != "/tmp/test_ccache" {
		t.Errorf("Expected /tmp/test_ccache or empty, got %s", path)
	}

	// Test API: prefix (should return empty)
	os.Setenv("KRB5CCNAME", "API:12345")
	path = FindCCachePath()
	if path != "" {
		t.Errorf("Expected empty for API: cache, got %s", path)
	}
}

func TestIsMacOSAPICCache(t *testing.T) {
	// Save and restore original env
	original := os.Getenv("KRB5CCNAME")
	defer os.Setenv("KRB5CCNAME", original)

	if runtime.GOOS == "darwin" {
		// On macOS with no env var set, should return true
		os.Unsetenv("KRB5CCNAME")
		if !IsMacOSAPICCache() {
			t.Error("Expected true for macOS with no KRB5CCNAME set")
		}

		// With API: prefix, should return true
		os.Setenv("KRB5CCNAME", "API:12345")
		if !IsMacOSAPICCache() {
			t.Error("Expected true for macOS with API: cache")
		}

		// With file path, should return false
		os.Setenv("KRB5CCNAME", "/tmp/krb5cc_test")
		if IsMacOSAPICCache() {
			t.Error("Expected false for macOS with file-based cache")
		}
	} else {
		// On non-macOS, should always return false
		os.Unsetenv("KRB5CCNAME")
		if IsMacOSAPICCache() {
			t.Error("Expected false on non-macOS platform")
		}
	}
}

func TestGetUID(t *testing.T) {
	uid := getUID()
	if uid == "" {
		t.Error("Expected non-empty UID")
	}
}

func TestConvertAPICacheToFile_NotMacOS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping on macOS - this test is for non-macOS platforms")
	}

	// On non-macOS, should return error because IsMacOSAPICCache returns false
	_, err := ConvertAPICacheToFile()
	if err == nil {
		t.Error("Expected error on non-macOS platform")
	}
	if !strings.Contains(err.Error(), "not using macOS API cache") {
		t.Errorf("Expected 'not using macOS API cache' error, got: %v", err)
	}
}

func TestConvertAPICacheToFile_WithFileCache(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-macOS - testing file cache detection on darwin")
	}

	// Save and restore original env
	original := os.Getenv("KRB5CCNAME")
	defer os.Setenv("KRB5CCNAME", original)

	// Set a file-based cache - should not attempt conversion
	os.Setenv("KRB5CCNAME", "/tmp/krb5cc_test_file")
	_, err := ConvertAPICacheToFile()
	if err == nil {
		t.Error("Expected error when already using file-based cache")
	}
	if !strings.Contains(err.Error(), "not using macOS API cache") {
		t.Errorf("Expected 'not using macOS API cache' error, got: %v", err)
	}
}

func TestNormalizePrincipal(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"alice", "alice@CERN.CH"},
		{"alice@CERN.CH", "alice@CERN.CH"},
		{"alice@cern.ch", "alice@CERN.CH"},
		{"BOB@cern.ch", "BOB@CERN.CH"},
		{"bob", "bob@CERN.CH"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := NormalizePrincipal(tc.input)
			if result != tc.expected {
				t.Errorf("NormalizePrincipal(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}
