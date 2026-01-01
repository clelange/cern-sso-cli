package auth

import (
	"os"
	"runtime"
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
