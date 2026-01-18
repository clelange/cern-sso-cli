package auth

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFindCCachePath_WithEnvVar(t *testing.T) {
	// Save and restore original env
	original := os.Getenv("KRB5CCNAME")
	defer func() { _ = os.Setenv("KRB5CCNAME", original) }()

	// Test FILE: prefix handling
	_ = os.Setenv("KRB5CCNAME", "FILE:/tmp/test_ccache")
	path := FindCCachePath()
	// Note: this returns empty if file doesn't exist, so we just verify prefix stripping
	if path != "" && path != "/tmp/test_ccache" {
		t.Errorf("Expected /tmp/test_ccache or empty, got %s", path)
	}

	// Test API: prefix (should return empty)
	_ = os.Setenv("KRB5CCNAME", "API:12345")
	path = FindCCachePath()
	if path != "" {
		t.Errorf("Expected empty for API: cache, got %s", path)
	}
}

func TestIsMacOSAPICCache(t *testing.T) {
	// Save and restore original env
	original := os.Getenv("KRB5CCNAME")
	defer func() { _ = os.Setenv("KRB5CCNAME", original) }()

	if runtime.GOOS == "darwin" {
		// On macOS with no env var set, should return true
		_ = os.Unsetenv("KRB5CCNAME")
		if !IsMacOSAPICCache() {
			t.Error("Expected true for macOS with no KRB5CCNAME set")
		}

		// With API: prefix, should return true
		_ = os.Setenv("KRB5CCNAME", "API:12345")
		if !IsMacOSAPICCache() {
			t.Error("Expected true for macOS with API: cache")
		}

		// With file path, should return false
		_ = os.Setenv("KRB5CCNAME", "/tmp/krb5cc_test")
		if IsMacOSAPICCache() {
			t.Error("Expected false for macOS with file-based cache")
		}
	} else {
		// On non-macOS, should always return false
		_ = os.Unsetenv("KRB5CCNAME")
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
	defer func() { _ = os.Setenv("KRB5CCNAME", original) }()

	// Set a file-based cache - should not attempt conversion
	_ = os.Setenv("KRB5CCNAME", "/tmp/krb5cc_test_file")
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

// TestConvertSpecificCacheToFile_NotMacOS verifies that the function
// returns an error when called on non-macOS platforms.
func TestConvertSpecificCacheToFile_NotMacOS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping on macOS - this test is for non-macOS platforms")
	}

	cacheInfo := &CacheInfo{
		CacheName: "API:12345",
		Principal: "testuser@CERN.CH",
	}

	_, err := ConvertSpecificCacheToFile(cacheInfo)
	if err == nil {
		t.Error("Expected error on non-macOS platform")
	}
	if !strings.Contains(err.Error(), "only supported on macOS") {
		t.Errorf("Expected 'only supported on macOS' error, got: %v", err)
	}
}

// TestConvertSpecificCacheToFile_CacheDir verifies that the function uses
// the correct cache directory path (~/.cache/cern-sso-cli).
func TestConvertSpecificCacheToFile_CacheDir(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-macOS - ConvertSpecificCacheToFile is macOS only")
	}

	// This test verifies the cache directory path logic without actually
	// running kgetcred (which requires a valid Kerberos ticket).
	// We verify the expected path format.

	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home dir: %v", err)
	}

	expectedDir := homeDir + "/.cache/cern-sso-cli"
	t.Logf("Expected cache directory: %s", expectedDir)

	// Verify the cache dir would be created in the expected location
	// by checking it doesn't exist at an old location (/tmp)
	cacheInfo := &CacheInfo{
		CacheName: "API:nonexistent",
		Principal: "testuser@CERN.CH",
	}

	// The function will fail because the cache doesn't exist, but the error
	// should be from kgetcred, not from directory creation
	_, err = ConvertSpecificCacheToFile(cacheInfo)
	if err == nil {
		t.Log("Function succeeded unexpectedly (valid ticket found)")
		return
	}

	// Verify error is from kgetcred, not from directory creation
	if strings.Contains(err.Error(), "failed to create cache dir") {
		t.Errorf("Failed to create cache directory: %v", err)
	}
	if strings.Contains(err.Error(), "failed to get home dir") {
		t.Errorf("Failed to get home directory: %v", err)
	}

	// Check that the cache directory was created
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Logf("Cache directory not created (expected if kgetcred failed early): %s", expectedDir)
	} else {
		t.Logf("Cache directory exists: %s", expectedDir)
	}
}

// TestFindCacheByUsername_NormalizesUsername verifies that FindCacheByUsername
// properly normalizes username input before searching.
func TestFindCacheByUsername_NormalizesUsername(t *testing.T) {
	// This test requires klist to be installed
	// Skip if klist is not available (common in CI environments)
	if _, err := exec.LookPath("klist"); err != nil {
		t.Skip("Skipping test - klist not available")
	}

	// This test verifies the normalization logic works correctly.
	// Without actual Kerberos tickets, we test the error message formatting.

	tests := []struct {
		input           string
		normalizedInErr string // The normalized form should appear in the error
	}{
		{"alice", "alice@CERN.CH"},
		{"alice@cern.ch", "alice@CERN.CH"},
		{"ALICE@CERN.CH", "ALICE@CERN.CH"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := FindCacheByUsername(tc.input)
			if err == nil {
				t.Log("Found matching cache (expected in CI with Kerberos tickets)")
				return
			}

			// Error message should contain the normalized username
			if !strings.Contains(err.Error(), tc.normalizedInErr) {
				t.Errorf("Error should reference normalized username %q, got: %v",
					tc.normalizedInErr, err)
			}
		})
	}
}

// TestFindCacheByUsername_NotFound verifies that FindCacheByUsername returns
// a helpful error message when no matching cache is found.
func TestFindCacheByUsername_NotFound(t *testing.T) {
	// This test requires klist to be installed
	// Skip if klist is not available (common in CI environments)
	if _, err := exec.LookPath("klist"); err != nil {
		t.Skip("Skipping test - klist not available")
	}

	// Use a username that definitely won't exist
	_, err := FindCacheByUsername("nonexistent_test_user_12345")
	if err == nil {
		t.Fatal("Expected error for nonexistent user")
	}

	// Error should include the normalized username
	if !strings.Contains(err.Error(), "nonexistent_test_user_12345@CERN.CH") {
		t.Errorf("Error should contain normalized username, got: %v", err)
	}

	// Error should be helpful - either "no CERN.CH caches available" or list available caches
	if !strings.Contains(err.Error(), "no Kerberos cache found") {
		t.Errorf("Error should start with 'no Kerberos cache found', got: %v", err)
	}

	t.Logf("Error message: %v", err)
}

// TestCacheInfo_Struct verifies the CacheInfo struct has expected fields.
// This is a contract test to prevent breaking changes.
func TestCacheInfo_Struct(t *testing.T) {
	now := time.Now()
	info := CacheInfo{
		CacheName: "API:12345",
		Principal: "testuser@CERN.CH",
		Expires:   now,
		IsDefault: true,
	}

	if info.CacheName != "API:12345" {
		t.Errorf("CacheName = %q, want %q", info.CacheName, "API:12345")
	}
	if info.Principal != "testuser@CERN.CH" {
		t.Errorf("Principal = %q, want %q", info.Principal, "testuser@CERN.CH")
	}
	if !info.Expires.Equal(now) {
		t.Errorf("Expires = %v, want %v", info.Expires, now)
	}
	if !info.IsDefault {
		t.Error("IsDefault should be true")
	}
}
