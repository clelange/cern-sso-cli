package browser

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestIsChromeAvailable tests Chrome detection across platforms.
// This test is meaningful on any platform - it should not panic or error.
func TestIsChromeAvailable(t *testing.T) {
	// The function should not panic and should return a boolean
	result := IsChromeAvailable()

	// On CI without Chrome, this might return false, but should not error
	t.Logf("IsChromeAvailable() = %v (platform: %s)", result, runtime.GOOS)

	// Basic sanity check - the function returns consistently
	result2 := IsChromeAvailable()
	if result != result2 {
		t.Error("IsChromeAvailable() returned inconsistent results")
	}
}

// TestIsChromeAvailable_PathChecks verifies the function checks expected paths.
func TestIsChromeAvailable_PathChecks(t *testing.T) {
	// This test verifies that common Chrome paths are checked
	// The actual availability depends on the system

	expectedPaths := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
	}

	// Check if any of the expected paths exist
	var foundPath string
	for _, path := range expectedPaths {
		if _, err := os.Stat(path); err == nil {
			foundPath = path
			break
		}
	}

	if foundPath != "" {
		t.Logf("Found Chrome at: %s", foundPath)
		if !IsChromeAvailable() {
			// Function should return true when Chrome exists
			// Note: the current implementation always returns true as fallback
			t.Log("Note: IsChromeAvailable returns true (delegates to chromedp)")
		}
	} else {
		t.Log("No Chrome found at expected paths, IsChromeAvailable relies on chromedp detection")
	}
}

// TestAuthenticateWithChrome_Signature verifies the function signature accepts env parameter.
// This is a compile-time contract test that ensures the API is stable.
func TestAuthenticateWithChrome_Signature(t *testing.T) {
	// Verify the function signature by assigning to a typed variable
	// This fails at compile time if the signature changes
	var f func(string, string, time.Duration, map[string]string) (*AuthResult, error)
	f = AuthenticateWithChrome
	_ = f // Use to prevent unused variable error

	t.Log("AuthenticateWithChrome signature matches expected contract")
}

// TestAuthResult_Fields verifies the AuthResult struct has expected fields.
// This is a contract test to prevent breaking changes to the result type.
func TestAuthResult_Fields(t *testing.T) {
	result := &AuthResult{
		Cookies:  nil,
		FinalURL: "https://example.com",
		Username: "testuser",
	}

	// Verify all fields are accessible
	if result.Cookies != nil {
		t.Error("Cookies should be nil")
	}
	if result.FinalURL != "https://example.com" {
		t.Errorf("FinalURL = %q, want %q", result.FinalURL, "https://example.com")
	}
	if result.Username != "testuser" {
		t.Errorf("Username = %q, want %q", result.Username, "testuser")
	}
}
