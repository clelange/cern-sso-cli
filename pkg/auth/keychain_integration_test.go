//go:build integration && darwin

// Package auth provides integration tests for keychain-based TOTP generation.
// These tests write and read from the macOS Keychain and require:
// - macOS (darwin)
// - The `security` command-line tool
//
// Run with: go test -tags=integration -v -run TestIntegration_Keychain ./pkg/auth/
package auth

import (
	"os/exec"
	"testing"
	"time"
)

const (
	testKeychainService = "cern-sso-cli-test-otp"
	testKeychainAccount = "testuser"
	// RFC 6238 test secret: "12345678901234567890" in base32
	testKeychainSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

func TestIntegration_KeychainTOTP(t *testing.T) {
	// Store a known secret in the keychain
	addSecret(t)
	defer removeSecret(t)

	// Generate OTP via the keychain path
	otp, err := GenerateKeychainOTP(testKeychainAccount, testKeychainService)
	if err != nil {
		t.Fatalf("GenerateKeychainOTP failed: %v", err)
	}

	// Verify format: 6 digits
	if len(otp) != 6 {
		t.Errorf("OTP length = %d, want 6", len(otp))
	}
	for _, c := range otp {
		if c < '0' || c > '9' {
			t.Errorf("OTP contains non-digit character: %c", c)
		}
	}

	// Verify it matches what GenerateTOTP would produce directly
	expected, err := GenerateTOTP(testKeychainSecret)
	if err != nil {
		t.Fatalf("GenerateTOTP failed: %v", err)
	}
	if otp != expected {
		t.Errorf("Keychain OTP = %q, direct TOTP = %q — mismatch", otp, expected)
	}

	t.Logf("Generated OTP %s from keychain at %s", otp, time.Now().Format(time.RFC3339))
}

func TestIntegration_KeychainOTPProvider(t *testing.T) {
	// Store a known secret in the keychain
	addSecret(t)
	defer removeSecret(t)

	// Use the OTPProvider with keychain
	p := &OTPProvider{OTPKeychainName: testKeychainService}
	otp, source, err := p.GetOTP(testKeychainAccount)
	if err != nil {
		t.Fatalf("GetOTP with keychain failed: %v", err)
	}

	if source != OTPSourceKeychain {
		t.Errorf("source = %q, want %q", source, OTPSourceKeychain)
	}

	if len(otp) != 6 {
		t.Errorf("OTP length = %d, want 6", len(otp))
	}

	t.Logf("OTPProvider returned OTP %s from source %s", otp, source)
}

func TestIntegration_KeychainRefresh(t *testing.T) {
	addSecret(t)
	defer removeSecret(t)

	p := &OTPProvider{OTPKeychainName: testKeychainService}
	otp, err := p.RefreshOTP(testKeychainAccount, OTPSourceKeychain, 1, 3)
	if err != nil {
		t.Fatalf("RefreshOTP with keychain failed: %v", err)
	}

	if len(otp) != 6 {
		t.Errorf("Refreshed OTP length = %d, want 6", len(otp))
	}

	t.Logf("RefreshOTP returned OTP %s", otp)
}

func TestIntegration_KeychainWithRealm(t *testing.T) {
	addSecret(t)
	defer removeSecret(t)

	// Username with @CERN.CH realm should be stripped
	otp, err := GenerateKeychainOTP(testKeychainAccount+"@CERN.CH", testKeychainService)
	if err != nil {
		t.Fatalf("GenerateKeychainOTP with realm failed: %v", err)
	}

	if len(otp) != 6 {
		t.Errorf("OTP length = %d, want 6", len(otp))
	}

	t.Logf("Generated OTP %s using username with realm suffix", otp)
}

// addSecret stores the test secret in the macOS Keychain.
func addSecret(t *testing.T) {
	t.Helper()
	// Remove any existing entry first (ignore errors)
	_ = exec.Command("security", "delete-generic-password", "-a", testKeychainAccount, "-s", testKeychainService).Run()

	cmd := exec.Command("security", "add-generic-password",
		"-a", testKeychainAccount,
		"-s", testKeychainService,
		"-l", "cern-sso-cli test OTP secret",
		"-w", testKeychainSecret,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to add test secret to keychain: %v\nOutput: %s", err, output)
	}
}

// removeSecret removes the test secret from the macOS Keychain.
func removeSecret(t *testing.T) {
	t.Helper()
	cmd := exec.Command("security", "delete-generic-password",
		"-a", testKeychainAccount,
		"-s", testKeychainService,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("Warning: Failed to remove test secret from keychain: %v\nOutput: %s", err, output)
	}
}
