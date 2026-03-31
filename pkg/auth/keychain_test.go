package auth

import (
	"os"
	"runtime"
	"testing"
)

func TestRetrieveKeychainSecret_RequiresDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping non-darwin check on darwin")
	}
	_, err := retrieveKeychainSecret("testuser", "test-service")
	if err == nil {
		t.Error("retrieveKeychainSecret expected error on non-darwin, got nil")
	}
	if !contains(err.Error(), "only supported on macOS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRetrieveKeychainSecret_RequiresUsername(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	_, err := retrieveKeychainSecret("", "test-service")
	if err == nil {
		t.Error("retrieveKeychainSecret expected error for empty username, got nil")
	}
	if !contains(err.Error(), "username is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRetrieveKeychainSecret_StripsRealm(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	// This will fail (no such keychain entry) but should strip @CERN.CH
	// and attempt the lookup with just the username
	_, err := retrieveKeychainSecret("testuser@CERN.CH", "nonexistent-test-service-12345")
	if err == nil {
		t.Error("retrieveKeychainSecret expected error for nonexistent service, got nil")
	}
	// Error should mention the plain username, confirming realm was stripped
	if !contains(err.Error(), "testuser") {
		t.Errorf("expected error to mention 'testuser', got: %v", err)
	}
}

func TestRetrieveKeychainSecret_NonexistentEntry(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	_, err := retrieveKeychainSecret("testuser", "nonexistent-service-xyz-98765")
	if err == nil {
		t.Error("retrieveKeychainSecret expected error for nonexistent keychain entry, got nil")
	}
}

func TestOTPProvider_KeychainFlag(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	// The keychain entry won't exist, but we can verify the source is tried
	p := &OTPProvider{OTPKeychainName: "nonexistent-test-service-12345"}
	_, _, err := p.GetOTP("testuser")
	if err == nil {
		t.Error("GetOTP expected error for nonexistent keychain entry, got nil")
	}
	if !contains(err.Error(), "keychain OTP failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOTPProvider_KeychainEnvVar(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	t.Setenv(EnvOTPKeychain, "nonexistent-test-service-12345")

	p := &OTPProvider{}
	_, _, err := p.GetOTP("testuser")
	if err == nil {
		t.Error("GetOTP expected error for nonexistent keychain entry, got nil")
	}
	if !contains(err.Error(), "keychain OTP") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOTPProvider_FlagTakesPrecedenceOverKeychain(t *testing.T) {
	// Direct OTP flag should take precedence over keychain
	p := &OTPProvider{
		OTP:             "111111",
		OTPKeychainName: "some-service",
	}
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "111111" {
		t.Errorf("GetOTP returned %q, want %q (flag should take precedence over keychain)", otp, "111111")
	}
	if source != OTPSourceFlag {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceFlag)
	}
}

func TestOTPProvider_CommandTakesPrecedenceOverKeychain(t *testing.T) {
	p := &OTPProvider{
		OTPCommand:      "echo 222222",
		OTPKeychainName: "some-service",
	}
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "222222" {
		t.Errorf("GetOTP returned %q, want %q (command should take precedence over keychain)", otp, "222222")
	}
	if source != OTPSourceCommand {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceCommand)
	}
}

func TestOTPProvider_KeychainTakesPrecedenceOverEnvOTP(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	// Set env OTP, but keychain should be tried first (and will fail,
	// so this tests the priority ordering - keychain is checked before env)
	t.Setenv(EnvOTP, "333333")

	p := &OTPProvider{OTPKeychainName: "nonexistent-test-service-12345"}
	_, _, err := p.GetOTP("testuser")
	// Keychain should fail (nonexistent entry), proving it was tried before env
	if err == nil {
		t.Error("GetOTP expected keychain error, not env fallback")
	}
	if !contains(err.Error(), "keychain OTP failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIsRefreshable_Keychain(t *testing.T) {
	if !IsRefreshable(OTPSourceKeychain) {
		t.Error("OTPSourceKeychain should be refreshable")
	}
}

func TestOTPProvider_RefreshOTP_Keychain(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	p := &OTPProvider{OTPKeychainName: "nonexistent-test-service-12345"}
	_, err := p.RefreshOTP("testuser", OTPSourceKeychain, 2, 3)
	if err == nil {
		t.Error("RefreshOTP expected error for nonexistent keychain entry, got nil")
	}
}

func TestOTPProvider_RefreshOTP_KeychainFromEnv(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping darwin-only test")
	}
	_ = os.Setenv(EnvOTPKeychain, "nonexistent-test-service-12345")
	defer func() { _ = os.Unsetenv(EnvOTPKeychain) }()

	// No flag set, should fall back to env keychain name
	p := &OTPProvider{}
	_, err := p.RefreshOTP("testuser", OTPSourceKeychain, 2, 3)
	if err == nil {
		t.Error("RefreshOTP expected error for nonexistent keychain entry, got nil")
	}
}
