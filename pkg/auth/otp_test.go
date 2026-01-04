package auth

import (
	"os"
	"testing"
)

func TestValidateOTP_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"123456", "123456"},
		{" 123456 ", "123456"}, // with whitespace
		{"000000", "000000"},
		{"999999", "999999"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result, err := validateOTP(tc.input)
			if err != nil {
				t.Errorf("validateOTP(%q) returned error: %v", tc.input, err)
			}
			if result != tc.expected {
				t.Errorf("validateOTP(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestValidateOTP_Invalid(t *testing.T) {
	tests := []struct {
		input   string
		wantErr string
	}{
		{"12345", "OTP must be 6 digits"},
		{"1234567", "OTP must be 6 digits"},
		{"", "OTP must be 6 digits"},
		{"abcdef", "OTP must contain only digits"},
		{"12345a", "OTP must contain only digits"},
		{"12 345", "OTP must contain only digits"}, // space in middle
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			_, err := validateOTP(tc.input)
			if err == nil {
				t.Errorf("validateOTP(%q) expected error, got nil", tc.input)
				return
			}
			if !contains(err.Error(), tc.wantErr) {
				t.Errorf("validateOTP(%q) error = %q, want to contain %q", tc.input, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestExecuteOTPCommand_Success(t *testing.T) {
	// Test with echo command
	otp, err := executeOTPCommand("echo 123456")
	if err != nil {
		t.Fatalf("executeOTPCommand failed: %v", err)
	}
	if otp != "123456" {
		t.Errorf("executeOTPCommand returned %q, want %q", otp, "123456")
	}
}

func TestExecuteOTPCommand_WithWhitespace(t *testing.T) {
	// Command output with newline should be trimmed
	otp, err := executeOTPCommand("echo '  654321  '")
	if err != nil {
		t.Fatalf("executeOTPCommand failed: %v", err)
	}
	if otp != "654321" {
		t.Errorf("executeOTPCommand returned %q, want %q", otp, "654321")
	}
}

func TestExecuteOTPCommand_InvalidOutput(t *testing.T) {
	// Command returns invalid OTP
	_, err := executeOTPCommand("echo 'not-an-otp'")
	if err == nil {
		t.Error("executeOTPCommand expected error for invalid OTP, got nil")
	}
}

func TestExecuteOTPCommand_CommandFailure(t *testing.T) {
	// Command that fails
	_, err := executeOTPCommand("exit 1")
	if err == nil {
		t.Error("executeOTPCommand expected error for failed command, got nil")
	}
}

func TestExecuteOTPCommand_NonexistentCommand(t *testing.T) {
	// Non-existent command
	_, err := executeOTPCommand("nonexistent-command-12345")
	if err == nil {
		t.Error("executeOTPCommand expected error for nonexistent command, got nil")
	}
}

func TestOTPProvider_DirectOTP(t *testing.T) {
	p := &OTPProvider{OTP: "123456"}
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "123456" {
		t.Errorf("GetOTP returned %q, want %q", otp, "123456")
	}
	if source != OTPSourceFlag {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceFlag)
	}
}

func TestOTPProvider_Command(t *testing.T) {
	p := &OTPProvider{OTPCommand: "echo 654321"}
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "654321" {
		t.Errorf("GetOTP returned %q, want %q", otp, "654321")
	}
	if source != OTPSourceCommand {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceCommand)
	}
}

func TestOTPProvider_FlagTakesPrecedence(t *testing.T) {
	// Both flag and command set - flag should win
	p := &OTPProvider{
		OTP:        "111111",
		OTPCommand: "echo 222222",
	}
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "111111" {
		t.Errorf("GetOTP returned %q, want %q (flag should take precedence)", otp, "111111")
	}
	if source != OTPSourceFlag {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceFlag)
	}
}

func TestOTPProvider_EnvVar(t *testing.T) {
	// Set environment variable
	os.Setenv(EnvOTP, "333333")
	defer os.Unsetenv(EnvOTP)

	p := &OTPProvider{} // No flags set
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "333333" {
		t.Errorf("GetOTP returned %q, want %q", otp, "333333")
	}
	if source != OTPSourceEnv {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceEnv)
	}
}

func TestOTPProvider_EnvCommand(t *testing.T) {
	// Set environment variable for command
	os.Setenv(EnvOTPCommand, "echo 444444")
	defer os.Unsetenv(EnvOTPCommand)

	p := &OTPProvider{} // No flags set
	otp, source, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "444444" {
		t.Errorf("GetOTP returned %q, want %q", otp, "444444")
	}
	if source != OTPSourceEnv {
		t.Errorf("GetOTP source = %q, want %q", source, OTPSourceEnv)
	}
}

func TestOTPProvider_FlagOverridesEnv(t *testing.T) {
	// Set environment variable
	os.Setenv(EnvOTP, "555555")
	defer os.Unsetenv(EnvOTP)

	// Flag should override env
	p := &OTPProvider{OTP: "666666"}
	otp, _, err := p.GetOTP("testuser")
	if err != nil {
		t.Fatalf("GetOTP failed: %v", err)
	}
	if otp != "666666" {
		t.Errorf("GetOTP returned %q, want %q (flag should override env)", otp, "666666")
	}
}

func TestOTPProvider_InvalidDirectOTP(t *testing.T) {
	p := &OTPProvider{OTP: "bad"}
	_, _, err := p.GetOTP("testuser")
	if err == nil {
		t.Error("GetOTP expected error for invalid OTP, got nil")
	}
}

func TestOTPProvider_InvalidCommandOutput(t *testing.T) {
	p := &OTPProvider{OTPCommand: "echo invalid"}
	_, _, err := p.GetOTP("testuser")
	if err == nil {
		t.Error("GetOTP expected error for invalid command output, got nil")
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Tests for OTP retry functionality

func TestOTPProvider_GetMaxRetries_Default(t *testing.T) {
	p := &OTPProvider{}
	if p.GetMaxRetries() != 3 {
		t.Errorf("GetMaxRetries() = %d, want 3 (default)", p.GetMaxRetries())
	}
}

func TestOTPProvider_GetMaxRetries_Configured(t *testing.T) {
	p := &OTPProvider{MaxRetries: 5}
	if p.GetMaxRetries() != 5 {
		t.Errorf("GetMaxRetries() = %d, want 5", p.GetMaxRetries())
	}
}

func TestOTPProvider_GetMaxRetries_ZeroDefault(t *testing.T) {
	p := &OTPProvider{MaxRetries: 0}
	if p.GetMaxRetries() != 3 {
		t.Errorf("GetMaxRetries() = %d, want 3 (default for zero)", p.GetMaxRetries())
	}
}

func TestOTPProvider_RefreshOTP_Command(t *testing.T) {
	p := &OTPProvider{OTPCommand: "echo 789012"}
	otp, err := p.RefreshOTP("testuser", OTPSourceCommand, 2, 3)
	if err != nil {
		t.Fatalf("RefreshOTP failed: %v", err)
	}
	if otp != "789012" {
		t.Errorf("RefreshOTP returned %q, want %q", otp, "789012")
	}
}

func TestOTPProvider_RefreshOTP_StaticFlagFails(t *testing.T) {
	p := &OTPProvider{OTP: "123456"}
	_, err := p.RefreshOTP("testuser", OTPSourceFlag, 2, 3)
	if err == nil {
		t.Error("RefreshOTP expected error for static flag, got nil")
	}
	if !contains(err.Error(), "cannot refresh static OTP") {
		t.Errorf("RefreshOTP error = %q, want to contain 'cannot refresh static OTP'", err.Error())
	}
}

func TestOTPProvider_RefreshOTP_StaticEnvFails(t *testing.T) {
	// Set static env (not command)
	os.Setenv(EnvOTP, "123456")
	os.Unsetenv(EnvOTPCommand)
	defer os.Unsetenv(EnvOTP)

	p := &OTPProvider{}
	_, err := p.RefreshOTP("testuser", OTPSourceEnv, 2, 3)
	if err == nil {
		t.Error("RefreshOTP expected error for static env, got nil")
	}
}

func TestOTPProvider_RefreshOTP_EnvCommand(t *testing.T) {
	os.Setenv(EnvOTPCommand, "echo 345678")
	defer os.Unsetenv(EnvOTPCommand)

	p := &OTPProvider{}
	otp, err := p.RefreshOTP("testuser", OTPSourceEnv, 2, 3)
	if err != nil {
		t.Fatalf("RefreshOTP failed: %v", err)
	}
	if otp != "345678" {
		t.Errorf("RefreshOTP returned %q, want %q", otp, "345678")
	}
}

func TestIsRefreshable(t *testing.T) {
	tests := []struct {
		source      string
		envCmd      string
		refreshable bool
	}{
		{OTPSourceCommand, "", true},
		{OTPSourcePrompt, "", true},
		{OTPSourceFlag, "", false},
		{OTPSourceEnv, "echo 123456", true}, // With command env
		{OTPSourceEnv, "", false},           // Static env
	}

	for _, tc := range tests {
		os.Unsetenv(EnvOTPCommand)
		if tc.envCmd != "" {
			os.Setenv(EnvOTPCommand, tc.envCmd)
		}

		result := IsRefreshable(tc.source)
		if result != tc.refreshable {
			t.Errorf("IsRefreshable(%q) with envCmd=%q = %v, want %v", tc.source, tc.envCmd, result, tc.refreshable)
		}
	}
	os.Unsetenv(EnvOTPCommand)
}
