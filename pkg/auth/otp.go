package auth

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OTP source priority constants
const (
	OTPSourceFlag    = "flag"
	OTPSourceCommand = "command"
	OTPSourceEnv     = "env"
	OTPSourcePrompt  = "prompt"
)

// Environment variable names for OTP configuration
const (
	EnvOTP        = "CERN_SSO_OTP"
	EnvOTPCommand = "CERN_SSO_OTP_COMMAND"
)

// OTPProvider handles OTP code retrieval from various sources.
// It checks sources in priority order: flag > command > env > prompt.
type OTPProvider struct {
	OTP        string // Direct OTP value (from --otp flag or CERN_SSO_OTP)
	OTPCommand string // Command to execute (from --otp-command flag or CERN_SSO_OTP_COMMAND)
	MaxRetries int    // Maximum retry attempts (default: 3)
}

// GetOTP retrieves an OTP code using the configured sources.
// It tries sources in priority order:
//  1. Direct OTP value (p.OTP)
//  2. OTP command (p.OTPCommand)
//  3. CERN_SSO_OTP environment variable
//  4. CERN_SSO_OTP_COMMAND environment variable
//  5. Interactive prompt (fallback)
//
// Returns the OTP code and the source it was retrieved from.
func (p *OTPProvider) GetOTP(username string) (string, string, error) {
	// Priority 1: Direct OTP from flag
	if p.OTP != "" {
		otp, err := validateOTP(p.OTP)
		if err != nil {
			return "", "", fmt.Errorf("invalid OTP from flag: %w", err)
		}
		return otp, OTPSourceFlag, nil
	}

	// Priority 2: OTP command from flag
	if p.OTPCommand != "" {
		otp, err := executeOTPCommand(p.OTPCommand)
		if err != nil {
			return "", "", fmt.Errorf("OTP command failed: %w", err)
		}
		return otp, OTPSourceCommand, nil
	}

	// Priority 3: CERN_SSO_OTP environment variable
	if envOTP := os.Getenv(EnvOTP); envOTP != "" {
		otp, err := validateOTP(envOTP)
		if err != nil {
			return "", "", fmt.Errorf("invalid OTP from %s: %w", EnvOTP, err)
		}
		return otp, OTPSourceEnv, nil
	}

	// Priority 4: CERN_SSO_OTP_COMMAND environment variable
	if envCmd := os.Getenv(EnvOTPCommand); envCmd != "" {
		otp, err := executeOTPCommand(envCmd)
		if err != nil {
			return "", "", fmt.Errorf("OTP command from %s failed: %w", EnvOTPCommand, err)
		}
		return otp, OTPSourceEnv, nil
	}

	// Priority 5: Interactive prompt
	otp, err := promptForOTPInteractive(username)
	if err != nil {
		return "", "", err
	}
	return otp, OTPSourcePrompt, nil
}

// executeOTPCommand runs a shell command and returns its output as an OTP.
func executeOTPCommand(command string) (string, error) {
	// Use shell to execute the command (supports pipes, etc.)
	// Command is user-configured via CERN_SSO_OTP_COMMAND environment variable
	cmd := exec.Command("sh", "-c", command) // #nosec G702,G204
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("command exited with status %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return "", err
	}

	otp := strings.TrimSpace(string(output))
	return validateOTP(otp)
}

// validateOTP validates that the OTP is a 6-digit code.
func validateOTP(otp string) (string, error) {
	otp = strings.TrimSpace(otp)
	if len(otp) != 6 {
		return "", fmt.Errorf("OTP must be 6 digits, got %d characters", len(otp))
	}
	for _, c := range otp {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("OTP must contain only digits")
		}
	}
	return otp, nil
}

// promptForOTPInteractive prompts the user interactively for an OTP code.
func promptForOTPInteractive(username string) (string, error) {
	if username != "" {
		fmt.Printf("Enter your 6-digit OTP code for %s: ", username)
	} else {
		fmt.Print("Enter your 6-digit OTP code: ")
	}
	var code string
	_, err := fmt.Scanln(&code)
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return validateOTP(code)
}

// GetMaxRetries returns the configured max retries, defaulting to 3.
func (p *OTPProvider) GetMaxRetries() int {
	if p.MaxRetries <= 0 {
		return 3 // Default
	}
	return p.MaxRetries
}

// RefreshOTP gets a fresh OTP for retry attempts.
// For command sources, it waits for TOTP window rollover then re-executes.
// For interactive sources, it re-prompts the user.
// For static flag sources, it returns an error (cannot refresh).
func (p *OTPProvider) RefreshOTP(username string, source string, attempt, maxRetries int) (string, error) {
	switch source {
	case OTPSourceFlag:
		// Static flag value cannot be refreshed
		return "", fmt.Errorf("cannot refresh static OTP value from --otp flag")

	case OTPSourceCommand:
		// Re-execute the command (already waited in caller)
		return executeOTPCommand(p.OTPCommand)

	case OTPSourceEnv:
		// Check if it's a command from env or static value
		if envCmd := os.Getenv(EnvOTPCommand); envCmd != "" {
			return executeOTPCommand(envCmd)
		}
		// Static env value cannot be refreshed
		return "", fmt.Errorf("cannot refresh static OTP value from %s", EnvOTP)

	case OTPSourcePrompt:
		// Re-prompt the user
		fmt.Printf("Invalid OTP. Try again (%d/%d): ", attempt, maxRetries)
		var code string
		_, err := fmt.Scanln(&code)
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		return validateOTP(code)

	default:
		return "", fmt.Errorf("unknown OTP source: %s", source)
	}
}

// IsRefreshable returns true if the OTP source supports refresh/retry.
func IsRefreshable(source string) bool {
	return source == OTPSourceCommand || source == OTPSourcePrompt ||
		(source == OTPSourceEnv && os.Getenv(EnvOTPCommand) != "")
}
