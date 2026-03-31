package auth

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// OTPKeychainService is the keychain service name for OTP secrets.
const OTPKeychainService = "cern-otp"

// Environment variable for keychain-based OTP
const EnvOTPKeychain = "CERN_SSO_OTP_KEYCHAIN"

func validateKeychainLookupArg(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required for keychain OTP", name)
	}

	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%s contains unsupported control characters", name)
		}
	}

	return value, nil
}

// retrieveKeychainSecret retrieves an OTP secret from the macOS Keychain.
// It uses the `security` command-line tool to find a generic password
// matching the given account and service name.
func retrieveKeychainSecret(account, service string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("keychain OTP is only supported on macOS")
	}

	if account == "" {
		return "", fmt.Errorf("username is required for keychain OTP (use --user or Kerberos)")
	}

	// Strip @CERN.CH realm suffix if present
	if idx := strings.Index(account, "@"); idx != -1 {
		account = account[:idx]
	}

	account, err := validateKeychainLookupArg("username", account)
	if err != nil {
		return "", err
	}
	service, err = validateKeychainLookupArg("service name", service)
	if err != nil {
		return "", err
	}

	// Use macOS `security` to find the generic password
	// security find-generic-password -a <account> -s <service> -w
	cmd := exec.Command("security", "find-generic-password", "-a", account, "-s", service, "-w") // #nosec G204,G702 -- arguments are validated and passed directly as argv, not through a shell
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return "", fmt.Errorf("failed to retrieve OTP secret from keychain (service=%q, account=%q): %s: %w", service, account, detail, err)
		}
		return "", fmt.Errorf("failed to retrieve OTP secret from keychain (service=%q, account=%q): %w", service, account, err)
	}

	secret := strings.TrimSpace(string(output))
	if secret == "" {
		return "", fmt.Errorf("empty OTP secret in keychain (service=%q, account=%q)", service, account)
	}

	return secret, nil
}

// GenerateKeychainOTP retrieves a TOTP secret from the macOS Keychain and
// generates a 6-digit OTP code from it.
func GenerateKeychainOTP(username, service string) (string, error) {
	secret, err := retrieveKeychainSecret(username, service)
	if err != nil {
		return "", err
	}
	return GenerateTOTP(secret)
}
