package auth

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 - TOTP RFC 6238 specifies HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	// totpDigits is the number of digits in a TOTP code.
	totpDigits = 6
	// totpPeriod is the time step in seconds (standard TOTP).
	totpPeriod = 30
)

// timeNow and timeSleep are test hooks for time-dependent TOTP behavior.
var timeNow = time.Now
var timeSleep = time.Sleep

// timeUntilNextTOTPWindow returns the remaining time until the next TOTP step.
func timeUntilNextTOTPWindow(now time.Time) time.Duration {
	step := time.Duration(totpPeriod) * time.Second
	elapsed := time.Duration(now.UnixNano()) % step
	if elapsed == 0 {
		return 0
	}
	return step - elapsed
}

// waitForNextTOTPWindow sleeps until the next TOTP step and returns the delay.
func waitForNextTOTPWindow() time.Duration {
	delay := timeUntilNextTOTPWindow(timeNow())
	if delay > 0 {
		timeSleep(delay)
	}
	return delay
}

// GenerateTOTP generates a TOTP code from a base32-encoded secret.
// It implements RFC 6238 with HMAC-SHA1 (the standard for most authenticator apps),
// 6-digit codes, and a 30-second time step.
func GenerateTOTP(secret string) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode OTP secret: %w", err)
	}

	unixTime := timeNow().Unix()
	if unixTime < 0 {
		return "", fmt.Errorf("failed to generate OTP for pre-epoch time %d", unixTime)
	}

	counter := uint64(unixTime) / uint64(totpPeriod)
	return generateHOTP(key, counter)
}

// decodeSecret decodes a base32-encoded TOTP secret, handling common formatting
// variations (spaces, hyphens, lowercase, missing padding).
func decodeSecret(secret string) ([]byte, error) {
	// Clean up: remove spaces, hyphens, convert to uppercase
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")

	// Strip any existing padding before re-calculating
	secret = strings.TrimRight(secret, "=")

	// Add padding if needed (base32 requires length to be multiple of 8)
	if remainder := len(secret) % 8; remainder != 0 {
		secret += strings.Repeat("=", 8-remainder)
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 secret: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("empty secret after decoding")
	}
	return key, nil
}

// generateHOTP generates an HOTP code per RFC 4226.
func generateHOTP(key []byte, counter uint64) (string, error) {
	// Encode counter as 8-byte big-endian
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// HMAC-SHA1
	mac := hmac.New(sha1.New, key) // #nosec G401 - required by TOTP RFC 6238
	_, _ = mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.4)
	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Modulo to get desired number of digits
	otp := code % uint32(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, otp), nil
}
