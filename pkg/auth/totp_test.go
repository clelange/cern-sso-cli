package auth

import (
	"testing"
	"time"
)

// RFC 6238 test vector: the standard test secret is "12345678901234567890"
// which in base32 is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
const testSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestGenerateTOTP_KnownVectors(t *testing.T) {
	// RFC 6238 Appendix B test vectors for SHA1
	// https://www.rfc-editor.org/rfc/rfc6238#appendix-B
	tests := []struct {
		name     string
		unixTime int64
		expected string
	}{
		{"T=59", 59, "287082"},
		{"T=1111111109", 1111111109, "081804"},
		{"T=1111111111", 1111111111, "050471"},
		{"T=1234567890", 1234567890, "005924"},
		{"T=2000000000", 2000000000, "279037"},
		{"T=20000000000", 20000000000, "353130"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Override time for deterministic testing
			origTimeNow := timeNow
			timeNow = func() time.Time { return time.Unix(tc.unixTime, 0) }
			defer func() { timeNow = origTimeNow }()

			otp, err := GenerateTOTP(testSecret)
			if err != nil {
				t.Fatalf("GenerateTOTP(%q) at t=%d returned error: %v", testSecret, tc.unixTime, err)
			}
			if otp != tc.expected {
				t.Errorf("GenerateTOTP(%q) at t=%d = %q, want %q", testSecret, tc.unixTime, otp, tc.expected)
			}
		})
	}
}

func TestGenerateTOTP_SecretFormats(t *testing.T) {
	// All these should produce the same result for the same time
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(59, 0) }
	defer func() { timeNow = origTimeNow }()

	// Different representations of the same secret
	secrets := []string{
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",        // standard base32
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",        // lowercase
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", // with spaces
		"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ", // with hyphens
		" GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ ",      // leading/trailing whitespace
	}

	expected := "287082" // RFC 6238 vector at T=59

	for _, secret := range secrets {
		t.Run(secret, func(t *testing.T) {
			otp, err := GenerateTOTP(secret)
			if err != nil {
				t.Fatalf("GenerateTOTP(%q) returned error: %v", secret, err)
			}
			if otp != expected {
				t.Errorf("GenerateTOTP(%q) = %q, want %q", secret, otp, expected)
			}
		})
	}
}

func TestGenerateTOTP_PaddingHandling(t *testing.T) {
	// A shorter secret without padding should still work
	// "JBSWY3DPEHPK3PXP" is base32 for "Hello!\xde\xa9\xd7\xaf" (common test secret)
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(0, 0) }
	defer func() { timeNow = origTimeNow }()

	// This should not error (secret without padding)
	_, err := GenerateTOTP("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("GenerateTOTP with unpadded secret returned error: %v", err)
	}
}

func TestGenerateTOTP_InvalidSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{"invalid base32 chars", "!!!invalid!!!"},
		{"digit-only (invalid base32)", "1234567890123456"},
		{"empty", ""},
		{"only spaces", "   "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origTimeNow := timeNow
			timeNow = func() time.Time { return time.Unix(0, 0) }
			defer func() { timeNow = origTimeNow }()

			_, err := GenerateTOTP(tc.secret)
			if err == nil {
				t.Errorf("GenerateTOTP(%q) expected error, got nil", tc.secret)
			}
		})
	}
}

func TestGenerateTOTP_OutputFormat(t *testing.T) {
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(59, 0) }
	defer func() { timeNow = origTimeNow }()

	otp, err := GenerateTOTP(testSecret)
	if err != nil {
		t.Fatalf("GenerateTOTP returned error: %v", err)
	}

	// Must be exactly 6 digits
	if len(otp) != 6 {
		t.Errorf("OTP length = %d, want 6", len(otp))
	}
	for _, c := range otp {
		if c < '0' || c > '9' {
			t.Errorf("OTP contains non-digit character: %c", c)
		}
	}
}

func TestGenerateTOTP_LeadingZeros(t *testing.T) {
	// Test at T=1111111109 which should give "081804" (leading zero)
	origTimeNow := timeNow
	timeNow = func() time.Time { return time.Unix(1111111109, 0) }
	defer func() { timeNow = origTimeNow }()

	otp, err := GenerateTOTP(testSecret)
	if err != nil {
		t.Fatalf("GenerateTOTP returned error: %v", err)
	}
	if otp != "081804" {
		t.Errorf("GenerateTOTP = %q, want %q (leading zero)", otp, "081804")
	}
	if len(otp) != 6 {
		t.Errorf("OTP with leading zero has length %d, want 6", len(otp))
	}
}

func TestDecodeSecret_Valid(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{"standard base32", "GEZDGNBVGY3TQOJQ"},
		{"lowercase", "gezdgnbvgy3tqojq"},
		{"with spaces", "GEZD GNBV GY3T QOJQ"},
		{"with hyphens", "GEZD-GNBV-GY3T-QOJQ"},
		{"with padding", "GEZDGNBVGY3TQOJQ========"},
		{"needs padding", "GEZDGNBV"}, // 8 chars, already multiple of 8
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := decodeSecret(tc.secret)
			if err != nil {
				t.Errorf("decodeSecret(%q) returned error: %v", tc.secret, err)
			}
			if len(key) == 0 {
				t.Errorf("decodeSecret(%q) returned empty key", tc.secret)
			}
		})
	}
}

func TestDecodeSecret_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{"empty", ""},
		{"only spaces", "   "},
		{"invalid chars", "!!!"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeSecret(tc.secret)
			if err == nil {
				t.Errorf("decodeSecret(%q) expected error, got nil", tc.secret)
			}
		})
	}
}

func TestGenerateTOTP_DifferentTimeWindows(t *testing.T) {
	origTimeNow := timeNow
	defer func() { timeNow = origTimeNow }()

	// Two timestamps in the same 30-second window should produce the same code
	timeNow = func() time.Time { return time.Unix(60, 0) }
	otp1, err := GenerateTOTP(testSecret)
	if err != nil {
		t.Fatalf("GenerateTOTP returned error: %v", err)
	}

	timeNow = func() time.Time { return time.Unix(89, 0) }
	otp2, err := GenerateTOTP(testSecret)
	if err != nil {
		t.Fatalf("GenerateTOTP returned error: %v", err)
	}

	if otp1 != otp2 {
		t.Errorf("Same time window produced different codes: %q vs %q", otp1, otp2)
	}

	// Different 30-second window should (almost certainly) produce a different code
	timeNow = func() time.Time { return time.Unix(90, 0) }
	otp3, err := GenerateTOTP(testSecret)
	if err != nil {
		t.Fatalf("GenerateTOTP returned error: %v", err)
	}

	if otp1 == otp3 {
		t.Log("Warning: adjacent time windows produced the same code (rare but possible)")
	}
}

func TestTimeUntilNextTOTPWindow(t *testing.T) {
	tests := []struct {
		name     string
		now      time.Time
		expected time.Duration
	}{
		{"exact boundary", time.Unix(60, 0), 0},
		{"half second left", time.Unix(59, 500_000_000), 500 * time.Millisecond},
		{"five seconds left", time.Unix(85, 0), 5 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			delay := timeUntilNextTOTPWindow(tc.now)
			if delay != tc.expected {
				t.Errorf("timeUntilNextTOTPWindow(%v) = %v, want %v", tc.now, delay, tc.expected)
			}
		})
	}
}

func TestWaitForNextTOTPWindow(t *testing.T) {
	origTimeNow := timeNow
	origTimeSleep := timeSleep
	defer func() {
		timeNow = origTimeNow
		timeSleep = origTimeSleep
	}()

	timeNow = func() time.Time { return time.Unix(59, 250_000_000) }
	var slept time.Duration
	timeSleep = func(d time.Duration) {
		slept = d
	}

	waited := waitForNextTOTPWindow()
	expected := 750 * time.Millisecond
	if waited != expected {
		t.Fatalf("waitForNextTOTPWindow() = %v, want %v", waited, expected)
	}
	if slept != expected {
		t.Errorf("waitForNextTOTPWindow() slept %v, want %v", slept, expected)
	}
}
