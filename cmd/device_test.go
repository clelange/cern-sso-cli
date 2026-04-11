package cmd

import (
	"strings"
	"testing"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

func TestRenderDeviceInstructionsIncludesWaitingMessageByDefault(t *testing.T) {
	oldQuiet := quiet
	quiet = false
	defer func() { quiet = oldQuiet }()

	stdout, stderr := captureStdoutStderr(t, func() {
		renderDeviceInstructions(auth.DeviceAuthorizationPrompt{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://auth.example/verify",
			VerificationURIComplete: "https://auth.example/verify?user_code=ABCD-EFGH",
		})
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
	for _, want := range []string{
		"CERN Single Sign-On",
		"https://auth.example/verify",
		"ABCD-EFGH",
		"https://auth.example/verify?user_code=ABCD-EFGH",
		"Waiting for login...",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("expected stderr to contain %q, got %q", want, stderr)
		}
	}
}

func TestRenderDeviceInstructionsOmitsWaitingMessageInQuietMode(t *testing.T) {
	oldQuiet := quiet
	quiet = true
	defer func() { quiet = oldQuiet }()

	_, stderr := captureStdoutStderr(t, func() {
		renderDeviceInstructions(auth.DeviceAuthorizationPrompt{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://auth.example/verify",
			VerificationURIComplete: "https://auth.example/verify?user_code=ABCD-EFGH",
		})
	})

	if strings.Contains(stderr, "Waiting for login...") {
		t.Fatalf("expected quiet mode to omit waiting message, got %q", stderr)
	}
	for _, want := range []string{"CERN Single Sign-On", "https://auth.example/verify", "ABCD-EFGH"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("expected stderr to contain %q, got %q", want, stderr)
		}
	}
}
