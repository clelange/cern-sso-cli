//go:build !nowebauthn

package auth

import (
	"strings"
	"testing"
)

func TestWebAuthnAuthenticateValidatesAssertionParameters(t *testing.T) {
	tests := []struct {
		name      string
		form      *WebAuthnForm
		errorText string
	}{
		{
			name:      "nil form",
			errorText: "form is nil",
		},
		{
			name:      "empty challenge",
			form:      &WebAuthnForm{RPID: "auth.cern.ch"},
			errorText: "challenge is empty",
		},
		{
			name:      "empty RP ID",
			form:      &WebAuthnForm{Challenge: "challenge-123"},
			errorText: "RP ID is empty",
		},
	}

	provider := &WebAuthnProvider{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.Authenticate(tt.form)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errorText) {
				t.Fatalf("error = %q, expected it to contain %q", err, tt.errorText)
			}
		})
	}
}
