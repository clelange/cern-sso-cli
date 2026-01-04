//go:build nowebauthn
// +build nowebauthn

// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"errors"
	"time"
)

// WebAuthn source constants
const (
	WebAuthnSourceDevice  = "device"
	WebAuthnSourceBrowser = "browser"
)

// Environment variable names for WebAuthn configuration
const (
	EnvWebAuthnPIN = "CERN_SSO_WEBAUTHN_PIN"
)

// ErrWebAuthnDisabled is returned when WebAuthn is not compiled in.
var ErrWebAuthnDisabled = errors.New("WebAuthn support is disabled. Build without -tags nowebauthn to enable")

// WebAuthnProvider handles FIDO2 authentication with security keys.
// This is a stub implementation for builds without WebAuthn support.
type WebAuthnProvider struct {
	DevicePath string        // Optional: specific device path, empty = auto-detect
	PIN        string        // Device PIN if required
	Timeout    time.Duration // Timeout for device interaction
	UseBrowser bool          // Fall back to browser-based flow
}

// WebAuthnResult contains the response data to submit to Keycloak.
type WebAuthnResult struct {
	ClientDataJSON    string // base64url-encoded clientDataJSON
	AuthenticatorData string // base64url-encoded authenticatorData
	Signature         string // base64url-encoded signature
	CredentialID      string // base64url-encoded credential ID used
	UserHandle        string // base64url-encoded user handle (if present)
}

// GetPIN is a stub that returns an error when WebAuthn is disabled.
func (p *WebAuthnProvider) GetPIN() (string, error) {
	return "", ErrWebAuthnDisabled
}

// GetTimeout returns the configured timeout, defaulting to 30 seconds.
func (p *WebAuthnProvider) GetTimeout() time.Duration {
	if p.Timeout <= 0 {
		return 30 * time.Second
	}
	return p.Timeout
}

// Authenticate is a stub that returns an error when WebAuthn is disabled.
// The browser fallback flow should be used instead.
func (p *WebAuthnProvider) Authenticate(form *WebAuthnForm) (*WebAuthnResult, error) {
	if p.UseBrowser {
		return nil, errors.New("browser fallback requested")
	}
	return nil, ErrWebAuthnDisabled
}

// IsWebAuthnAvailable returns false when WebAuthn support is not compiled in.
func IsWebAuthnAvailable() bool {
	return false
}
