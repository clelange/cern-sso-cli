//go:build !nowebauthn
// +build !nowebauthn

// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/keys-pub/go-libfido2"
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

// WebAuthnProvider handles FIDO2 authentication with security keys.
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

// GetPIN retrieves the PIN using the configured sources.
// Priority: struct field > environment variable > interactive prompt.
func (p *WebAuthnProvider) GetPIN() (string, error) {
	// Priority 1: Direct PIN from struct
	if p.PIN != "" {
		return p.PIN, nil
	}

	// Priority 2: Environment variable
	if envPIN := os.Getenv(EnvWebAuthnPIN); envPIN != "" {
		return envPIN, nil
	}

	// Priority 3: Interactive prompt
	fmt.Print("Enter your security key PIN: ")
	var pin string
	_, err := fmt.Scanln(&pin)
	if err != nil {
		return "", fmt.Errorf("failed to read PIN: %w", err)
	}
	return pin, nil
}

// GetTimeout returns the configured timeout, defaulting to 30 seconds.
func (p *WebAuthnProvider) GetTimeout() time.Duration {
	if p.Timeout <= 0 {
		return 30 * time.Second
	}
	return p.Timeout
}

// Authenticate performs FIDO2 assertion with the connected device.
// Returns the assertion data formatted for Keycloak submission.
func (p *WebAuthnProvider) Authenticate(form *WebAuthnForm) (*WebAuthnResult, error) {
	if form == nil {
		return nil, errors.New("webauthn form is nil")
	}

	// Find available FIDO2 devices
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate FIDO2 devices: %w", err)
	}

	if len(locs) == 0 {
		if p.UseBrowser {
			return nil, errors.New("no FIDO2 device found, browser fallback requested")
		}
		return nil, errors.New("no FIDO2 device found. Please connect your security key and try again")
	}

	// Use specified device or first available
	devicePath := p.DevicePath
	if devicePath == "" {
		devicePath = locs[0].Path
		fmt.Printf("Using FIDO2 device: %s\n", locs[0].Product)
	}

	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open FIDO2 device: %w", err)
	}
	// Note: Device doesn't have a public Close method, cleanup is handled internally

	// Decode challenge from base64url
	challenge, err := base64.RawURLEncoding.DecodeString(form.Challenge)
	if err != nil {
		// Try standard base64 as fallback
		challenge, err = base64.StdEncoding.DecodeString(form.Challenge)
		if err != nil {
			return nil, fmt.Errorf("failed to decode challenge: %w", err)
		}
	}

	// Decode credential IDs
	credentialIDs := make([][]byte, 0, len(form.CredentialIDs))
	for _, credIDStr := range form.CredentialIDs {
		credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
		if err != nil {
			// Try standard base64 as fallback
			credID, err = base64.StdEncoding.DecodeString(credIDStr)
			if err != nil {
				continue // Skip invalid credential IDs
			}
		}
		credentialIDs = append(credentialIDs, credID)
	}

	// Check if PIN is needed - try RetryCount which fails if PIN is set but not yet verified
	var pin string
	_, retryErr := device.RetryCount()
	if retryErr == nil {
		// Device has PIN set, we need to get it
		pin, err = p.GetPIN()
		if err != nil {
			return nil, err
		}
	}

	fmt.Println("Touch your security key...")

	// Perform the assertion
	assertion, err := device.Assertion(
		form.RPID,
		challenge,
		credentialIDs,
		pin,
		&libfido2.AssertionOpts{
			UP: libfido2.True, // Require user presence
		},
	)
	if err != nil {
		return nil, fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	// Format result for Keycloak
	// Note: go-libfido2 returns AuthDataCBOR, which is CBOR-encoded authenticator data
	result := &WebAuthnResult{
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(assertion.AuthDataCBOR),
		Signature:         base64.RawURLEncoding.EncodeToString(assertion.Sig),
	}

	// Build clientDataJSON (this is what the browser would normally create)
	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"https://%s","crossOrigin":false}`,
		form.Challenge, form.RPID)
	result.ClientDataJSON = base64.RawURLEncoding.EncodeToString([]byte(clientData))

	// Include credential ID if available
	if len(assertion.CredentialID) > 0 {
		result.CredentialID = base64.RawURLEncoding.EncodeToString(assertion.CredentialID)
	} else if len(credentialIDs) > 0 {
		result.CredentialID = base64.RawURLEncoding.EncodeToString(credentialIDs[0])
	}

	// Include user handle if present
	if len(assertion.User.ID) > 0 {
		result.UserHandle = base64.RawURLEncoding.EncodeToString(assertion.User.ID)
	}

	return result, nil
}

// IsWebAuthnAvailable returns true if WebAuthn support is compiled in.
func IsWebAuthnAvailable() bool {
	return true
}
