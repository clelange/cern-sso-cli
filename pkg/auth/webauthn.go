//go:build !nowebauthn
// +build !nowebauthn

// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
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
	DevicePath  string        // Optional: specific device path, empty = auto-detect
	DeviceIndex int           // Optional: device index (0-based), -1 = auto-detect first device
	PIN         string        // Device PIN if required
	Timeout     time.Duration // Timeout for device interaction
	UseBrowser  bool          // Fall back to browser-based flow
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
	fmt.Fprint(os.Stderr, "Enter your security key PIN: ")
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

// FIDO2DeviceInfo contains information about an available FIDO2 device.
type FIDO2DeviceInfo struct {
	Index   int    // 0-based index for selection
	Path    string // Device path (e.g., /dev/hidraw0)
	Product string // Product name (e.g., "YubiKey 5 NFC")
}

// ListFIDO2Devices returns a list of available FIDO2 devices.
// Returns an empty slice if no devices are found or if enumeration fails.
func ListFIDO2Devices() ([]FIDO2DeviceInfo, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate FIDO2 devices: %w", err)
	}

	devices := make([]FIDO2DeviceInfo, len(locs))
	for i, loc := range locs {
		devices[i] = FIDO2DeviceInfo{
			Index:   i,
			Path:    loc.Path,
			Product: loc.Product,
		}
	}
	return devices, nil
}

// formatDeviceList formats a list of devices for display in error messages.
func formatDeviceList(locs []*libfido2.DeviceLocation) string {
	var sb strings.Builder
	sb.WriteString("Available FIDO2 devices:\n")
	for i, loc := range locs {
		sb.WriteString(fmt.Sprintf("  [%d] %s (%s)\n", i, loc.Product, loc.Path))
	}
	return sb.String()
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
		return nil, errors.New("no FIDO2 device found.\n\n" +
			"Note: This tool only supports USB/NFC security keys (e.g., YubiKey).\n" +
			"macOS Touch ID and iCloud Keychain passkeys are not supported by libfido2.\n\n" +
			"Please connect a hardware security key and try again.")
	}

	// Determine which device to use
	var devicePath string
	var selectedDevice *libfido2.DeviceLocation

	if p.DevicePath != "" {
		// Explicit path specified
		devicePath = p.DevicePath
		// Find matching device for display
		for _, loc := range locs {
			if loc.Path == p.DevicePath {
				selectedDevice = loc
				break
			}
		}
		if selectedDevice == nil {
			return nil, fmt.Errorf("specified device path %q not found.\n\n%s",
				p.DevicePath, formatDeviceList(locs))
		}
	} else if p.DeviceIndex >= 0 {
		// Index-based selection
		if p.DeviceIndex >= len(locs) {
			return nil, fmt.Errorf("device index %d out of range (0-%d).\n\n%s",
				p.DeviceIndex, len(locs)-1, formatDeviceList(locs))
		}
		selectedDevice = locs[p.DeviceIndex]
		devicePath = selectedDevice.Path
	} else {
		// Auto-detect: use first device, but warn if multiple available
		selectedDevice = locs[0]
		devicePath = selectedDevice.Path

		if len(locs) > 1 {
			fmt.Fprintf(os.Stderr, "Multiple FIDO2 devices detected. Using first device.\n")
			fmt.Fprintf(os.Stderr, "%s", formatDeviceList(locs))
			fmt.Fprintf(os.Stderr, "Use --webauthn-device-index N to select a specific device.\n\n")
		}
	}

	fmt.Fprintf(os.Stderr, "Using FIDO2 device: %s (%s)\n", selectedDevice.Product, selectedDevice.Path)

	device, err := libfido2.NewDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open FIDO2 device %q: %w", selectedDevice.Product, err)
	}
	// Note: Device doesn't have a public Close method, cleanup is handled internally
	// Build clientDataJSON (this is what the browser creates)
	// The origin must use "https://" prefix for WebAuthn
	origin := fmt.Sprintf("https://%s", form.RPID)
	clientDataJSON := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}`,
		form.Challenge, origin)

	// Compute SHA-256 hash of clientDataJSON - this is what libfido2 expects
	// The Assertion function takes clientDataHash (32 bytes), not raw challenge
	clientDataHash := sha256.Sum256([]byte(clientDataJSON))

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

	// Decode credential IDs from Keycloak's authn_use_chk field (base64url encoded)
	// This is the allowCredentials list that the browser's WebAuthn API receives
	var credentialIDs [][]byte
	for _, credIDStr := range form.CredentialIDs {
		if credIDStr == "" {
			continue
		}

		// Keycloak uses base64url encoding with {loose: true} which allows missing padding
		credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
		if err != nil {
			// Try with standard base64url (with padding)
			credID, err = base64.URLEncoding.DecodeString(credIDStr)
			if err != nil {
				// Try standard base64 as last resort
				credID, err = base64.StdEncoding.DecodeString(credIDStr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Could not decode credential ID: %v\n", err)
					continue
				}
			}
		}
		credentialIDs = append(credentialIDs, credID)
	}

	if len(credentialIDs) == 0 && pin != "" {
		creds, credErr := device.Credentials(form.RPID, pin)
		if credErr == nil && len(creds) > 0 {
			for _, cred := range creds {
				credentialIDs = append(credentialIDs, cred.ID)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "Touch your security key...")

	// Run assertion in goroutine to allow signal handling
	type assertionResult struct {
		assertion *libfido2.Assertion
		err       error
	}
	resultChan := make(chan assertionResult, 1)

	go func() {
		assertion, err := device.Assertion(
			form.RPID,
			clientDataHash[:], // SHA-256 hash of clientDataJSON (32 bytes)
			credentialIDs,     // nil for resident key discovery
			pin,
			&libfido2.AssertionOpts{
				UP: libfido2.True, // Require user presence
			},
		)
		resultChan <- assertionResult{assertion, err}
	}()

	// Wait for assertion or interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	var assertion *libfido2.Assertion
	select {
	case result := <-resultChan:
		assertion = result.assertion
		err = result.err
	case <-sigChan:
		fmt.Fprintln(os.Stderr, "\nInterrupted. Closing device...")
		// Cancel the device operation by closing it
		device.Cancel()
		return nil, fmt.Errorf("operation cancelled by user")
	}

	if err != nil {
		// If assertion failed without credential IDs, suggest browser fallback
		if len(credentialIDs) == 0 {
			return nil, fmt.Errorf("FIDO2 assertion failed on device %q: %w.\n\n"+
				"This device may not have credentials registered for %s.\n"+
				"If your passkey is stored elsewhere (e.g., iCloud Keychain, another security key),\n"+
				"try using --browser for browser-based authentication.", devicePath, err, form.RPID)
		}
		return nil, fmt.Errorf("FIDO2 assertion failed on device %q: %w", devicePath, err)
	}

	// Format result for Keycloak
	// go-libfido2 returns AuthDataCBOR which is CBOR-encoded authenticator data
	// Keycloak expects raw authenticator data (not CBOR-wrapped)
	// The CBOR wrapper is just a byte string containing the raw authenticator data
	var rawAuthData []byte
	if err := cbor.Unmarshal(assertion.AuthDataCBOR, &rawAuthData); err != nil {
		// If CBOR decoding fails, use raw data (some versions might differ)
		rawAuthData = assertion.AuthDataCBOR
	}

	result := &WebAuthnResult{
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(rawAuthData),
		Signature:         base64.RawURLEncoding.EncodeToString(assertion.Sig),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString([]byte(clientDataJSON)),
	}

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
