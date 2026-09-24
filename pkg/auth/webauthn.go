//go:build !nowebauthn
// +build !nowebauthn

// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
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
		fmt.Fprintf(&sb, "  [%d] %s (%s)\n", i, loc.Product, loc.Path)
	}
	return sb.String()
}

// webAuthnDevice is owned by one goroutine, on one OS thread. Implementations
// must bound native communication using the supplied context's deadline. Close
// is called by that owner only, after any in-flight native call has returned.
type webAuthnDevice interface {
	HasPIN() bool
	Credentials(context.Context, string, string) ([][]byte, error)
	Assertion(context.Context, string, []byte, [][]byte, string) (*libfido2.Assertion, error)
	Close()
}

type webAuthnBackend struct {
	locations func() ([]*libfido2.DeviceLocation, error)
	open      func(context.Context, string) (webAuthnDevice, error)
}

// runDeviceInteraction bounds the caller's wait without racing libfido2's
// non-thread-safe handles. A cancelled operation retains its handle until its
// native timeout expires; its owner then closes it. Never call Cancel or Close
// concurrently with native I/O, including opening the device.
func runDeviceInteraction[T any](ctx context.Context, timeout time.Duration, operation func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		value T
		err   error
	}
	done := make(chan result, 1)
	go func() {
		// macOS HID handles use a thread-local CFRunLoop.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := ctx.Err(); err != nil {
			done <- result{err: err}
			return
		}
		value, err := operation(ctx)
		done <- result{value, err}
	}()
	select {
	case r := <-done:
		if err := ctx.Err(); err != nil {
			return *new(T), err
		}
		return r.value, r.err
	case <-ctx.Done():
		return *new(T), ctx.Err()
	}
}

// Authenticate performs FIDO2 assertion with the connected device.
// Timeout covers device discovery and communication, excluding PIN entry.
func (p *WebAuthnProvider) Authenticate(form *WebAuthnForm) (*WebAuthnResult, error) {
	return p.authenticate(form, webAuthnBackend{
		locations: libfido2.DeviceLocations,
		open:      openNativeWebAuthnDevice,
	}, p.GetPIN)
}

//nolint:cyclop // Device selection, PIN handling and assertion formatting have separate failure paths.
func (p *WebAuthnProvider) authenticate(form *WebAuthnForm, backend webAuthnBackend, getPIN func() (string, error)) (*WebAuthnResult, error) {
	if form == nil {
		return nil, errors.New("webauthn form is nil")
	}
	if form.Challenge == "" {
		return nil, errors.New("webauthn challenge is empty")
	}
	if form.RPID == "" {
		return nil, errors.New("webauthn RP ID is empty")
	}

	// Install signal handling only during device I/O. PIN entry remains an
	// ordinary terminal prompt, with the terminal's usual interrupt behaviour.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	start := time.Now()
	selection, err := runDeviceInteraction(ctx, p.GetTimeout(), func(ctx context.Context) (*selectedWebAuthnDevice, error) {
		locs, err := backend.locations()
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate FIDO2 devices: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, selected, err := p.selectDevice(locs)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Using FIDO2 device: %s (%s)\n", selected.Product, path)
		device, err := backend.open(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to open FIDO2 device %q: %w", selected.Product, err)
		}
		defer device.Close()
		return &selectedWebAuthnDevice{path: path, hasPIN: device.HasPIN()}, nil
	})
	stop()
	remaining := p.GetTimeout() - time.Since(start)
	if err != nil {
		return nil, webAuthnInteractionError(err)
	}
	var pin string
	if selection.hasPIN {
		pin, err = getPIN()
		if err != nil {
			return nil, err
		}
	}
	// Build clientDataJSON (this is what the browser creates)
	// The origin is the authentication page's origin. It may differ from the RP
	// ID when credentials are scoped to a parent domain.
	origin := form.Origin
	if origin == "" {
		origin = fmt.Sprintf("https://%s", form.RPID)
	}
	clientDataJSON := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}`,
		form.Challenge, origin)

	// Compute SHA-256 hash of clientDataJSON - this is what libfido2 expects
	// The Assertion function takes clientDataHash (32 bytes), not raw challenge
	clientDataHash := sha256.Sum256([]byte(clientDataJSON))

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

	ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	assertion, err := runDeviceInteraction(ctx, remaining, func(ctx context.Context) (*libfido2.Assertion, error) {
		device, err := backend.open(ctx, selection.path)
		if err != nil {
			return nil, fmt.Errorf("failed to open FIDO2 device: %w", err)
		}
		defer device.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(credentialIDs) == 0 && pin != "" {
			creds, err := device.Credentials(ctx, form.RPID, pin)
			if err != nil && !errors.Is(err, errCredentialManagementUnsupported) {
				return nil, fmt.Errorf("failed to discover FIDO2 credentials: %w", err)
			}
			credentialIDs = append(credentialIDs, creds...)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fmt.Fprintln(os.Stderr, "Touch your security key...")
		assertion, err := device.Assertion(ctx, form.RPID, clientDataHash[:], credentialIDs, pin)
		if err != nil && len(credentialIDs) == 0 && ctx.Err() == nil {
			return nil, fmt.Errorf("%w\n\n"+
				"This device may not have credentials registered for %s\n"+
				"If your passkey is stored elsewhere (e.g., iCloud Keychain, another security key),\n"+
				"try using --browser for browser-based authentication", err, form.RPID)
		}
		return assertion, err
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, webAuthnInteractionError(err)
		}
		return nil, fmt.Errorf("FIDO2 authentication failed on device %q: %w", selection.path, err)
	}
	if assertion == nil {
		return nil, errors.New("FIDO2 device returned an empty assertion")
	}
	// Format result for Keycloak
	// libfido2 returns AuthDataCBOR which is CBOR-encoded authenticator data
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

type selectedWebAuthnDevice struct {
	path   string
	hasPIN bool
}

func webAuthnInteractionError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("FIDO2 device interaction timed out (adjust --webauthn-timeout if needed): %w", err)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("FIDO2 operation cancelled by user: %w", err)
	default:
		return err
	}
}

//nolint:cyclop // Explicit path, index and automatic device selection.
func (p *WebAuthnProvider) selectDevice(locs []*libfido2.DeviceLocation) (string, *libfido2.DeviceLocation, error) {
	if len(locs) == 0 {
		if p.UseBrowser {
			return "", nil, errors.New("no FIDO2 device found, browser fallback requested")
		}
		return "", nil, errors.New("no FIDO2 device found\n\n" +
			"Note: This tool only supports USB/NFC security keys (e.g., YubiKey)\n" +
			"macOS Touch ID and iCloud Keychain passkeys are not supported by libfido2\n\n" +
			"Please connect a hardware security key and try again")
	}

	// Determine which device to use
	var devicePath string
	var selectedDevice *libfido2.DeviceLocation

	switch {
	case p.DevicePath != "":
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
			return "", nil, fmt.Errorf("specified device path %q not found\n\n%s",
				p.DevicePath, formatDeviceList(locs))
		}
	case p.DeviceIndex >= 0:
		// Index-based selection
		if p.DeviceIndex >= len(locs) {
			return "", nil, fmt.Errorf("device index %d out of range (0-%d)\n\n%s",
				p.DeviceIndex, len(locs)-1, formatDeviceList(locs))
		}
		selectedDevice = locs[p.DeviceIndex]
		devicePath = selectedDevice.Path
	default:
		// Auto-detect: use first device, but warn if multiple available
		selectedDevice = locs[0]
		devicePath = selectedDevice.Path

		if len(locs) > 1 {
			fmt.Fprintf(os.Stderr, "Multiple FIDO2 devices detected. Using first device.\n")
			fmt.Fprintf(os.Stderr, "%s", formatDeviceList(locs))
			fmt.Fprintf(os.Stderr, "Use --webauthn-device-index N to select a specific device.\n\n")
		}
	}

	return devicePath, selectedDevice, nil
}

// IsWebAuthnAvailable returns true if WebAuthn support is compiled in.
func IsWebAuthnAvailable() bool {
	return true
}
