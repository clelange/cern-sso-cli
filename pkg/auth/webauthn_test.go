//go:build !nowebauthn

package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"strings"
	"testing"

	"github.com/keys-pub/go-libfido2"
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

type fakeWebAuthnDevice struct {
	hasPIN      bool
	credentials func(context.Context, string, string) ([][]byte, error)
	assertion   func(context.Context, string, []byte, [][]byte, string) (*libfido2.Assertion, error)
	close       func()
}

func (d *fakeWebAuthnDevice) HasPIN() bool { return d.hasPIN }
func (d *fakeWebAuthnDevice) Close() {
	if d.close != nil {
		d.close()
	}
}
func (d *fakeWebAuthnDevice) Credentials(ctx context.Context, rp, pin string) ([][]byte, error) {
	if d.credentials == nil {
		return nil, errCredentialManagementUnsupported
	}
	return d.credentials(ctx, rp, pin)
}
func (d *fakeWebAuthnDevice) Assertion(ctx context.Context, rp string, hash []byte, ids [][]byte, pin string) (*libfido2.Assertion, error) {
	if d.assertion == nil {
		return nil, errors.New("unexpected assertion")
	}
	return d.assertion(ctx, rp, hash, ids, pin)
}

func fakeWebAuthnBackend(open func(context.Context, string) (webAuthnDevice, error)) webAuthnBackend {
	return webAuthnBackend{
		locations: func() ([]*libfido2.DeviceLocation, error) {
			return []*libfido2.DeviceLocation{{Path: "fake-device", Product: "Fake key"}}, nil
		},
		open: open,
	}
}

func TestWebAuthnAuthenticateSerializesAssertion(t *testing.T) {
	tests := []struct {
		name         string
		authData     []byte
		credentialID []byte
	}{
		{"CBOR authenticator data", []byte{0x43, 1, 2, 3}, []byte("chosen")},
		{"raw authenticator data and credential fallback", []byte{1, 2, 3}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			form := &WebAuthnForm{Challenge: "challenge", RPID: "cern.ch", Origin: "https://auth.cern.ch", CredentialIDs: []string{base64.RawURLEncoding.EncodeToString([]byte("allowed"))}}
			backend := fakeWebAuthnBackend(func(_ context.Context, path string) (webAuthnDevice, error) {
				calls = append(calls, "open:"+path)
				return &fakeWebAuthnDevice{hasPIN: true, close: func() { calls = append(calls, "close") },
					assertion: func(_ context.Context, rp string, hash []byte, ids [][]byte, pin string) (*libfido2.Assertion, error) {
						calls = append(calls, "assertion")
						expectedHash := sha256.Sum256([]byte(`{"type":"webauthn.get","challenge":"challenge","origin":"https://auth.cern.ch","crossOrigin":false}`))
						if rp != "cern.ch" || pin != "1234" || !bytes.Equal(hash, expectedHash[:]) || !reflect.DeepEqual(ids, [][]byte{[]byte("allowed")}) {
							t.Errorf("unexpected assertion input: rp=%q pin=%q hash=%x ids=%q", rp, pin, hash, ids)
						}
						return &libfido2.Assertion{AuthDataCBOR: tt.authData, Sig: []byte("signature"), CredentialID: tt.credentialID, User: libfido2.User{ID: []byte("user")}}, nil
					},
				}, nil
			})
			p := &WebAuthnProvider{Timeout: time.Second}
			result, err := p.authenticate(form, backend, func() (string, error) { calls = append(calls, "pin"); return "1234", nil })
			if err != nil {
				t.Fatal(err)
			}
			wantID := tt.credentialID
			if len(wantID) == 0 {
				wantID = []byte("allowed")
			}
			if result.AuthenticatorData != "AQID" || result.Signature != base64.RawURLEncoding.EncodeToString([]byte("signature")) || result.CredentialID != base64.RawURLEncoding.EncodeToString(wantID) || result.UserHandle != "dXNlcg" {
				t.Fatalf("unexpected serialized assertion: %+v", result)
			}
			clientJSON, err := base64.RawURLEncoding.DecodeString(result.ClientDataJSON)
			if err != nil || !strings.Contains(string(clientJSON), `"origin":"https://auth.cern.ch"`) {
				t.Fatalf("bad client data: %q, %v", clientJSON, err)
			}
			wantCalls := []string{"open:fake-device", "close", "pin", "open:fake-device", "assertion", "close"}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, wantCalls)
			}
		})
	}
}

func TestWebAuthnAuthenticatePropagatesDeviceErrors(t *testing.T) {
	ioErr := errors.New("USB read failed")
	for _, stage := range []string{"enumeration", "open and PIN discovery", "PIN input", "credential discovery", "invalid PIN", "assertion"} {
		t.Run(stage, func(t *testing.T) {
			assertionCalls := 0
			backend := fakeWebAuthnBackend(func(_ context.Context, _ string) (webAuthnDevice, error) {
				if stage == "open and PIN discovery" {
					return nil, ioErr
				}
				return &fakeWebAuthnDevice{hasPIN: true,
					credentials: func(context.Context, string, string) ([][]byte, error) {
						if stage == "invalid PIN" {
							return nil, libfido2.ErrPinInvalid
						}
						if stage == "credential discovery" {
							return nil, ioErr
						}
						return nil, errCredentialManagementUnsupported
					},
					assertion: func(context.Context, string, []byte, [][]byte, string) (*libfido2.Assertion, error) {
						assertionCalls++
						return nil, ioErr
					},
				}, nil
			})
			if stage == "enumeration" {
				backend.locations = func() ([]*libfido2.DeviceLocation, error) { return nil, ioErr }
			}
			getPIN := func() (string, error) {
				if stage == "PIN input" {
					return "", ioErr
				}
				return "1234", nil
			}
			_, err := (&WebAuthnProvider{}).authenticate(&WebAuthnForm{Challenge: "challenge", RPID: "cern.ch"}, backend, getPIN)
			wantErr := ioErr
			if stage == "invalid PIN" {
				wantErr = libfido2.ErrPinInvalid
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want %v", err, wantErr)
			}
			wantCalls := 0
			if stage == "assertion" {
				wantCalls = 1
			}
			if assertionCalls != wantCalls {
				t.Fatalf("assertion called %d times, want %d; failed PIN/I/O must never be retried", assertionCalls, wantCalls)
			}
		})
	}
}

func TestWebAuthnAuthenticateCredentialDiscovery(t *testing.T) {
	for _, hasPIN := range []bool{false, true} {
		t.Run(fmt.Sprintf("PIN=%v", hasPIN), func(t *testing.T) {
			backend := fakeWebAuthnBackend(func(context.Context, string) (webAuthnDevice, error) {
				return &fakeWebAuthnDevice{hasPIN: hasPIN,
					credentials: func(_ context.Context, _, pin string) ([][]byte, error) {
						if pin != "1234" {
							t.Error("incorrect discovery PIN")
						}
						return [][]byte{[]byte("resident")}, nil
					},
					assertion: func(_ context.Context, _ string, _ []byte, ids [][]byte, pin string) (*libfido2.Assertion, error) {
						if hasPIN && (!reflect.DeepEqual(ids, [][]byte{[]byte("resident")}) || pin != "1234") {
							t.Errorf("bad resident discovery: %q %q", ids, pin)
						}
						if !hasPIN && (len(ids) != 0 || pin != "") {
							t.Error("unexpected PIN/allowCredentials")
						}
						return &libfido2.Assertion{AuthDataCBOR: []byte{0x41, 1}}, nil
					},
				}, nil
			})
			_, err := (&WebAuthnProvider{}).authenticate(&WebAuthnForm{Challenge: "challenge", RPID: "cern.ch"}, backend, func() (string, error) {
				if !hasPIN {
					t.Error("prompted for PIN on a device without a PIN")
				}
				return "1234", nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRunDeviceInteractionCancellationOwnsCleanup(t *testing.T) {
	for _, stage := range []string{"startup", "assertion"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := runDeviceInteraction(ctx, time.Second, func(ctx context.Context) (bool, error) {
					// Fake a native call that does not support concurrent Cancel.
					// The worker must retain sole ownership until it returns.
					if stage == "assertion" {
						defer close(closed)
					}
					close(started)
					<-release
					if stage == "startup" {
						defer close(closed)
					}
					return true, ctx.Err()
				})
				done <- err
			}()
			<-started
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not return promptly")
			}
			select {
			case <-closed:
				t.Error("device freed during native I/O")
			default:
			}
			close(release)
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("worker did not clean up")
			}
		})
	}
}

func TestWebAuthnAuthenticateTimeoutDuringDiscovery(t *testing.T) {
	closed := make(chan struct{})
	p := &WebAuthnProvider{Timeout: 20 * time.Millisecond}
	backend := fakeWebAuthnBackend(func(ctx context.Context, _ string) (webAuthnDevice, error) {
		<-ctx.Done()
		close(closed)
		return nil, ctx.Err()
	})
	start := time.Now()
	_, err := p.authenticate(&WebAuthnForm{Challenge: "challenge", RPID: "cern.ch"}, backend, func() (string, error) { t.Error("unexpected PIN prompt"); return "", nil })
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout was ignored")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("open worker did not exit")
	}
}

func TestWebAuthnSelectDevice(t *testing.T) {
	locs := []*libfido2.DeviceLocation{{Path: "first", Product: "First"}, {Path: "second", Product: "Second"}}
	for _, tt := range []struct {
		name      string
		provider  WebAuthnProvider
		path      string
		errorText string
	}{
		{"auto", WebAuthnProvider{DeviceIndex: -1}, "first", ""},
		{"index", WebAuthnProvider{DeviceIndex: 1}, "second", ""},
		{"path overrides index", WebAuthnProvider{DevicePath: "second"}, "second", ""},
		{"missing path", WebAuthnProvider{DevicePath: "missing"}, "", "not found"},
		{"invalid index", WebAuthnProvider{DeviceIndex: 2}, "", "out of range"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, _, err := tt.provider.selectDevice(locs)
			if tt.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errorText) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || path != tt.path {
				t.Fatalf("path = %q, err = %v", path, err)
			}
		})
	}
}

func TestNativeTimeoutMilliseconds(t *testing.T) {
	if _, err := nativeTimeoutMilliseconds(context.Background()); err == nil {
		t.Fatal("unbounded communication must be rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ms, err := nativeTimeoutMilliseconds(ctx)
	if err != nil || ms <= 0 || ms > 1000 {
		t.Fatalf("timeout = %d, %v", ms, err)
	}
	cancel()
	if _, err := nativeTimeoutMilliseconds(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), -time.Second)
	defer cancel()
	if _, err := nativeTimeoutMilliseconds(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100000*time.Hour)
	defer cancel()
	if ms, err := nativeTimeoutMilliseconds(ctx); err != nil || ms != math.MaxInt32 {
		t.Fatalf("timeout overflow: %d, %v", ms, err)
	}
}

func TestWebAuthnAuthenticateTimeoutDuringAssertion(t *testing.T) {
	closed := make(chan struct{})
	openCount := 0
	backend := fakeWebAuthnBackend(func(_ context.Context, _ string) (webAuthnDevice, error) {
		openCount++
		device := &fakeWebAuthnDevice{}
		if openCount == 2 {
			device.close = func() { close(closed) }
			device.assertion = func(ctx context.Context, _ string, _ []byte, _ [][]byte, _ string) (*libfido2.Assertion, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		return device, nil
	})
	start := time.Now()
	_, err := (&WebAuthnProvider{Timeout: 30 * time.Millisecond}).authenticate(&WebAuthnForm{Challenge: "challenge", RPID: "cern.ch"}, backend, func() (string, error) { t.Error("unexpected PIN prompt"); return "", nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("assertion timeout was ignored")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("assertion worker did not clean up")
	}
}

func TestWebAuthnTimeoutExcludesPINButPreservesDeviceBudget(t *testing.T) {
	const timeout = 200 * time.Millisecond
	var firstRemaining, secondRemaining time.Duration
	openCount := 0
	backend := fakeWebAuthnBackend(func(ctx context.Context, _ string) (webAuthnDevice, error) {
		openCount++
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("native operation has no deadline")
		}
		if openCount == 1 {
			firstRemaining = time.Until(deadline)
			time.Sleep(50 * time.Millisecond)
		} else {
			secondRemaining = time.Until(deadline)
		}
		return &fakeWebAuthnDevice{hasPIN: true, assertion: func(context.Context, string, []byte, [][]byte, string) (*libfido2.Assertion, error) {
			return &libfido2.Assertion{AuthDataCBOR: []byte{0x41, 1}}, nil
		}}, nil
	})
	_, err := (&WebAuthnProvider{Timeout: timeout}).authenticate(&WebAuthnForm{Challenge: "challenge", RPID: "cern.ch"}, backend, func() (string, error) {
		time.Sleep(timeout)
		return "1234", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if secondRemaining <= 0 || secondRemaining >= firstRemaining-40*time.Millisecond {
		t.Fatalf("device timeout budget was reset: first=%s second=%s", firstRemaining, secondRemaining)
	}
}
