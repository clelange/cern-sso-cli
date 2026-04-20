package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"
)

func TestStartDeviceAuthorizationReturnsPrompt(t *testing.T) {
	var gotChallengeMethod string
	var gotClientID string
	var gotChallenge string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/realms/cern/protocol/openid-connect/auth/device" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		gotClientID = r.Form.Get("client_id")
		gotChallengeMethod = r.Form.Get("code_challenge_method")
		gotChallenge = r.Form.Get("code_challenge")

		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "device-code-123",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://auth.example/verify",
			"verification_uri_complete": "https://auth.example/verify?user_code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  9,
		})
	}))
	defer server.Close()

	cfg := newOIDCTestConfig(t, server.URL)
	session, err := StartDeviceAuthorization(cfg)
	if err != nil {
		t.Fatalf("StartDeviceAuthorization failed: %v", err)
	}

	if gotClientID != cfg.ClientID {
		t.Fatalf("expected client_id %q, got %q", cfg.ClientID, gotClientID)
	}
	if gotChallengeMethod != "S256" {
		t.Fatalf("expected code_challenge_method %q, got %q", "S256", gotChallengeMethod)
	}
	if gotChallenge == "" {
		t.Fatal("expected non-empty code_challenge")
	}
	if session.Prompt.UserCode != "ABCD-EFGH" {
		t.Fatalf("expected user code %q, got %q", "ABCD-EFGH", session.Prompt.UserCode)
	}
	if session.Prompt.VerificationURI != "https://auth.example/verify" {
		t.Fatalf("expected verification URI %q, got %q", "https://auth.example/verify", session.Prompt.VerificationURI)
	}
	if session.Prompt.VerificationURIComplete != "https://auth.example/verify?user_code=ABCD-EFGH" {
		t.Fatalf("expected complete verification URI %q, got %q", "https://auth.example/verify?user_code=ABCD-EFGH", session.Prompt.VerificationURIComplete)
	}
	if session.pollInterval != 9*time.Second {
		t.Fatalf("expected poll interval %v, got %v", 9*time.Second, session.pollInterval)
	}
}

func TestDeviceAuthorizationSessionWaitForToken(t *testing.T) {
	origOIDCTimeNow := oidcTimeNow
	origOIDCSleep := oidcSleep
	defer func() {
		oidcTimeNow = origOIDCTimeNow
		oidcSleep = origOIDCSleep
	}()

	currentTime := time.Unix(1_700_000_000, 0)
	oidcTimeNow = func() time.Time { return currentTime }

	var sleepCalls []time.Duration
	oidcSleep = func(d time.Duration) {
		sleepCalls = append(sleepCalls, d)
	}

	var tokenRequests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/realms/cern/protocol/openid-connect/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "device-code-123",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          "https://auth.example/verify",
				"verification_uri_complete": "https://auth.example/verify?user_code=ABCD-EFGH",
				"expires_in":                600,
				"interval":                  1,
			})
		case "/auth/realms/cern/protocol/openid-connect/token":
			tokenRequests++
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse token form: %v", err)
			}
			if r.Form.Get("client_id") != "device-client" {
				t.Fatalf("expected client_id %q, got %q", "device-client", r.Form.Get("client_id"))
			}
			if r.Form.Get("device_code") != "device-code-123" {
				t.Fatalf("expected device_code %q, got %q", "device-code-123", r.Form.Get("device_code"))
			}
			if r.Form.Get("code_verifier") == "" {
				t.Fatal("expected non-empty code_verifier")
			}

			if tokenRequests == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "authorization_pending",
				})
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "access-123",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "refresh-456",
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	session, err := StartDeviceAuthorization(newOIDCTestConfig(t, server.URL))
	if err != nil {
		t.Fatalf("StartDeviceAuthorization failed: %v", err)
	}

	token, err := session.WaitForToken()
	if err != nil {
		t.Fatalf("WaitForToken failed: %v", err)
	}

	if token.AccessToken != "access-123" {
		t.Fatalf("expected access token %q, got %q", "access-123", token.AccessToken)
	}
	if token.RefreshToken != "refresh-456" {
		t.Fatalf("expected refresh token %q, got %q", "refresh-456", token.RefreshToken)
	}
	if tokenRequests != 2 {
		t.Fatalf("expected %d token requests, got %d", 2, tokenRequests)
	}
	if !slices.Equal(sleepCalls, []time.Duration{time.Second, time.Second}) {
		t.Fatalf("expected sleep calls %v, got %v", []time.Duration{time.Second, time.Second}, sleepCalls)
	}
}

func TestTokenRefresh(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
	}{
		{
			name:       "success",
			statusCode: http.StatusOK,
			body:       `{"access_token":"access-123","refresh_token":"refresh-456","expires_in":3600,"token_type":"Bearer"}`,
		},
		{
			name:       "non-200 response",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_grant"}`,
			wantErr:    true,
		},
		{
			name:       "malformed json",
			statusCode: http.StatusOK,
			body:       `not-json`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/auth/realms/cern/protocol/openid-connect/token" {
					t.Fatalf("unexpected path %q", r.URL.Path)
				}
				if err := r.ParseForm(); err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}
				if r.Form.Get("grant_type") != "refresh_token" {
					t.Fatalf("expected grant_type refresh_token, got %q", r.Form.Get("grant_type"))
				}
				if r.Form.Get("refresh_token") != "refresh-123" {
					t.Fatalf("expected refresh token %q, got %q", "refresh-123", r.Form.Get("refresh_token"))
				}
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			token, err := TokenRefresh(newOIDCTestConfig(t, server.URL), "refresh-123")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("TokenRefresh failed: %v", err)
			}
			if token.AccessToken != "access-123" {
				t.Fatalf("expected access token %q, got %q", "access-123", token.AccessToken)
			}
			if token.RefreshToken != "refresh-456" {
				t.Fatalf("expected refresh token %q, got %q", "refresh-456", token.RefreshToken)
			}
		})
	}
}

func newOIDCTestConfig(t *testing.T, serverURL string) OIDCConfig {
	t.Helper()

	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	return OIDCConfig{
		AuthHostname: u.Host,
		AuthRealm:    "cern",
		ClientID:     "device-client",
		VerifyCert:   false,
	}
}
