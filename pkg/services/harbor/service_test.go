package harbor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchCLISecretUsesProfileSecret(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("sso"); err != nil {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v2.0/users/current" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":  7,
			"username": "alice",
			"oidc_user_meta": map[string]any{
				"secret": "profile-secret",
			},
		})
	}))
	defer server.Close()

	result, err := FetchCLISecret(server.URL, []*http.Cookie{{Name: "sso", Value: "ok"}}, false)
	if err != nil {
		t.Fatalf("FetchCLISecret failed: %v", err)
	}

	if result.UserID != 7 {
		t.Fatalf("expected user ID 7, got %d", result.UserID)
	}
	if result.Username != "alice" {
		t.Fatalf("expected username %q, got %q", "alice", result.Username)
	}
	if result.Secret != "profile-secret" {
		t.Fatalf("expected secret %q, got %q", "profile-secret", result.Secret)
	}
}

func TestFetchCLISecretFallsBackToCLISecretEndpoint(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("sso"); err != nil {
			http.Error(w, "missing cookie", http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/api/v2.0/users/current":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":        7,
				"username":       "alice",
				"oidc_user_meta": map[string]any{},
			})
		case "/api/v2.0/users/7/cli_secret":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secret": "api-secret",
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	result, err := FetchCLISecret(server.URL, []*http.Cookie{{Name: "sso", Value: "ok"}}, false)
	if err != nil {
		t.Fatalf("FetchCLISecret failed: %v", err)
	}

	if result.Secret != "api-secret" {
		t.Fatalf("expected secret %q, got %q", "api-secret", result.Secret)
	}
}
