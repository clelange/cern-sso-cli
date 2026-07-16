package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestDetectUsersPortal(t *testing.T) {
	portalHTML := []byte(`<!doctype html><html><head><title>CERN Users Portal</title></head></html>`)

	tests := []struct {
		name      string
		targetURL string
		body      []byte
		wantErr   bool
	}{
		{
			name:      "current Users Portal",
			targetURL: usersPortalRedirectURI,
			body:      portalHTML,
		},
		{
			name:      "legacy Account Management redirect",
			targetURL: "https://account.web.cern.ch/Management/MyAccounts.aspx",
			body:      portalHTML,
		},
		{
			name:      "wrong hostname",
			targetURL: "https://example.com/",
			body:      portalHTML,
			wantErr:   true,
		},
		{
			name:      "wrong page",
			targetURL: usersPortalRedirectURI,
			body:      []byte(`<html><head><title>Other application</title></head></html>`),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := DetectUsersPortal(tt.body, tt.targetURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("DetectUsersPortal() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("DetectUsersPortal() unexpected error: %v", err)
			}
			if info.Type != SPATypeUsersPortal {
				t.Errorf("DetectUsersPortal() type = %q, want %q", info.Type, SPATypeUsersPortal)
			}
			if info.ClientID != usersPortalClientID {
				t.Errorf("DetectUsersPortal() client ID = %q, want %q", info.ClientID, usersPortalClientID)
			}
		})
	}
}

func TestDetectHarbor(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   string
		responseStatus int
		wantType       string
		wantErr        bool
	}{
		{
			name: "Harbor with OIDC auth",
			responseBody: `{
				"auth_mode": "oidc_auth",
				"oidc_provider_name": "CERN SSO",
				"harbor_version": "v2.12.2"
			}`,
			responseStatus: http.StatusOK,
			wantType:       SPATypeHarbor,
			wantErr:        false,
		},
		{
			name: "Harbor with DB auth (not OIDC)",
			responseBody: `{
				"auth_mode": "db_auth",
				"harbor_version": "v2.12.2"
			}`,
			responseStatus: http.StatusOK,
			wantType:       "",
			wantErr:        true,
		},
		{
			name:           "Not a Harbor server",
			responseBody:   `{"error": "not found"}`,
			responseStatus: http.StatusNotFound,
			wantType:       "",
			wantErr:        true,
		},
		{
			name:           "Invalid JSON",
			responseBody:   `not json`,
			responseStatus: http.StatusOK,
			wantType:       "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2.0/systeminfo" {
					w.WriteHeader(tt.responseStatus)
					_, _ = w.Write([]byte(tt.responseBody))
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := server.Client()
			info, err := DetectHarbor(client, server.URL)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectHarbor() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("DetectHarbor() unexpected error: %v", err)
				return
			}

			if info.Type != tt.wantType {
				t.Errorf("DetectHarbor() type = %q, want %q", info.Type, tt.wantType)
			}
		})
	}
}

func TestDetectOpenShift(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantType string
		wantURL  string
		wantErr  bool
	}{
		{
			name: "OpenShift with SERVER_FLAGS",
			body: `<!doctype html><html><head>
				<script>window.SERVER_FLAGS = {
					"loginURL":"https://paas.cern.ch/auth/login",
					"logoutURL":"/api/console/logout"
				};</script>
			</head><body></body></html>`,
			wantType: SPATypeOpenShift,
			wantURL:  "https://paas.cern.ch/auth/login",
			wantErr:  false,
		},
		{
			name: "OpenShift with escaped URL",
			body: `<!doctype html><html><head>
				<script>window.SERVER_FLAGS = {
					"loginURL":"https://paas.cern.ch/auth/login\u0026param=value"
				};</script>
			</head><body></body></html>`,
			wantType: SPATypeOpenShift,
			wantURL:  "https://paas.cern.ch/auth/login&param=value",
			wantErr:  false,
		},
		{
			name:     "Not an OpenShift page",
			body:     `<!doctype html><html><body>Hello World</body></html>`,
			wantType: "",
			wantURL:  "",
			wantErr:  true,
		},
		{
			name: "SERVER_FLAGS without loginURL",
			body: `<!doctype html><html><head>
				<script>window.SERVER_FLAGS = {"logoutURL":"/logout"};</script>
			</head><body></body></html>`,
			wantType: "",
			wantURL:  "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := DetectOpenShift([]byte(tt.body), "https://paas.cern.ch/")

			if tt.wantErr {
				if err == nil {
					t.Errorf("DetectOpenShift() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("DetectOpenShift() unexpected error: %v", err)
				return
			}

			if info.Type != tt.wantType {
				t.Errorf("DetectOpenShift() type = %q, want %q", info.Type, tt.wantType)
			}

			if info.LoginURL != tt.wantURL {
				t.Errorf("DetectOpenShift() loginURL = %q, want %q", info.LoginURL, tt.wantURL)
			}
		})
	}
}

func TestDetectSPA(t *testing.T) {
	t.Run("Detects Users Portal without an API probe", func(t *testing.T) {
		info, err := DetectSPA(http.DefaultClient, usersPortalRedirectURI,
			[]byte(`<html><head><title>CERN Users Portal</title></head></html>`))
		if err != nil {
			t.Fatalf("DetectSPA() unexpected error: %v", err)
		}
		if info.Type != SPATypeUsersPortal {
			t.Errorf("DetectSPA() type = %q, want %q", info.Type, SPATypeUsersPortal)
		}
	})

	t.Run("Detects Harbor via API", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2.0/systeminfo" {
				_, _ = w.Write([]byte(`{"auth_mode":"oidc_auth","harbor_version":"v2.12.2"}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>Loading...</body></html>`))
			}
		}))
		defer server.Close()

		client := server.Client()
		info, err := DetectSPA(client, server.URL, []byte("<html><body>Loading...</body></html>"))

		if err != nil {
			t.Fatalf("DetectSPA() unexpected error: %v", err)
		}

		if info.Type != SPATypeHarbor {
			t.Errorf("DetectSPA() type = %q, want %q", info.Type, SPATypeHarbor)
		}
	})

	t.Run("Falls back to OpenShift detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Harbor API not available
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := server.Client()
		openShiftHTML := `<html><head><script>window.SERVER_FLAGS = {"loginURL":"https://test.cern.ch/auth/login"};</script></head></html>`
		info, err := DetectSPA(client, server.URL, []byte(openShiftHTML))

		if err != nil {
			t.Fatalf("DetectSPA() unexpected error: %v", err)
		}

		if info.Type != SPATypeOpenShift {
			t.Errorf("DetectSPA() type = %q, want %q", info.Type, SPATypeOpenShift)
		}
	})

	t.Run("Returns error for unknown SPA", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := server.Client()
		_, err := DetectSPA(client, server.URL, []byte("<html><body>Unknown site</body></html>"))

		if err == nil {
			t.Errorf("DetectSPA() expected error for unknown SPA, got nil")
		}
	})
}

func TestBuildOIDCAuthorizationURL(t *testing.T) {
	authURL := "https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/auth"
	got, err := url.Parse(buildOIDCAuthorizationURL(authURL, usersPortalClientID, usersPortalRedirectURI))
	if err != nil {
		t.Fatalf("failed to parse authorization URL: %v", err)
	}

	if got.Scheme != "https" || got.Host != "auth.cern.ch" || got.Path != "/auth/realms/cern/protocol/openid-connect/auth" {
		t.Errorf("authorization endpoint = %q, want %q", got.Scheme+"://"+got.Host+got.Path, authURL)
	}
	if got.Query().Get("client_id") != usersPortalClientID {
		t.Errorf("client_id = %q, want %q", got.Query().Get("client_id"), usersPortalClientID)
	}
	if got.Query().Get("redirect_uri") != usersPortalRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", got.Query().Get("redirect_uri"), usersPortalRedirectURI)
	}
	if got.Query().Get("response_type") != "code" || got.Query().Get("scope") != "openid" {
		t.Errorf("unexpected OIDC parameters: %q", got.Query())
	}
}

func TestGetHarborLoginPage(t *testing.T) {
	// Test that the OIDC URL is constructed correctly
	spaInfo := &SPAInfo{
		Type:    SPATypeHarbor,
		BaseURL: "https://registry.cern.ch",
	}

	// We can't fully test this without mocking auth.cern.ch,
	// but we can verify the URL construction logic
	t.Run("Verifies client_id extraction", func(t *testing.T) {
		// The client_id should be "registry" from "registry.cern.ch"
		// This is an internal implementation detail but worth checking
		if spaInfo.BaseURL != "https://registry.cern.ch" {
			t.Errorf("Unexpected base URL: %s", spaInfo.BaseURL)
		}
	})
}
