package openshift

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

type deviceExchangeTestOverrides struct {
	cacheDir string
	now      func() time.Time
}

func setupDeviceExchangeTest(t *testing.T, opts deviceExchangeTestOverrides) {
	t.Helper()

	oldLookupTXT := lookupTXT
	oldNow := deviceExchangeTimeNow
	oldUserCache := deviceExchangeUserCache
	oldStart := startDeviceAuthorization
	oldWait := waitForDeviceToken
	oldExchange := tokenExchange
	oldRefresh := tokenRefresh

	t.Cleanup(func() {
		lookupTXT = oldLookupTXT
		deviceExchangeTimeNow = oldNow
		deviceExchangeUserCache = oldUserCache
		startDeviceAuthorization = oldStart
		waitForDeviceToken = oldWait
		tokenExchange = oldExchange
		tokenRefresh = oldRefresh
	})

	if opts.cacheDir == "" {
		opts.cacheDir = t.TempDir()
	}
	deviceExchangeUserCache = func() (string, error) { return opts.cacheDir, nil }

	if opts.now != nil {
		deviceExchangeTimeNow = opts.now
	}
}

func TestFetchLoginCommandWithDeviceExchangeUsesCachedAudienceToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setupDeviceExchangeTest(t, deviceExchangeTestOverrides{
		now: func() time.Time { return now },
	})

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer audience-access" {
			t.Fatalf("expected Authorization header %q, got %q", "Bearer audience-access", got)
		}
		if got := r.URL.Query().Get("redirect-uri"); got != openShiftTokenRedirectURI {
			t.Fatalf("expected redirect-uri %q, got %q", openShiftTokenRedirectURI, got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "sha256~api-token"})
	}))
	defer server.Close()

	lookupTXT = staticLookupTXT(server.URL)
	startDeviceAuthorization = func(auth.OIDCConfig) (*auth.DeviceAuthorizationSession, error) {
		t.Fatal("device authorization should not start when audience token is cached")
		return nil, nil
	}
	waitForDeviceToken = func(*auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		t.Fatal("WaitForToken should not be called when audience token is cached")
		return nil, nil
	}
	tokenExchange = func(auth.OIDCConfig, string, string) (*auth.TokenResponse, error) {
		t.Fatal("token exchange should not be called when audience token is cached")
		return nil, nil
	}
	tokenRefresh = func(auth.OIDCConfig, string) (*auth.TokenResponse, error) {
		t.Fatal("token refresh should not be called when audience token is cached")
		return nil, nil
	}

	if err := saveTokenCache(audienceCachePath("paas_id"), &auth.TokenResponse{
		AccessToken: "audience-access",
		ExpiresIn:   3600,
	}); err != nil {
		t.Fatalf("failed to seed audience cache: %v", err)
	}

	result, err := FetchLoginCommandWithDeviceExchange("https://paas.cern.ch", false, nil, nil)
	if err != nil {
		t.Fatalf("FetchLoginCommandWithDeviceExchange failed: %v", err)
	}

	if result.Token != "sha256~api-token" {
		t.Fatalf("expected OpenShift token %q, got %q", "sha256~api-token", result.Token)
	}
	if result.Server != "https://api.paas.okd.cern.ch" {
		t.Fatalf("expected server %q, got %q", "https://api.paas.okd.cern.ch", result.Server)
	}
}

func TestFetchLoginCommandWithDeviceExchangeRecoversFromRejectedCachedAudienceToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setupDeviceExchangeTest(t, deviceExchangeTestOverrides{
		now: func() time.Time { return now },
	})

	if err := saveTokenCache(audienceCachePath("paas_id"), &auth.TokenResponse{
		AccessToken: "stale-audience",
		ExpiresIn:   4 * 3600,
	}); err != nil {
		t.Fatalf("failed to seed audience cache: %v", err)
	}
	if err := saveTokenCache(loginApplicationCachePath("okd4-sso-login-application"), &auth.TokenResponse{
		AccessToken: "cached-login",
		ExpiresIn:   3600,
	}); err != nil {
		t.Fatalf("failed to seed login cache: %v", err)
	}

	mintCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mintCalls++
		switch mintCalls {
		case 1:
			if got := r.Header.Get("Authorization"); got != "Bearer stale-audience" {
				t.Fatalf("expected Authorization header %q, got %q", "Bearer stale-audience", got)
			}
			http.Error(w, "stale token", http.StatusUnauthorized)
		case 2:
			if got := r.Header.Get("Authorization"); got != "Bearer fresh-audience" {
				t.Fatalf("expected Authorization header %q, got %q", "Bearer fresh-audience", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "sha256~api-token"})
		default:
			t.Fatalf("unexpected mint attempt %d", mintCalls)
		}
	}))
	defer server.Close()

	lookupTXT = staticLookupTXT(server.URL)
	startDeviceAuthorization = func(auth.OIDCConfig) (*auth.DeviceAuthorizationSession, error) {
		t.Fatal("device authorization should not start during audience-token recovery")
		return nil, nil
	}
	waitForDeviceToken = func(*auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		t.Fatal("WaitForToken should not be called during audience-token recovery")
		return nil, nil
	}

	refreshCalls := 0
	tokenRefresh = func(auth.OIDCConfig, string) (*auth.TokenResponse, error) {
		refreshCalls++
		t.Fatal("token refresh should not be called when login token cache is still valid")
		return nil, nil
	}

	exchangeCalls := 0
	tokenExchange = func(cfg auth.OIDCConfig, subjectToken string, audience string) (*auth.TokenResponse, error) {
		exchangeCalls++
		if subjectToken != "cached-login" {
			t.Fatalf("unexpected subject token %q", subjectToken)
		}
		if audience != "paas_id" {
			t.Fatalf("unexpected audience %q", audience)
		}
		return &auth.TokenResponse{
			AccessToken: "fresh-audience",
			ExpiresIn:   1800,
		}, nil
	}

	result, err := FetchLoginCommandWithDeviceExchange("https://paas.cern.ch", false, nil, nil)
	if err != nil {
		t.Fatalf("FetchLoginCommandWithDeviceExchange failed: %v", err)
	}

	if result.Token != "sha256~api-token" {
		t.Fatalf("expected OpenShift token %q, got %q", "sha256~api-token", result.Token)
	}
	if exchangeCalls != 1 {
		t.Fatalf("expected %d token exchange call, got %d", 1, exchangeCalls)
	}
	if refreshCalls != 0 {
		t.Fatalf("expected %d refresh calls, got %d", 0, refreshCalls)
	}
	if mintCalls != 2 {
		t.Fatalf("expected %d mint attempts, got %d", 2, mintCalls)
	}

	audienceRecord, err := loadTokenCache(audienceCachePath("paas_id"))
	if err != nil {
		t.Fatalf("failed to load audience cache: %v", err)
	}
	if audienceRecord.AccessToken != "fresh-audience" {
		t.Fatalf("expected refreshed audience token %q, got %q", "fresh-audience", audienceRecord.AccessToken)
	}
}

func TestFetchLoginCommandWithDeviceExchangeRefreshesLoginTokenAfterRejectedCachedAudienceToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setupDeviceExchangeTest(t, deviceExchangeTestOverrides{
		now: func() time.Time { return now },
	})

	if err := saveTokenCache(audienceCachePath("paas_id"), &auth.TokenResponse{
		AccessToken: "stale-audience",
		ExpiresIn:   4 * 3600,
	}); err != nil {
		t.Fatalf("failed to seed audience cache: %v", err)
	}
	if err := saveTokenCache(loginApplicationCachePath("okd4-sso-login-application"), &auth.TokenResponse{
		AccessToken:  "expired-login",
		RefreshToken: "refresh-me",
		ExpiresIn:    60,
	}); err != nil {
		t.Fatalf("failed to seed login cache: %v", err)
	}

	now = now.Add(2 * time.Hour)

	mintCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mintCalls++
		switch mintCalls {
		case 1:
			if got := r.Header.Get("Authorization"); got != "Bearer stale-audience" {
				t.Fatalf("expected Authorization header %q, got %q", "Bearer stale-audience", got)
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		case 2:
			if got := r.Header.Get("Authorization"); got != "Bearer refreshed-audience" {
				t.Fatalf("expected Authorization header %q, got %q", "Bearer refreshed-audience", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "sha256~api-token"})
		default:
			t.Fatalf("unexpected mint attempt %d", mintCalls)
		}
	}))
	defer server.Close()

	lookupTXT = staticLookupTXT(server.URL)
	startDeviceAuthorization = func(auth.OIDCConfig) (*auth.DeviceAuthorizationSession, error) {
		t.Fatal("device authorization should not start when login token refresh succeeds")
		return nil, nil
	}
	waitForDeviceToken = func(*auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		t.Fatal("WaitForToken should not be called when login token refresh succeeds")
		return nil, nil
	}

	refreshCalls := 0
	tokenRefresh = func(cfg auth.OIDCConfig, refreshToken string) (*auth.TokenResponse, error) {
		refreshCalls++
		if cfg.ClientID != "okd4-sso-login-application" {
			t.Fatalf("unexpected client id %q", cfg.ClientID)
		}
		if refreshToken != "refresh-me" {
			t.Fatalf("unexpected refresh token %q", refreshToken)
		}
		return &auth.TokenResponse{
			AccessToken:  "refreshed-login",
			RefreshToken: "refresh-new",
			ExpiresIn:    3600,
		}, nil
	}

	exchangeCalls := 0
	tokenExchange = func(cfg auth.OIDCConfig, subjectToken string, audience string) (*auth.TokenResponse, error) {
		exchangeCalls++
		if subjectToken != "refreshed-login" {
			t.Fatalf("unexpected subject token %q", subjectToken)
		}
		if audience != "paas_id" {
			t.Fatalf("unexpected audience %q", audience)
		}
		return &auth.TokenResponse{
			AccessToken: "refreshed-audience",
			ExpiresIn:   1800,
		}, nil
	}

	result, err := FetchLoginCommandWithDeviceExchange("https://paas.cern.ch", false, nil, nil)
	if err != nil {
		t.Fatalf("FetchLoginCommandWithDeviceExchange failed: %v", err)
	}

	if result.Token != "sha256~api-token" {
		t.Fatalf("expected OpenShift token %q, got %q", "sha256~api-token", result.Token)
	}
	if refreshCalls != 1 {
		t.Fatalf("expected %d refresh call, got %d", 1, refreshCalls)
	}
	if exchangeCalls != 1 {
		t.Fatalf("expected %d token exchange call, got %d", 1, exchangeCalls)
	}
	if mintCalls != 2 {
		t.Fatalf("expected %d mint attempts, got %d", 2, mintCalls)
	}

	loginRecord, err := loadTokenCache(loginApplicationCachePath("okd4-sso-login-application"))
	if err != nil {
		t.Fatalf("failed to load login cache: %v", err)
	}
	if loginRecord.AccessToken != "refreshed-login" {
		t.Fatalf("expected refreshed login token %q, got %q", "refreshed-login", loginRecord.AccessToken)
	}
}

func TestFetchLoginCommandWithDeviceExchangeRefreshesLoginTokenAndCachesResults(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setupDeviceExchangeTest(t, deviceExchangeTestOverrides{
		now: func() time.Time { return now },
	})

	if err := saveTokenCache(loginApplicationCachePath("okd4-sso-login-application"), &auth.TokenResponse{
		AccessToken:  "expired-login",
		RefreshToken: "refresh-me",
		ExpiresIn:    60,
	}); err != nil {
		t.Fatalf("failed to seed login cache: %v", err)
	}

	now = now.Add(2 * time.Hour)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer exchanged-access" {
			t.Fatalf("expected Authorization header %q, got %q", "Bearer exchanged-access", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "sha256~api-token"})
	}))
	defer server.Close()

	lookupTXT = staticLookupTXT(server.URL)
	startDeviceAuthorization = func(auth.OIDCConfig) (*auth.DeviceAuthorizationSession, error) {
		t.Fatal("device authorization should not start when refresh succeeds")
		return nil, nil
	}
	waitForDeviceToken = func(*auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		t.Fatal("WaitForToken should not be called when refresh succeeds")
		return nil, nil
	}
	tokenRefresh = func(cfg auth.OIDCConfig, refreshToken string) (*auth.TokenResponse, error) {
		if cfg.ClientID != "okd4-sso-login-application" {
			t.Fatalf("unexpected client id %q", cfg.ClientID)
		}
		if refreshToken != "refresh-me" {
			t.Fatalf("unexpected refresh token %q", refreshToken)
		}
		return &auth.TokenResponse{
			AccessToken:  "refreshed-login",
			RefreshToken: "refresh-new",
			ExpiresIn:    3600,
		}, nil
	}
	tokenExchange = func(cfg auth.OIDCConfig, subjectToken string, audience string) (*auth.TokenResponse, error) {
		if subjectToken != "refreshed-login" {
			t.Fatalf("unexpected subject token %q", subjectToken)
		}
		if audience != "paas_id" {
			t.Fatalf("unexpected audience %q", audience)
		}
		return &auth.TokenResponse{
			AccessToken:  "exchanged-access",
			RefreshToken: "audience-refresh",
			ExpiresIn:    1800,
		}, nil
	}

	result, err := FetchLoginCommandWithDeviceExchange("https://api.paas.okd.cern.ch", false, nil, nil)
	if err != nil {
		t.Fatalf("FetchLoginCommandWithDeviceExchange failed: %v", err)
	}

	if result.Token != "sha256~api-token" {
		t.Fatalf("expected OpenShift token %q, got %q", "sha256~api-token", result.Token)
	}

	loginRecord, err := loadTokenCache(loginApplicationCachePath("okd4-sso-login-application"))
	if err != nil {
		t.Fatalf("failed to load login cache: %v", err)
	}
	if loginRecord.AccessToken != "refreshed-login" {
		t.Fatalf("expected refreshed login token %q, got %q", "refreshed-login", loginRecord.AccessToken)
	}

	audienceRecord, err := loadTokenCache(audienceCachePath("paas_id"))
	if err != nil {
		t.Fatalf("failed to load audience cache: %v", err)
	}
	if audienceRecord.AccessToken != "exchanged-access" {
		t.Fatalf("expected exchanged audience token %q, got %q", "exchanged-access", audienceRecord.AccessToken)
	}
}

func TestFetchLoginCommandWithDeviceExchangeFallsBackToDeviceAuthorizationWhenRefreshFails(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setupDeviceExchangeTest(t, deviceExchangeTestOverrides{
		now: func() time.Time { return now },
	})

	if err := saveTokenCache(loginApplicationCachePath("okd4-sso-login-application"), &auth.TokenResponse{
		AccessToken:  "expired-login",
		RefreshToken: "refresh-me",
		ExpiresIn:    60,
	}); err != nil {
		t.Fatalf("failed to seed login cache: %v", err)
	}

	now = now.Add(2 * time.Hour)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer exchanged-access" {
			t.Fatalf("expected Authorization header %q, got %q", "Bearer exchanged-access", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "sha256~api-token"})
	}))
	defer server.Close()

	lookupTXT = staticLookupTXT(server.URL)

	promptCalls := 0
	tokenRefresh = func(auth.OIDCConfig, string) (*auth.TokenResponse, error) {
		return nil, errors.New("refresh failed")
	}
	startDeviceAuthorization = func(cfg auth.OIDCConfig) (*auth.DeviceAuthorizationSession, error) {
		if cfg.ClientID != "okd4-sso-login-application" {
			t.Fatalf("unexpected client id %q", cfg.ClientID)
		}
		return &auth.DeviceAuthorizationSession{
			Prompt: auth.DeviceAuthorizationPrompt{
				UserCode: "ABCD-EFGH",
			},
		}, nil
	}
	waitForDeviceToken = func(*auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		return &auth.TokenResponse{
			AccessToken:  "device-login",
			RefreshToken: "device-refresh",
			ExpiresIn:    3600,
		}, nil
	}
	tokenExchange = func(auth.OIDCConfig, string, string) (*auth.TokenResponse, error) {
		return &auth.TokenResponse{
			AccessToken: "exchanged-access",
			ExpiresIn:   1800,
		}, nil
	}

	_, err := FetchLoginCommandWithDeviceExchange("https://oauth-openshift.paas.cern.ch/oauth/token/request", false, nil, func(prompt auth.DeviceAuthorizationPrompt) {
		promptCalls++
		if prompt.UserCode != "ABCD-EFGH" {
			t.Fatalf("unexpected prompt user code %q", prompt.UserCode)
		}
	})
	if err != nil {
		t.Fatalf("FetchLoginCommandWithDeviceExchange failed: %v", err)
	}

	if promptCalls != 1 {
		t.Fatalf("expected prompt callback to be invoked once, got %d", promptCalls)
	}

	loginRecord, err := loadTokenCache(loginApplicationCachePath("okd4-sso-login-application"))
	if err != nil {
		t.Fatalf("failed to load login cache: %v", err)
	}
	if loginRecord.AccessToken != "device-login" {
		t.Fatalf("expected device login token %q, got %q", "device-login", loginRecord.AccessToken)
	}
}

func TestFetchLoginCommandWithDeviceExchangeDoesNotRetryNonAuthAudienceMintFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	setupDeviceExchangeTest(t, deviceExchangeTestOverrides{
		now: func() time.Time { return now },
	})

	if err := saveTokenCache(audienceCachePath("paas_id"), &auth.TokenResponse{
		AccessToken: "stale-audience",
		ExpiresIn:   3600,
	}); err != nil {
		t.Fatalf("failed to seed audience cache: %v", err)
	}

	mintCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mintCalls++
		http.Error(w, "upstream failed", http.StatusBadGateway)
	}))
	defer server.Close()

	lookupTXT = staticLookupTXT(server.URL)
	startDeviceAuthorization = func(auth.OIDCConfig) (*auth.DeviceAuthorizationSession, error) {
		t.Fatal("device authorization should not start for non-auth mint failures")
		return nil, nil
	}
	waitForDeviceToken = func(*auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		t.Fatal("WaitForToken should not be called for non-auth mint failures")
		return nil, nil
	}
	tokenExchange = func(auth.OIDCConfig, string, string) (*auth.TokenResponse, error) {
		t.Fatal("token exchange should not run for non-auth mint failures")
		return nil, nil
	}
	tokenRefresh = func(auth.OIDCConfig, string) (*auth.TokenResponse, error) {
		t.Fatal("token refresh should not run for non-auth mint failures")
		return nil, nil
	}

	_, err := FetchLoginCommandWithDeviceExchange("https://paas.cern.ch", false, nil, nil)
	if err == nil {
		t.Fatal("expected mint failure")
	}
	if mintCalls != 1 {
		t.Fatalf("expected %d mint attempt, got %d", 1, mintCalls)
	}

	var exchangeErr *openShiftAPITokenExchangeError
	if !errors.As(err, &exchangeErr) {
		t.Fatalf("expected OpenShift token exchange error, got %T", err)
	}
	if exchangeErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, exchangeErr.StatusCode)
	}
	if exchangeErr.Body != "upstream failed" {
		t.Fatalf("expected response body %q, got %q", "upstream failed", exchangeErr.Body)
	}
}

func TestExchangeOpenShiftAPITokenErrorsOnBadResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadGateway)
	}))
	defer server.Close()

	_, err := exchangeOpenShiftAPIToken(server.URL, "access-token", false)
	if err == nil {
		t.Fatal("expected token exchange error for bad status")
	}

	var exchangeErr *openShiftAPITokenExchangeError
	if !errors.As(err, &exchangeErr) {
		t.Fatalf("expected OpenShift token exchange error, got %T", err)
	}
	if exchangeErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, exchangeErr.StatusCode)
	}
	if exchangeErr.Body != "bad request" {
		t.Fatalf("expected response body %q, got %q", "bad request", exchangeErr.Body)
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("expected error to include response body, got %q", err.Error())
	}
}

func TestExchangeOpenShiftAPITokenErrorsOnMissingToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"unexpected": "value"})
	}))
	defer server.Close()

	if _, err := exchangeOpenShiftAPIToken(server.URL, "access-token", false); err == nil {
		t.Fatal("expected token exchange error for missing token")
	}
}

func TestSanitizeCacheKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "preserves safe characters",
			input: "Login-App_01.prod",
			want:  "Login-App_01.prod",
		},
		{
			name:  "replaces unsafe characters",
			input: "audience/id with spaces",
			want:  "audience_id_with_spaces",
		},
		{
			name:  "maps punctuation to underscores",
			input: "!!!",
			want:  "___",
		},
		{
			name:  "falls back for empty input",
			input: "",
			want:  "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeCacheKey(tt.input); got != tt.want {
				t.Fatalf("expected sanitized cache key %q, got %q", tt.want, got)
			}
		})
	}
}

func staticLookupTXT(tokenExchangeURL string) func(string) ([]string, error) {
	return func(name string) ([]string, error) {
		if name != "_config.paas.okd.cern.ch" {
			return nil, errors.New("unexpected lookup name")
		}
		return []string{
			"api_url=https://api.paas.okd.cern.ch",
			"token_exchange_url=" + tokenExchangeURL,
			"audience_id=paas_id",
			"login_application_id=okd4-sso-login-application",
			"auth_url=https://auth.cern.ch/auth/realms/cern",
		}, nil
	}
}
