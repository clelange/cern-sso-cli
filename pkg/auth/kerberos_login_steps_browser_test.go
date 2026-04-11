//go:build !nowebauthn
// +build !nowebauthn

package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/browser"
)

func TestTryBrowserLoginUsesBrowserAuthenticator(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()
	kc.webauthnProvider = &WebAuthnProvider{
		UseBrowser: true,
		Timeout:    15 * time.Second,
	}

	oldIsChromeAvailableFunc := isChromeAvailableFunc
	oldAuthenticateWithChromeFunc := authenticateWithChromeFunc
	defer func() {
		isChromeAvailableFunc = oldIsChromeAvailableFunc
		authenticateWithChromeFunc = oldAuthenticateWithChromeFunc
	}()

	isChromeAvailableFunc = func() bool { return true }
	authenticateWithChromeFunc = func(targetURL string, authHostname string, timeout time.Duration, env map[string]string) (*browser.AuthResult, error) {
		if timeout != 3*time.Minute {
			t.Fatalf("expected minimum browser timeout %v, got %v", 3*time.Minute, timeout)
		}
		if targetURL != "https://target.example" {
			t.Fatalf("expected target URL %q, got %q", "https://target.example", targetURL)
		}
		if authHostname != "auth.example" {
			t.Fatalf("expected auth host %q, got %q", "auth.example", authHostname)
		}
		return &browser.AuthResult{
			Cookies:  []*http.Cookie{{Name: "sso", Value: "ok"}},
			FinalURL: "https://target.example/callback",
			Username: "alice@CERN.CH",
		}, nil
	}

	result, handled, err := kc.tryBrowserLogin("https://target.example", "auth.example")
	if err != nil {
		t.Fatalf("tryBrowserLogin failed: %v", err)
	}
	if !handled {
		t.Fatal("expected browser login path to be handled")
	}
	if result.RedirectURI != "https://target.example/callback" {
		t.Fatalf("expected redirect URI %q, got %q", "https://target.example/callback", result.RedirectURI)
	}
	if result.Username != "alice@CERN.CH" {
		t.Fatalf("expected username %q, got %q", "alice@CERN.CH", result.Username)
	}
	if len(result.Cookies) != 1 || result.Cookies[0].Name != "sso" {
		t.Fatalf("expected browser cookies to be returned, got %#v", result.Cookies)
	}
}
