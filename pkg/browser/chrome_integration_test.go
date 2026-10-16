//go:build browserintegration

package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// These tests require Chrome and fail if it is missing. They use local servers
// and an isolated profile, without CERN credentials or WebAuthn hardware.
func TestBrowserIntegration_Authenticate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		button string
	}{
		{"CERN", `<a id="social-kerberos" href="/kerberos">Kerberos</a>`},
		{"legacy", `<a id="zocial-kerberos" href="/kerberos">Kerberos</a>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testBrowserAuthentication(t, tc.button)
		})
	}
}

func testBrowserAuthentication(t *testing.T, button string) {
	t.Helper()
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	var authURL string
	targetMux := http.NewServeMux()
	targetServer := httptest.NewTLSServer(targetMux)
	t.Cleanup(targetServer.Close)
	targetMux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, authURL+"/login", http.StatusFound)
	})
	targetMux.HandleFunc("/callback", func(w http.ResponseWriter, _ *http.Request) {
		// The callback is transient: completion must wait for the final URL.
		fmt.Fprint(w, `<html><body><script>setTimeout(() => location.replace('/done'), 1000)</script></body></html>`)
	})
	targetMux.HandleFunc("/done", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "sso", Value: "authenticated", Path: "/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		fmt.Fprint(w, "<html><body>Authenticated</body></html>")
	})

	authMux := http.NewServeMux()
	authServer := httptest.NewTLSServer(authMux)
	t.Cleanup(authServer.Close)
	// Different hostnames exercise extraction of cookies from both domains.
	authURL = strings.Replace(authServer.URL, "127.0.0.1", "localhost", 1)
	authMux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "<html><body>%s</body></html>", button)
	})
	authMux.HandleFunc("/kerberos", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "KEYCLOAK_REMEMBER_ME", Value: "username:alice", Path: "/auth/realms/cern/",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires,
		})
		http.Redirect(w, r, targetServer.URL+"/callback", http.StatusFound)
	})

	// Inspect the environment of the actual browser process before starting it.
	// Synthetic values verify both inheritance and credential-cache overrides.
	t.Setenv("CERN_SSO_TEST_INHERITED", "inherited")
	t.Setenv("KRB5CCNAME", "FILE:original")
	testDir := t.TempDir()
	envFile := filepath.Join(testDir, "browser-env")
	wrapper := filepath.Join(testDir, "chrome")
	const script = `#!/bin/sh
printf '%s\n' "$CERN_SSO_TEST_INHERITED" "$KRB5CCNAME" > "$CERN_SSO_TEST_ENV_FILE"
exec "$CERN_SSO_TEST_CHROME" "$@"
`
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := browserTestOptions(t, map[string]string{
		"KRB5CCNAME":             "FILE:test-cache",
		"CERN_SSO_TEST_ENV_FILE": envFile,
		"CERN_SSO_TEST_CHROME":   browserTestExecutable(t),
	})
	opts = append(opts, chromedp.ExecPath(wrapper))
	result, err := authenticateWithChrome(context.Background(), targetServer.URL+"/start",
		strings.TrimPrefix(authURL, "https://"), 30*time.Second, opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.FinalURL != targetServer.URL+"/done" || result.Username != "alice" {
		t.Fatalf("unexpected authentication result: URL=%q username=%q", result.FinalURL, result.Username)
	}
	cookies := make(map[string]*http.Cookie)
	for _, cookie := range result.Cookies {
		cookies[cookie.Name] = cookie
	}
	sso := cookies["sso"]
	if sso == nil || sso.Value != "authenticated" || sso.Domain != "127.0.0.1" || sso.Path != "/" ||
		!sso.Secure || !sso.HttpOnly || sso.SameSite != http.SameSiteLaxMode || !sso.Expires.IsZero() {
		t.Fatalf("session cookie attributes were not preserved: %#v", sso)
	}
	remember := cookies["KEYCLOAK_REMEMBER_ME"]
	if remember == nil || remember.Value != "username:alice" || remember.Domain != "localhost" ||
		remember.Path != "/auth/realms/cern/" || !remember.Secure || !remember.HttpOnly ||
		remember.SameSite != http.SameSiteStrictMode || !remember.Expires.Equal(expires) {
		t.Fatalf("auth-domain cookie attributes were not preserved: %#v", remember)
	}
	browserEnv, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(browserEnv) != "inherited\nFILE:test-cache\n" {
		t.Fatalf("browser environment was not inherited and overridden: %q", browserEnv)
	}
}

func TestBrowserIntegration_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html><body>Waiting for login</body></html>")
	}))
	t.Cleanup(server.Close)
	result, err := authenticateWithChrome(context.Background(), server.URL,
		strings.TrimPrefix(server.URL, "http://"), 8*time.Second, browserTestOptions(t, nil))
	if result != nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "authentication timed out") {
		t.Fatalf("expected authentication timeout, got result=%#v error=%v", result, err)
	}
}

func TestBrowserIntegration_Cancel(t *testing.T) {
	ready := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			select {
			case ready <- struct{}{}:
			default:
			}
			return
		}
		fmt.Fprint(w, `<html><body>Waiting for login<script>setTimeout(() => fetch('/ready'), 1000)</script></body></html>`)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := browserTestOptions(t, nil)
	done := make(chan error, 1)
	go func() {
		_, err := authenticateWithChrome(ctx, server.URL, strings.TrimPrefix(server.URL, "http://"), 30*time.Second, opts)
		done <- err
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("browser stopped before cancellation: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("browser did not reach the login page")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("browser did not stop after cancellation")
	}
}

func browserTestOptions(t *testing.T, env map[string]string) []chromedp.ExecAllocatorOption {
	t.Helper()
	opts := chromeAllocatorOptions(env, os.Getenv("CERN_SSO_TEST_VISIBLE_BROWSER") == "1")
	return append(opts,
		chromedp.ExecPath(browserTestExecutable(t)),
		chromedp.UserDataDir(t.TempDir()),
		// Only the local TLS fixture uses a self-signed certificate.
		chromedp.Flag("ignore-certificate-errors", true),
	)
}

func browserTestExecutable(t *testing.T) string {
	t.Helper()
	if chromePath := os.Getenv("CHROME_PATH"); chromePath != "" {
		if _, err := os.Stat(chromePath); err != nil {
			t.Fatalf("CHROME_PATH is not available: %v", err)
		}
		return chromePath
	}
	if runtime.GOOS == "darwin" {
		const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(chromePath); err == nil {
			return chromePath
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if chromePath, err := exec.LookPath(name); err == nil {
			return chromePath
		}
	}
	t.Fatal("browser integration tests require Chrome or Chromium; set CHROME_PATH to its executable")
	return ""
}
