package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/auth"
	cookiepkg "github.com/clelange/cern-sso-cli/pkg/cookie"
)

func TestRunCookieJSONOutputWhenReusingValidCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	jar, err := cookiepkg.NewJar()
	if err != nil {
		t.Fatalf("failed to create cookie jar: %v", err)
	}

	cookieFilePath := filepath.Join(t.TempDir(), "cookies.txt")
	cookies := []*http.Cookie{
		{
			Name:    "session",
			Value:   "abc123",
			Domain:  targetURL.Hostname(),
			Path:    "/",
			Expires: time.Now().Add(time.Hour),
		},
	}
	if err := jar.SaveWithUser(cookieFilePath, cookies, targetURL.Hostname(), "alice@CERN.CH"); err != nil {
		t.Fatalf("failed to save cookies: %v", err)
	}

	oldQuiet := quiet
	oldCookieURL := cookieURL
	oldCookieFile := cookieFile
	oldCookieAuthHost := cookieAuthHost
	oldCookieForce := cookieForce
	oldCookieInsecure := cookieInsecure
	oldCookieJSON := cookieJSON
	oldKrbUser := krbUser
	oldUseOTP := useOTP
	oldUseWebAuthn := useWebAuthn
	oldUsePassword := usePassword
	oldUseKeytab := useKeytab
	oldUseCCache := useCCache
	oldKeytabPath := keytabPath
	defer func() {
		quiet = oldQuiet
		cookieURL = oldCookieURL
		cookieFile = oldCookieFile
		cookieAuthHost = oldCookieAuthHost
		cookieForce = oldCookieForce
		cookieInsecure = oldCookieInsecure
		cookieJSON = oldCookieJSON
		krbUser = oldKrbUser
		useOTP = oldUseOTP
		useWebAuthn = oldUseWebAuthn
		usePassword = oldUsePassword
		useKeytab = oldUseKeytab
		useCCache = oldUseCCache
		keytabPath = oldKeytabPath
	}()

	quiet = false
	cookieURL = server.URL
	cookieFile = cookieFilePath
	cookieAuthHost = defaultAuthHostname
	cookieForce = false
	cookieInsecure = false
	cookieJSON = true
	krbUser = ""
	useOTP = false
	useWebAuthn = false
	usePassword = false
	useKeytab = false
	useCCache = false
	keytabPath = ""

	stdout, _ := captureStdoutStderr(t, func() {
		if err := runCookie(nil, nil); err != nil {
			t.Fatalf("runCookie failed: %v", err)
		}
	})

	var output CookieOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("expected JSON output, got %q: %v", stdout, err)
	}

	if output.File != cookieFilePath {
		t.Fatalf("expected file %q, got %q", cookieFilePath, output.File)
	}
	if output.Count != 1 {
		t.Fatalf("expected count 1, got %d", output.Count)
	}
	if output.User != "alice@CERN.CH" {
		t.Fatalf("expected user %q, got %q", "alice@CERN.CH", output.User)
	}
}

type testCookieSession struct {
	cookies   []*http.Cookie
	err       error
	closed    bool
	collected bool
}

func (s *testCookieSession) CollectCookies(_, _ string, _ *auth.LoginResult) ([]*http.Cookie, error) {
	s.collected = true
	return s.cookies, s.err
}

func (s *testCookieSession) Close() { s.closed = true }

func TestSaveCookiesFromAuthPropagatesErrorsInQuietMode(t *testing.T) {
	oldQuiet := quiet
	quiet = true
	t.Cleanup(func() { quiet = oldQuiet })

	collectionErr := errors.New("cookie collection failed")
	for _, tt := range []struct {
		name          string
		collectionErr error
		want          string
	}{
		{"collection", collectionErr, "failed to collect cookies"},
		{"save", nil, "failed to save cookies"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "file-not-directory")
			if err := os.WriteFile(parent, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			session := &testCookieSession{cookies: []*http.Cookie{{Name: "session", Value: "token"}}, err: tt.collectionErr}
			var result *CookieOutput
			var resultErr error
			stdout, stderr := captureStdoutStderr(t, func() {
				result, resultErr = saveCookiesFromAuth(session, filepath.Join(parent, "cookies.txt"), "https://portal.example.com", "auth.example.com", &auth.LoginResult{})
			})
			if result != nil || resultErr == nil || !strings.Contains(resultErr.Error(), tt.want) {
				t.Fatalf("expected actionable error, got %v, %v", result, resultErr)
			}
			if tt.collectionErr != nil && !errors.Is(resultErr, tt.collectionErr) {
				t.Fatalf("original error was lost: %v", resultErr)
			}
			if exitCodeForError(resultErr) != 1 || !session.closed {
				t.Fatal("error must fail the command and close the session")
			}
			if stdout != "" || stderr != "" {
				t.Fatalf("helper must return its error without success output: %q, %q", stdout, stderr)
			}
		})
	}
}

func TestSaveCookiesFromAuthUsesFullResultMetadata(t *testing.T) {
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	session := &testCookieSession{err: errors.New("must not re-fetch browser session")}
	filename := filepath.Join(t.TempDir(), "cookies.txt")
	output, err := saveCookiesFromAuth(session, filename, "https://portal.example.com", "auth.example.com", &auth.LoginResult{
		Username: "alice",
		Cookies: []*http.Cookie{
			{Name: "deleted", Domain: "auth.example.com", Path: "/auth", MaxAge: -1},
			{Name: "expired", Domain: "auth.example.com", Path: "/auth", Expires: time.Now().Add(-time.Hour)},
			{Name: "app", Value: "app-token", Domain: "portal.example.com", Path: "/private", Secure: true, HttpOnly: true, Expires: expires},
			{Name: "sso", Value: "sso-token", Domain: "auth.example.com", Path: "/auth", Secure: true, HttpOnly: true, Expires: expires},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.collected || !session.closed || output.Count != 2 || output.User != "alice@CERN.CH" {
		t.Fatalf("unexpected output or session use: %+v, %+v", output, session)
	}
	loaded, err := cookiepkg.Load(filename)
	if err != nil || len(loaded) != 2 {
		t.Fatalf("missing saved cookies: %v, %v", loaded, err)
	}
	for _, c := range loaded {
		if !c.Secure || !c.HttpOnly || c.Path == "/" || !c.Expires.Equal(expires) {
			t.Fatalf("saved cookie lost metadata: %#v", c)
		}
	}
}

func TestRunCookiePropagatesUpdateFailure(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cookies.txt")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verification succeeds, but the destination becomes unavailable before saving.
		if err := os.Rename(filename, filename+".original"); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(filename, 0700); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	jar, _ := cookiepkg.NewJar()
	if err := jar.Save(filename, []*http.Cookie{{Name: "session", Domain: u.Hostname(), Expires: time.Now().Add(time.Hour)}}, u.Hostname()); err != nil {
		t.Fatal(err)
	}

	oldQuiet, oldURL, oldFile, oldHost, oldForce, oldJSON := quiet, cookieURL, cookieFile, cookieAuthHost, cookieForce, cookieJSON
	t.Cleanup(func() {
		quiet, cookieURL, cookieFile, cookieAuthHost, cookieForce, cookieJSON = oldQuiet, oldURL, oldFile, oldHost, oldForce, oldJSON
	})
	quiet, cookieURL, cookieFile, cookieAuthHost, cookieForce, cookieJSON = true, server.URL, filename, "auth.example.com", false, true
	var resultErr error
	stdout, _ := captureStdoutStderr(t, func() { resultErr = runCookie(nil, nil) })
	if resultErr == nil || !strings.Contains(resultErr.Error(), "failed to update cookie file") || exitCodeForError(resultErr) != 1 {
		t.Fatalf("update failure did not fail the command: %v", resultErr)
	}
	if stdout != "" {
		t.Fatalf("command printed successful JSON despite save failure: %q", stdout)
	}
}
