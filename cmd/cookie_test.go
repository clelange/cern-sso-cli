package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

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
