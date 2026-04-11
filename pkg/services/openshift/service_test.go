package openshift

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

func TestFetchLoginCommandUsesConfiguredAuthHost(t *testing.T) {
	t.Parallel()

	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("sso"); err != nil {
			http.Error(w, "missing SSO cookie", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `<html><body><pre>oc login --token=sha256~test-token --server=https://api.example:6443</pre></body></html>`)
	}))
	defer authServer.Close()

	oauthServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token/request":
			http.Redirect(w, r, authServer.URL+"/display", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	authURL, err := url.Parse(authServer.URL)
	if err != nil {
		t.Fatalf("failed to parse auth server URL: %v", err)
	}

	result, err := FetchLoginCommand(
		oauthServer.URL,
		"https://paas.example",
		authURL.Host,
		[]*http.Cookie{{Name: "sso", Value: "ok", Path: "/"}},
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("FetchLoginCommand failed: %v", err)
	}

	if result.Command == "" {
		t.Fatal("expected login command")
	}
	if result.Token != "sha256~test-token" {
		t.Fatalf("expected token %q, got %q", "sha256~test-token", result.Token)
	}
	if result.Server != "https://api.example:6443" {
		t.Fatalf("expected server %q, got %q", "https://api.example:6443", result.Server)
	}
}

func TestParseTokenFromPageBuildsCommandFromTokenOnlyPage(t *testing.T) {
	t.Parallel()

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(`
		<html>
			<body>
				<code>sha256~test-token</code>
			</body>
		</html>
	`))
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	result := parseTokenFromPage(doc, "https://paas.example")
	if result.Command != "oc login --token=sha256~test-token --server=https://api.paas.example:6443" {
		t.Fatalf("unexpected login command %q", result.Command)
	}
	if result.Token != "sha256~test-token" {
		t.Fatalf("expected token %q, got %q", "sha256~test-token", result.Token)
	}
	if result.Server != "https://api.paas.example:6443" {
		t.Fatalf("expected server %q, got %q", "https://api.paas.example:6443", result.Server)
	}
}
