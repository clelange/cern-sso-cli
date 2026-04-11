package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestFetchOpenShiftLoginCommandUsesConfiguredAuthHost(t *testing.T) {
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

	loginCmd, token, server, err := fetchOpenShiftLoginCommand(
		oauthServer.URL,
		"https://paas.example",
		authURL.Host,
		[]*http.Cookie{{Name: "sso", Value: "ok", Path: "/"}},
		false,
	)
	if err != nil {
		t.Fatalf("fetchOpenShiftLoginCommand failed: %v", err)
	}

	if loginCmd == "" {
		t.Fatal("expected login command")
	}
	if token != "sha256~test-token" {
		t.Fatalf("expected token %q, got %q", "sha256~test-token", token)
	}
	if server != "https://api.example:6443" {
		t.Fatalf("expected server %q, got %q", "https://api.example:6443", server)
	}
}
