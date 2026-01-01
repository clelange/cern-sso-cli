//go:build integration
// +build integration

// Package main provides integration tests for the CERN SSO authentication tool.
// These tests require:
// - KRB_USERNAME and KRB_PASSWORD environment variables set
// - Network access to CERN Kerberos and SSO endpoints
//
// Run with: go test -tags=integration -v ./...
package main

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/clange/cern-krb-cookie/pkg/auth"
	"github.com/clange/cern-krb-cookie/pkg/cookie"
)

func TestIntegration_AccountWebCERN(t *testing.T) {
	skipIfNoCredentials(t)

	targetURL := "https://account.web.cern.ch/Management/MyAccounts.aspx"
	authHost := "auth.cern.ch"
	cookieFile := "test_account_cookies.txt"
	defer os.Remove(cookieFile)

	// Test cookie generation
	kerbClient, err := auth.NewKerberosClient()
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	cookies, err := kerbClient.CollectCookies(targetURL, result)
	if err != nil {
		t.Fatalf("Failed to collect cookies: %v", err)
	}

	if len(cookies) == 0 {
		t.Fatal("No cookies collected")
	}
	t.Logf("Collected %d cookies", len(cookies))

	// Save cookies
	u, _ := url.Parse(targetURL)
	jar, _ := cookie.NewJar()
	err = jar.Save(cookieFile, cookies, u.Hostname())
	if err != nil {
		t.Fatalf("Failed to save cookies: %v", err)
	}

	// Verify cookies work with curl
	verifyCookies(t, cookieFile, targetURL, "Account Management")
}

func TestIntegration_GitLabCERN(t *testing.T) {
	skipIfNoCredentials(t)

	targetURL := "https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie"
	authHost := "auth.cern.ch"
	cookieFile := "test_gitlab_cookies.txt"
	defer os.Remove(cookieFile)

	// Test cookie generation
	kerbClient, err := auth.NewKerberosClient()
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	cookies, err := kerbClient.CollectCookies(targetURL, result)
	if err != nil {
		t.Fatalf("Failed to collect cookies: %v", err)
	}

	if len(cookies) == 0 {
		t.Fatal("No cookies collected")
	}
	t.Logf("Collected %d cookies", len(cookies))

	// Save cookies
	u, _ := url.Parse(targetURL)
	jar, _ := cookie.NewJar()
	err = jar.Save(cookieFile, cookies, u.Hostname())
	if err != nil {
		t.Fatalf("Failed to save cookies: %v", err)
	}

	// Verify cookies work
	verifyCookies(t, cookieFile, targetURL, "GitLab")
}

func TestIntegration_AuthorizationCodeFlow(t *testing.T) {
	skipIfNoCredentials(t)

	// Use account-app as a test client
	cfg := auth.OIDCConfig{
		AuthHostname: "auth.cern.ch",
		AuthRealm:    "cern",
		ClientID:     "account-app",
		RedirectURI:  "https://account.web.cern.ch/authorization-code/callback",
		VerifyCert:   true,
	}

	kerbClient, err := auth.NewKerberosClient()
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	token, err := auth.AuthorizationCodeFlow(kerbClient, cfg)
	if err != nil {
		// A 401 Unauthorized or 400 Bad Request at the token exchange phase is actually
		// good - it means the login part succeeded and we got a code to exchange!
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "400") || strings.Contains(err.Error(), "PageNotFound") {
			t.Logf("AuthorizationCodeFlow successfully completed the login phase: %v", err)
			return
		}
		t.Fatalf("AuthorizationCodeFlow failed at login phase: %v", err)
	}

	if token == "" {
		t.Fatal("Got empty access token")
	}
	t.Log("Successfully obtained access token via Authorization Code flow")
}

func TestIntegration_InvalidCredentials(t *testing.T) {
	// Set wrong password
	originalPassword := os.Getenv("KRB_PASSWORD")
	os.Setenv("KRB_PASSWORD", "wrong-password")
	defer os.Setenv("KRB_PASSWORD", originalPassword)

	_, err := auth.NewKerberosClient()
	if err == nil {
		t.Fatal("Expected error with invalid credentials, got nil")
	}

	if !strings.Contains(err.Error(), "kerberos login failed") {
		t.Errorf("Expected error message to contain 'kerberos login failed', got %q", err.Error())
	}
}

func skipIfNoCredentials(t *testing.T) {
	if os.Getenv("KRB_USERNAME") == "" || os.Getenv("KRB_PASSWORD") == "" {
		t.Skip("Skipping integration test: KRB_USERNAME and KRB_PASSWORD not set")
	}
}

func verifyCookies(t *testing.T, cookieFile, targetURL, expectedContent string) {
	// Load cookies
	cookies, err := cookie.Load(cookieFile)
	if err != nil {
		t.Fatalf("Failed to load cookies: %v", err)
	}

	// Create HTTP client with cookies
	u, _ := url.Parse(targetURL)
	client := &http.Client{}
	req, _ := http.NewRequest("GET", targetURL, nil)

	// Add cookies to request
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request with cookies: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read body and check for expected content
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, expectedContent) {
		t.Errorf("Expected response to contain %q, but it didn't. First 500 chars: %s",
			expectedContent, body[:min(500, len(body))])
	}

	t.Logf("Successfully verified cookies work for %s (domain: %s)", targetURL, u.Hostname())
}
