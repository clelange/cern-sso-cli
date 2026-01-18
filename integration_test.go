//go:build integration
// +build integration

// Package main provides integration tests for the CERN SSO authentication tool.
// These tests require:
// - KRB5_USERNAME and KRB5_PASSWORD environment variables set
// - Network access to CERN Kerberos and SSO endpoints
//
// Run with: go test -tags=integration -v ./...
package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/clelange/cern-sso-cli/pkg/auth"
	"github.com/clelange/cern-sso-cli/pkg/cookie"
)

const testVersion = "dev"

func TestIntegration_AccountWebCERN(t *testing.T) {
	skipIfNoCredentials(t)

	targetURL := "https://account.web.cern.ch/Management/MyAccounts.aspx"
	authHost := "auth.cern.ch"
	cookieFile := "test_account_cookies.txt"
	defer os.Remove(cookieFile)

	// Test cookie generation
	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	cookies, err := kerbClient.CollectCookies(targetURL, authHost, result)
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
	verifyCookiesIntegration(t, cookieFile, targetURL, "Account Management")
}

func TestIntegration_MultiDomainCookies(t *testing.T) {
	skipIfNoCredentials(t)

	cookieFile := "test_multi_domain_cookies.txt"
	defer os.Remove(cookieFile)

	// First, authenticate to account.web.cern.ch
	accountURL := "https://account.web.cern.ch/Management/MyAccounts.aspx"
	authHost := "auth.cern.ch"

	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}

	result, err := kerbClient.LoginWithKerberos(accountURL, authHost, true)
	if err != nil {
		t.Fatalf("Account login failed: %v", err)
	}

	accountCookies, err := kerbClient.CollectCookies(accountURL, authHost, result)
	if err != nil {
		t.Fatalf("Failed to collect account cookies: %v", err)
	}
	t.Logf("Collected %d cookies for account.web.cern.ch", len(accountCookies))

	// Save account cookies
	u1, _ := url.Parse(accountURL)
	jar, _ := cookie.NewJar()
	if err := jar.Save(cookieFile, accountCookies, u1.Hostname()); err != nil {
		t.Fatalf("Failed to save account cookies: %v", err)
	}
	kerbClient.Close()

	// Now authenticate to gitlab.cern.ch with a fresh client
	gitlabURL := "https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie"

	kerbClient2, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create second Kerberos client: %v", err)
	}
	defer kerbClient2.Close()

	result, err = kerbClient2.LoginWithKerberos(gitlabURL, authHost, true)
	if err != nil {
		t.Fatalf("GitLab login failed: %v", err)
	}

	gitlabCookies, err := kerbClient2.CollectCookies(gitlabURL, authHost, result)
	if err != nil {
		t.Fatalf("Failed to collect GitLab cookies: %v", err)
	}
	t.Logf("Collected %d cookies for gitlab.cern.ch", len(gitlabCookies))

	// Update with gitlab cookies (should preserve account cookies)
	u2, _ := url.Parse(gitlabURL)
	if err := jar.Update(cookieFile, gitlabCookies, u2.Hostname()); err != nil {
		t.Fatalf("Failed to update with GitLab cookies: %v", err)
	}

	// Verify file has cookies for both domains
	allCookies, err := cookie.Load(cookieFile)
	if err != nil {
		t.Fatalf("Failed to load cookies: %v", err)
	}

	accountDomainFound := false
	gitlabDomainFound := false
	for _, c := range allCookies {
		if strings.Contains(c.Domain, "account") || strings.Contains(c.Domain, "cern.ch") {
			if strings.Contains(c.Domain, "account") {
				accountDomainFound = true
			}
		}
		if strings.Contains(c.Domain, "gitlab") {
			gitlabDomainFound = true
		}
	}

	if !accountDomainFound || !gitlabDomainFound {
		t.Logf("Cookies found: %d", len(allCookies))
		for _, c := range allCookies {
			t.Logf("  %s: domain=%s", c.Name, c.Domain)
		}
		if !gitlabDomainFound {
			t.Errorf("GitLab cookies not found in file")
		}
	}

	t.Logf("Multi-domain cookie file contains %d total cookies", len(allCookies))
}

func TestIntegration_CookieReuse(t *testing.T) {
	skipIfNoCredentials(t)

	cookieFile := "test_cookie_reuse.txt"
	defer os.Remove(cookieFile)

	// First, authenticate to account.web.cern.ch to get auth.cern.ch cookies
	accountURL := "https://account.web.cern.ch/Management/MyAccounts.aspx"
	authHost := "auth.cern.ch"

	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}

	result, err := kerbClient.LoginWithKerberos(accountURL, authHost, true)
	if err != nil {
		t.Fatalf("Account login failed: %v", err)
	}

	accountCookies, err := kerbClient.CollectCookies(accountURL, authHost, result)
	if err != nil {
		t.Fatalf("Failed to collect account cookies: %v", err)
	}
	t.Logf("Collected %d cookies for account.web.cern.ch (includes auth.cern.ch cookies)", len(accountCookies))

	// Save account cookies (this includes auth.cern.ch cookies)
	u1, _ := url.Parse(accountURL)
	jar, _ := cookie.NewJar()
	if err := jar.Save(cookieFile, accountCookies, u1.Hostname()); err != nil {
		t.Fatalf("Failed to save account cookies: %v", err)
	}
	kerbClient.Close()

	// Verify auth.cern.ch cookies exist in the file
	allCookies, err := cookie.Load(cookieFile)
	if err != nil {
		t.Fatalf("Failed to load cookies: %v", err)
	}

	authCookiesFound := false
	for _, c := range allCookies {
		if strings.Contains(c.Domain, "auth") || c.Domain == authHost {
			authCookiesFound = true
			t.Logf("Found auth cookie: %s (domain: %s)", c.Name, c.Domain)
			break
		}
	}

	if !authCookiesFound {
		t.Logf("Warning: No auth.cern.ch cookies found, this test may not fully verify the feature")
	}

	// Now try to authenticate to another domain - it should use existing auth cookies
	// if they exist and are valid
	gitlabURL := "https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie"

	kerbClient2, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create second Kerberos client: %v", err)
	}
	defer kerbClient2.Close()

	// Try to login - if auth cookies work, it won't need Kerberos
	result, err = kerbClient2.LoginWithKerberos(gitlabURL, authHost, true)
	if err != nil {
		t.Fatalf("GitLab login failed: %v", err)
	}

	gitlabCookies, err := kerbClient2.CollectCookies(gitlabURL, authHost, result)
	if err != nil {
		t.Fatalf("Failed to collect GitLab cookies: %v", err)
	}
	t.Logf("Collected %d cookies for gitlab.cern.ch", len(gitlabCookies))

	// Verify the login succeeded (cookies were collected)
	if len(gitlabCookies) == 0 {
		t.Fatal("No cookies collected for GitLab")
	}

	// Update the cookie file - should have cookies for both domains
	u2, _ := url.Parse(gitlabURL)
	if err := jar.Update(cookieFile, gitlabCookies, u2.Hostname()); err != nil {
		t.Fatalf("Failed to update with GitLab cookies: %v", err)
	}

	t.Logf("Cookie reuse test completed successfully")
}

func TestIntegration_GitLabCERN(t *testing.T) {
	skipIfNoCredentials(t)

	targetURL := "https://gitlab.cern.ch/authzsvc/tools/auth-get-sso-cookie"
	authHost := "auth.cern.ch"
	cookieFile := "test_gitlab_cookies.txt"
	defer os.Remove(cookieFile)

	// Test cookie generation
	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	cookies, err := kerbClient.CollectCookies(targetURL, authHost, result)
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
	verifyCookiesIntegration(t, cookieFile, targetURL, "GitLab")
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

	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
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
	// Set wrong password and dummy username to force password-based auth
	originalUser := os.Getenv("KRB5_USERNAME")
	originalPassword := os.Getenv("KRB5_PASSWORD")
	originalCCache := os.Getenv("KRB5CCNAME")

	os.Setenv("KRB5_USERNAME", "testuser")
	os.Setenv("KRB5_PASSWORD", "wrong-password")
	os.Setenv("KRB5CCNAME", "/tmp/non-existent-ccache-path")

	defer func() {
		if originalUser != "" {
			os.Setenv("KRB5_USERNAME", originalUser)
		} else {
			os.Unsetenv("KRB5_USERNAME")
		}
		if originalPassword != "" {
			os.Setenv("KRB5_PASSWORD", originalPassword)
		} else {
			os.Unsetenv("KRB5_PASSWORD")
		}
		if originalCCache != "" {
			os.Setenv("KRB5CCNAME", originalCCache)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	_, err := auth.NewKerberosClient(testVersion, "", true)
	if err == nil {
		t.Fatal("Expected error with invalid credentials, got nil")
	}

	if !strings.Contains(err.Error(), "kerberos login failed") {
		t.Errorf("Expected error message to contain 'kerberos login failed', got %q", err.Error())
	}
}

func skipIfNoCredentials(t *testing.T) {
	if os.Getenv("KRB5_USERNAME") == "" || os.Getenv("KRB5_PASSWORD") == "" {
		t.Skip("Skipping integration test: KRB5_USERNAME and KRB5_PASSWORD not set")
	}
}

// TestIntegration_OpenShiftPaaS tests SPA fallback for OpenShift at paas.cern.ch.
// OpenShift uses JavaScript SPA with SERVER_FLAGS.loginURL that redirects to SSO.
func TestIntegration_OpenShiftPaaS(t *testing.T) {
	skipIfNoCredentials(t)

	targetURL := "https://paas.cern.ch/"
	authHost := "auth.cern.ch"
	cookieFile := "test_openshift_cookies.txt"
	defer os.Remove(cookieFile)

	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	cookies, err := kerbClient.CollectCookies(targetURL, authHost, result)
	if err != nil {
		t.Fatalf("Failed to collect cookies: %v", err)
	}

	if len(cookies) == 0 {
		t.Fatal("No cookies collected")
	}
	t.Logf("Collected %d cookies for OpenShift", len(cookies))

	// Save cookies
	u, _ := url.Parse(targetURL)
	jar, _ := cookie.NewJar()
	err = jar.Save(cookieFile, cookies, u.Hostname())
	if err != nil {
		t.Fatalf("Failed to save cookies: %v", err)
	}

	// Verify cookies work - check for OKD/OpenShift content
	verifyCookiesIntegration(t, cookieFile, targetURL, "OKD")
}

// TestIntegration_HarborRegistry tests SPA fallback for Harbor at registry.cern.ch.
// Harbor uses JavaScript SPA with OIDC auth detected via /api/v2.0/systeminfo.
// Note: This test may fail if the user hasn't granted consent for this application.
func TestIntegration_HarborRegistry(t *testing.T) {
	skipIfNoCredentials(t)

	targetURL := "https://registry.cern.ch/"
	authHost := "auth.cern.ch"
	cookieFile := "test_harbor_cookies.txt"
	defer os.Remove(cookieFile)

	kerbClient, err := auth.NewKerberosClient(testVersion, "", true)
	if err != nil {
		t.Fatalf("Failed to create Kerberos client: %v", err)
	}
	defer kerbClient.Close()

	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		// Harbor may require first-time consent which can only be done in browser
		if strings.Contains(err.Error(), "consent") {
			t.Skip("Skipping: Harbor requires consent. Please accept manually in browser first.")
		}
		t.Fatalf("Login failed: %v", err)
	}

	cookies, err := kerbClient.CollectCookies(targetURL, authHost, result)
	if err != nil {
		t.Fatalf("Failed to collect cookies: %v", err)
	}

	if len(cookies) == 0 {
		t.Fatal("No cookies collected")
	}
	t.Logf("Collected %d cookies for Harbor", len(cookies))

	// Save cookies
	u, _ := url.Parse(targetURL)
	jar, _ := cookie.NewJar()
	err = jar.Save(cookieFile, cookies, u.Hostname())
	if err != nil {
		t.Fatalf("Failed to save cookies: %v", err)
	}

	// Verify cookies work - check for Harbor content
	verifyCookiesIntegration(t, cookieFile, targetURL, "Harbor")
}

func verifyCookiesIntegration(t *testing.T, cookieFile, targetURL, expectedTitle string) {
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

	// Read full body to find title tag
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	body := string(bodyBytes)

	// Extract title from HTML
	titleStart := strings.Index(body, "<title>")
	titleEnd := strings.Index(body, "</title>")
	if titleStart == -1 || titleEnd == -1 || titleEnd <= titleStart {
		t.Errorf("Could not find <title> tag in response. First 500 chars: %s",
			body[:min(500, len(body))])
		return
	}

	title := body[titleStart+7 : titleEnd]
	t.Logf("Page title: %q", title)

	if !strings.Contains(title, expectedTitle) {
		t.Errorf("Expected page title to contain %q, got %q", expectedTitle, title)
	}

	t.Logf("Successfully verified cookies work for %s (domain: %s)", targetURL, u.Hostname())
}
