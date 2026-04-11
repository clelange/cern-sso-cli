package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// LoginResult contains the result of a Kerberos login.
type LoginResult struct {
	Cookies     []*http.Cookie
	RedirectURI string
	Username    string // The principal that was used for authentication
}

// TryLoginWithCookies attempts to authenticate using existing auth.cern.ch cookies.
// This is useful for reusing existing SSO session cookies instead of performing
// full Kerberos authentication for each new CERN subdomain.
//
// Example flow:
//  1. User authenticates to account.web.cern.ch with Kerberos
//  2. auth.cern.ch cookies are saved to cookies.txt
//  3. Later, user wants to authenticate to gitlab.cern.ch
//  4. TryLoginWithCookies reuses auth.cern.ch cookies
//  5. Only falls back to Kerberos if cookies are expired/invalid
//
// Returns success if cookies are valid (no redirect to auth hostname).
// Returns error if cookies are invalid/missing (caller should fall back to Kerberos).
//
//nolint:cyclop // Complex redirect/form handling for SSO cookie validation
func (k *KerberosClient) TryLoginWithCookies(targetURL string, authHostname string, cookies []*http.Cookie) (*LoginResult, error) {
	if len(cookies) == 0 {
		return nil, fmt.Errorf("no cookies provided")
	}

	// Load existing cookies into the jar
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}

	// Pre-populate the cookie jar with the existing cookies
	// Set cookies via URLs matching their domains for proper jar association
	authURL, _ := url.Parse("https://" + authHostname + "/")
	for _, cookie := range cookies {
		// Fix domain if missing
		if cookie.Domain == "" {
			cookie.Domain = u.Hostname()
		}
		// Set auth cookies via auth URL, others via target URL
		if cookie.Domain == authHostname || cookie.Domain == "."+authHostname ||
			strings.HasSuffix(cookie.Domain, "."+authHostname) {
			k.jar.SetCookies(authURL, []*http.Cookie{cookie})
		} else {
			k.jar.SetCookies(u, []*http.Cookie{cookie})
		}
	}

	// Start by accessing the target URL
	resp, err := k.httpClient.Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("request with cookies failed: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	// Follow redirects and auto-submit forms (same logic as LoginWithKerberos post-SPNEGO)
	// If cookies are valid, auth.cern.ch will auto-redirect back without requiring login
	var redirectURI string
	maxIterations := 20 // Prevent infinite loops
	for i := 0; i < maxIterations; i++ {
		var action string
		var data url.Values

		// Handle HTTP redirects
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusSeeOther {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}

			// Handle relative URLs
			locURL, err := url.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("failed to parse redirect location: %w", err)
			}
			if !locURL.IsAbs() {
				baseURL := resp.Request.URL
				locURL = baseURL.ResolveReference(locURL)
				location = locURL.String()
			}

			if locURL.IsAbs() && locURL.Host != authHostname && redirectURI == "" {
				redirectURI = location
			}

			_ = resp.Body.Close()                  // Close previous response before reassigning
			resp, err = k.httpClient.Get(location) // #nosec G704
			if err != nil {
				return nil, fmt.Errorf("redirect failed: %w", err)
			}
			continue
		}

		// Success: we're at the target with 200 OK
		if resp.StatusCode == http.StatusOK && resp.Request.URL.Host != authHostname {
			finalURI := resp.Request.URL.String()
			if redirectURI == "" {
				redirectURI = finalURI
			}
			return &LoginResult{
				Cookies:     k.GetCookies(resp.Request.URL),
				RedirectURI: redirectURI,
				Username:    k.username,
			}, nil
		}

		// Read body to check for forms or login page
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// If we see a Kerberos login link, cookies are invalid
		if strings.Contains(bodyStr, "kerberos") && strings.Contains(bodyStr, "Sign in") {
			return nil, fmt.Errorf("cookies invalid - login page shown")
		}

		// Check for CERN identity selection page (indicates need to authenticate)
		if strings.Contains(bodyStr, "identity-providers") || strings.Contains(bodyStr, "Select your identity provider") {
			return nil, fmt.Errorf("cookies invalid - identity selection page shown")
		}

		// Check for auto-submit form (OIDC or GitLab-style)
		if strings.Contains(bodyStr, "document.forms[0].submit()") || strings.Contains(bodyStr, "document.querySelector('form').submit()") {
			if strings.Contains(bodyStr, "csrf-token") {
				action, data, err = ParseGitLabOIDCForm(bytes.NewReader(body))
			} else {
				action, data, err = ParseForm(bytes.NewReader(body))
			}

			if err == nil && action != "" {
				// Make the action URL absolute
				actURL, err := url.Parse(action)
				if err == nil && !actURL.IsAbs() {
					baseURL := resp.Request.URL
					actURL = baseURL.ResolveReference(actURL)
					action = actURL.String()
				}

				_ = resp.Body.Close() // Close previous response before reassigning
				resp, err = k.httpClient.PostForm(action, data)
				if err != nil {
					return nil, fmt.Errorf("form auto-submit failed: %w", err)
				}
				continue
			}
		}

		// Try SAML form
		action, data, err = ParseSAMLForm(bytes.NewReader(body))
		if err == nil && action != "" {
			actURL, err := url.Parse(action)
			if err == nil && !actURL.IsAbs() {
				baseURL := resp.Request.URL
				actURL = baseURL.ResolveReference(actURL)
				action = actURL.String()
			}
			_ = resp.Body.Close() // Close previous response before reassigning
			resp, err = k.httpClient.PostForm(action, data)
			if err != nil {
				return nil, fmt.Errorf("SAML POST failed: %w", err)
			}
			continue
		}

		// If we're still on auth hostname and no form to submit, cookies didn't work
		if resp.Request.URL.Host == authHostname {
			return nil, fmt.Errorf("cookies invalid - stuck on auth page")
		}

		// Unknown state
		break
	}

	return nil, fmt.Errorf("cookie authentication failed - max iterations reached or unexpected state")
}

// LoginWithKerberos performs the full Kerberos login flow.
//
//nolint:cyclop // Helper phases still cover SPNEGO, 2FA, SPA detection, and redirects
func (k *KerberosClient) LoginWithKerberos(loginPage string, authHostname string, verifyCert bool) (*LoginResult, error) {
	if result, handled, err := k.tryBrowserLogin(loginPage, authHostname); handled {
		return result, err
	}

	initialPage, err := k.fetchKerberosLoginPage(loginPage)
	if err != nil {
		return nil, err
	}

	kerbURL, err := k.parseKerberosAuthURL(loginPage, authHostname, initialPage.body)
	if err != nil {
		return nil, err
	}

	kerbAuthURL, err := k.resolveKerberosAuthURL(kerbURL)
	if err != nil {
		return nil, err
	}

	authResp, err := k.DoSPNEGO(kerbAuthURL)
	if err != nil {
		return nil, fmt.Errorf("SPNEGO authentication failed: %w", err)
	}

	flow := newKerberosLoginFlow(k, loginPage, authHostname)
	return flow.run(authResp)
}
