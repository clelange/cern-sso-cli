package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/browser"
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
//nolint:cyclop // Core SSO flow handling SPNEGO, 2FA, SPA detection, and redirects
func (k *KerberosClient) LoginWithKerberos(loginPage string, authHostname string, verifyCert bool) (*LoginResult, error) {
	// If browser-based authentication is preferred, use it immediately.
	// This ensures we capture all necessary cookies (including OIDC) correctly,
	// even if 2FA strictly isn't required by the server.
	if k.webauthnProvider != nil && k.webauthnProvider.UseBrowser {
		// Check if Chrome is available before attempting browser auth
		if !browser.IsChromeAvailable() {
			return nil, &LoginError{Message: "--browser requires Chrome or Chromium to be installed"}
		}

		// Browser auth needs longer timeout (3 min minimum) for user interaction
		timeout := k.webauthnProvider.GetTimeout()
		if timeout < 3*time.Minute {
			timeout = 3 * time.Minute
		}

		// Prepare environment for Chrome
		env := make(map[string]string)

		// If a specific user is requested, try to find their ticket
		// This is critical for supporting --user with browser flow
		if k.username != "" && runtime.GOOS == "darwin" {
			// Temporarily unset KRB5CCNAME to ensure klist sees the system API caches
			// instead of any file cache set by tryUserCacheAuth
			originalKrb5CCName := os.Getenv("KRB5CCNAME")
			_ = os.Unsetenv("KRB5CCNAME")

			// On macOS, we can try to find the specific user's cache via klist -l
			// This works for both API-based and file-based caches if klist knows about them.
			cacheInfo, err := FindCacheByUsername(k.username)

			// Restore env
			if originalKrb5CCName != "" {
				_ = os.Setenv("KRB5CCNAME", originalKrb5CCName)
			}

			if err == nil {
				// If this is ALREADY the default cache, we should NOT set KRB5CCNAME.
				// Chrome on macOS picks up the system default cache reliably.
				// Setting KRB5CCNAME to a file export might break things (sandbox, format, etc.)
				if cacheInfo.IsDefault {
					// Do nothing - env stays empty, Chrome uses system default
				} else {
					var ccPath string

					// Handle different cache types
					switch {
					case strings.HasPrefix(cacheInfo.CacheName, "FILE:"):
						// Use existing file directly
						ccPath = strings.TrimPrefix(cacheInfo.CacheName, "FILE:")
					default:
						// API: or plain path
						ccPath = cacheInfo.CacheName
					}

					if ccPath != "" {
						env["KRB5CCNAME"] = ccPath
					}
				}
			} else {
				// User requested a specific user, but we couldn't find a ticket
				// Warn the user that we might be using the wrong ticket
				if !k.authConfig.Quiet {
					fmt.Fprintf(os.Stderr, "Warning: ticket for %s not found in system klist, using default\n", k.username)
				}
			}
		}

		browserResult, err := browser.AuthenticateWithChrome(loginPage, authHostname, timeout, env)
		if err != nil {
			return nil, &LoginError{Message: fmt.Sprintf("browser authentication failed: %v", err)}
		}
		// Return the browser result directly
		return &LoginResult{
			Cookies:     browserResult.Cookies,
			RedirectURI: browserResult.FinalURL,
			Username:    browserResult.Username,
		}, nil
	}

	// Step 1: Fetch login page (no SPNEGO needed yet)
	resp, err := k.httpClient.Get(loginPage)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch login page: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	// Follow redirects to get to the actual login page
	for resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		_ = resp.Body.Close() // Close previous response before reassigning
		resp, err = k.httpClient.Get(location)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check if we're at the old SSO (not supported)
	if strings.Contains(resp.Request.URL.Host, "login.cern.ch") {
		return nil, &LoginError{Message: "old SSO (login.cern.ch) is not supported"}
	}

	// Check if this is a GitLab auto-submit OIDC form
	if strings.Contains(string(bodyBytes), "/users/auth/openid_connect") {
		// GitLab uses a form that auto-submits via JavaScript
		// We need to POST to that endpoint ourselves
		action, data, err := ParseGitLabOIDCForm(bytes.NewReader(bodyBytes))
		if err == nil && action != "" {
			// Make the action URL absolute
			if !strings.HasPrefix(action, "http") {
				baseURL := resp.Request.URL
				resolvedURL, err := baseURL.Parse(action)
				if err == nil {
					action = resolvedURL.String()
				}
			}
			// POST to the OIDC endpoint
			oidcResp, err := k.httpClient.PostForm(action, data)
			if err != nil {
				return nil, fmt.Errorf("failed to submit OIDC form: %w", err)
			}
			defer func() {
				if oidcResp != nil && oidcResp.Body != nil {
					_ = oidcResp.Body.Close()
				}
			}()

			// Follow any redirects
			for oidcResp.StatusCode == http.StatusFound || oidcResp.StatusCode == http.StatusSeeOther {
				location := oidcResp.Header.Get("Location")
				if !strings.HasPrefix(location, "http") {
					baseURL := resp.Request.URL
					resolvedURL, err := baseURL.Parse(location)
					if err == nil {
						location = resolvedURL.String()
					}
				}
				oidcResp, err = k.httpClient.Get(location) // #nosec G704
				if err != nil {
					return nil, fmt.Errorf("failed to follow OIDC redirect: %w", err)
				}
				defer func() {
					if oidcResp != nil && oidcResp.Body != nil {
						_ = oidcResp.Body.Close()
					}
				}()
			}

			// Now we should be at the Keycloak login page
			bodyBytes, err = io.ReadAll(oidcResp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read OIDC response: %w", err)
			}
		}
	}

	// Step 2: Parse Kerberos link
	kerbURL, err := ParseKerberosLink(bytes.NewReader(bodyBytes), authHostname)
	if err != nil {
		// Try SPA fallback detection for sites like Harbor or OpenShift
		// that use JavaScript to initiate OIDC redirects
		spaInfo, spaErr := DetectSPA(k.httpClient, loginPage, bodyBytes)
		if spaErr == nil && spaInfo != nil {
			// Navigate to the SPA's login page which should redirect to SSO
			_, loginBody, navErr := GetSPALoginPage(k.httpClient, spaInfo, authHostname)
			if navErr == nil {
				// Retry parsing the Kerberos link from the actual login page
				kerbURL, err = ParseKerberosLink(bytes.NewReader(loginBody), authHostname)
			}
		}
		// If still failing, return the original error
		if err != nil {
			return nil, err
		}
	}

	// Step 3: Follow redirects to get the actual SPNEGO URL
	// We need to follow redirects but NOT consume the final page - only get the redirect chain
	kerbAuthURL := kerbURL
	for {
		req, err := http.NewRequest("GET", kerbAuthURL, nil) // #nosec G704
		if err != nil {
			return nil, fmt.Errorf("failed to create redirect request: %w", err)
		}

		// Use the no-redirect client
		resp, err := k.httpClient.Do(req) // #nosec G704
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
		_ = resp.Body.Close()

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
				baseURL, _ := url.Parse(kerbAuthURL)
				locURL = baseURL.ResolveReference(locURL)
			}
			kerbAuthURL = locURL.String()
		} else {
			// Not a redirect - this is the URL we want to authenticate against
			break
		}
	}
	// Step 4: Perform SPNEGO authentication
	authResp, err := k.DoSPNEGO(kerbAuthURL)
	if err != nil {
		return nil, fmt.Errorf("SPNEGO authentication failed: %w", err)
	}
	defer func() { _ = authResp.Body.Close() }()

	// Step 5: Follow redirects within auth hostname or to login completion
	var redirectURI string
	for {
		var action string
		var data url.Values

		if authResp.StatusCode == http.StatusFound || authResp.StatusCode == http.StatusMovedPermanently || authResp.StatusCode == http.StatusSeeOther {
			location := authResp.Header.Get("Location")
			if location == "" {
				break
			}

			// Handle relative URLs
			u, err := url.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("failed to parse redirect location: %w", err)
			}
			if !u.IsAbs() {
				baseURL := authResp.Request.URL
				u = baseURL.ResolveReference(u)
				location = u.String()
			}

			if u.IsAbs() && u.Host != authHostname && redirectURI == "" {
				// Record the first redirect away from auth as the potential RedirectURI
				// This is useful for OIDC flows that need the authorization code.
				redirectURI = location
			}

			authResp, err = k.httpClient.Get(location) // #nosec G704
			if err != nil {
				return nil, fmt.Errorf("redirect failed: %w", err)
			}
			defer func() { _ = authResp.Body.Close() }()
			continue
		}

		// Not a redirect - check body for auto-submit forms or errors
		authBody, _ := io.ReadAll(authResp.Body)
		authBodyStr := string(authBody)

		if Check2FARequired(authBodyStr) {
			// Check if we need to switch to a different 2FA method
			currentMethod := GetCurrentMethod(authBodyStr)
			if k.preferredMethod != "" && currentMethod != "" && currentMethod != k.preferredMethod {
				// User wants a different method than what's shown
				if HasTryAnotherWay(authBodyStr) {
					// Switch to the preferred method
					switchedBody, switchedResp, err := k.switchTo2FAMethod(authResp, authBody, k.preferredMethod)
					if err != nil {
						return nil, &LoginError{Message: fmt.Sprintf("failed to switch 2FA method: %v", err)}
					}
					authBody = switchedBody
					authBodyStr = string(authBody)
					authResp = switchedResp
				}
			}

			// Determine which 2FA method to use
			webauthnAvailable := IsWebAuthnRequired(authBodyStr) && k.webauthnProvider != nil && IsWebAuthnAvailable()
			otpAvailable := IsOTPRequired(authBodyStr)

			// Use WebAuthn if available and preferred (or if OTP not available)
			if webauthnAvailable && (k.preferredMethod == "webauthn" || !otpAvailable) {
				// Check if browser-based flow is requested
				if k.webauthnProvider.UseBrowser {
					// Use Chrome browser for WebAuthn (supports Touch ID)
					timeout := k.webauthnProvider.GetTimeout()
					browserResult, err := browser.AuthenticateWithChrome(loginPage, authHostname, timeout, nil)
					if err != nil {
						return nil, &LoginError{Message: fmt.Sprintf("browser authentication failed: %v", err)}
					}
					// Return the browser result directly
					return &LoginResult{
						Cookies:     browserResult.Cookies,
						RedirectURI: browserResult.FinalURL,
						Username:    k.username,
					}, nil
				}

				// Handle WebAuthn flow with hardware key
				webauthnForm, err := ParseWebAuthnForm(bytes.NewReader(authBody))
				if err != nil {
					return nil, &LoginError{Message: fmt.Sprintf("failed to parse WebAuthn form: %v", err)}
				}

				// Perform FIDO2 assertion
				result, err := k.webauthnProvider.Authenticate(webauthnForm)
				if err != nil {
					// If WebAuthn failed but OTP is available, could fall back
					// For now, just return the error
					return nil, &LoginError{Message: fmt.Sprintf("WebAuthn authentication failed: %v", err)}
				}

				// Build form data for WebAuthn response
				formData := url.Values{}
				for key, val := range webauthnForm.HiddenFields {
					formData.Set(key, val)
				}
				formData.Set("clientDataJSON", result.ClientDataJSON)
				formData.Set("authenticatorData", result.AuthenticatorData)
				formData.Set("signature", result.Signature)
				formData.Set("credentialId", result.CredentialID)
				if result.UserHandle != "" {
					formData.Set("userHandle", result.UserHandle)
				}

				// Make the action URL absolute
				actionURL := webauthnForm.Action
				if !strings.HasPrefix(actionURL, "http") {
					baseURL := authResp.Request.URL
					resolvedURL, err := baseURL.Parse(actionURL)
					if err == nil {
						actionURL = resolvedURL.String()
					}
				}

				authResp, err = k.httpClient.PostForm(actionURL, formData)
				if err != nil {
					return nil, &LoginError{Message: fmt.Sprintf("failed to submit WebAuthn response: %v", err)}
				}
				defer func() { _ = authResp.Body.Close() }()
				continue
			}

			// Fall back to OTP handling
			if !otpAvailable {
				return nil, &LoginError{Message: "2FA required but no supported method available"}
			}

			otpForm, err := ParseOTPForm(bytes.NewReader(authBody))
			if err != nil {
				return nil, &LoginError{Message: fmt.Sprintf("failed to parse OTP form: %v", err)}
			}

			// Get initial OTP
			otpCode, source, err := k.getOTP()
			if err != nil {
				return nil, &LoginError{Message: fmt.Sprintf("failed to read OTP: %v", err)}
			}

			maxRetries := maxOTPAttemptsForSource(source, k.getMaxOTPRetries())

			// OTP retry loop
			for attempt := 1; attempt <= maxRetries; attempt++ {
				formData := url.Values{}
				for key, val := range otpForm.HiddenFields {
					formData.Set(key, val)
				}
				formData.Set(otpForm.OTPField, otpCode)
				if otpForm.SubmitName != "" {
					formData.Set(otpForm.SubmitName, otpForm.SubmitValue)
				}

				otpResp, err := k.httpClient.PostForm(otpForm.Action, formData)
				if err != nil {
					return nil, &LoginError{Message: fmt.Sprintf("failed to submit OTP: %v", err)}
				}
				defer func() { _ = otpResp.Body.Close() }()

				otpBody, _ := io.ReadAll(otpResp.Body)
				otpBodyStr := string(otpBody)

				// Check if OTP was accepted
				if !Check2FARequired(otpBodyStr) {
					// Success - check for other errors
					if errMsg, _ := GetErrorMessageFromHTML(bytes.NewReader(otpBody)); errMsg != "" {
						return nil, &LoginError{Message: errMsg}
					}
					authResp = otpResp
					break // OTP accepted, continue with auth flow
				}

				// OTP failed - try to retry if possible
				if attempt >= maxRetries {
					return nil, &LoginError{Message: fmt.Sprintf("OTP verification failed after %d attempts", maxRetries)}
				}

				// Check if we can refresh the OTP
				if !IsRefreshable(source) {
					return nil, &LoginError{Message: "Invalid OTP code. Cannot retry with static OTP value."}
				}

				// Auto-generated TOTP sources need a new time window to produce a fresh code.
				if isAutoGeneratedTOTPSource(source) {
					wait := timeUntilNextTOTPWindow(timeNow())
					if !k.authConfig.Quiet {
						if wait >= time.Second {
							_, _ = fmt.Fprintf(os.Stderr, "OTP may have expired. Waiting %s for a fresh code...\n", wait.Round(time.Second))
						} else {
							_, _ = fmt.Fprintln(os.Stderr, "OTP may have expired. Retrying with a fresh code...")
						}
					}
					waitForNextTOTPWindow()
				}

				// Get fresh OTP
				otpCode, err = k.refreshOTP(source, attempt+1, maxRetries)
				if err != nil {
					return nil, &LoginError{Message: fmt.Sprintf("failed to refresh OTP: %v", err)}
				}
			}
			continue
		}

		if CheckConsentRequired(authBodyStr) {
			return nil, &LoginError{Message: "application requires consent, please accept manually first"}
		}

		// Check for auto-submit form (OIDC or GitLab-style)
		if strings.Contains(authBodyStr, "document.forms[0].submit()") || strings.Contains(authBodyStr, "document.querySelector('form').submit()") {
			var err error

			if strings.Contains(authBodyStr, "csrf-token") {
				action, data, err = ParseGitLabOIDCForm(bytes.NewReader(authBody))
			} else {
				action, data, err = ParseForm(bytes.NewReader(authBody))
			}

			if err == nil && action != "" {
				// Make the action URL absolute
				u, err := url.Parse(action)
				if err == nil && !u.IsAbs() {
					baseURL := authResp.Request.URL
					u = baseURL.ResolveReference(u)
					action = u.String()
				}

				authResp, err = k.httpClient.PostForm(action, data)
				if err != nil {
					return nil, fmt.Errorf("form auto-submit failed: %w", err)
				}
				defer func() { _ = authResp.Body.Close() }()
				continue // Process the response from POST (might be another redirect or form)
			}
		}

		// Try SAML (last resort if it's not a recognized auto-submit but looks like a SAML form)
		action, data, err = ParseSAMLForm(bytes.NewReader(authBody))
		if err == nil && action != "" {
			u, err := url.Parse(action)
			if err == nil && !u.IsAbs() {
				baseURL := authResp.Request.URL
				u = baseURL.ResolveReference(u)
				action = u.String()
			}
			authResp, err = k.httpClient.PostForm(action, data)
			if err != nil {
				return nil, fmt.Errorf("SAML POST failed: %w", err)
			}
			defer func() { _ = authResp.Body.Close() }()
			continue
		}

		// Final check: if we're on a different host, it's a success
		if authResp.Request.URL.Host != authHostname {
			return &LoginResult{
				Cookies:     k.GetCookies(authResp.Request.URL),
				RedirectURI: authResp.Request.URL.String(),
				Username:    k.username,
			}, nil
		}

		// Check for error message
		errMsg, _ := GetErrorMessageFromHTML(bytes.NewReader(authBody))
		if errMsg != "" {
			return nil, &LoginError{Message: errMsg}
		}

		// If we're here and still on authHostname with a 200, it's an unrecognized response
		if authResp.Request.URL.Host == authHostname {
			return nil, &LoginError{Message: "unexpected response from authentication server"}
		}

		// Otherwise, success!
		break
	}

	finalURI := authResp.Request.URL.String()
	if redirectURI == "" {
		redirectURI = finalURI
	}

	return &LoginResult{
		Cookies:     k.GetCookies(authResp.Request.URL),
		RedirectURI: redirectURI,
		Username:    k.username,
	}, nil
}
