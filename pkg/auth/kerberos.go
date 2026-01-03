package auth

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/net/publicsuffix"
)

const defaultKrb5Conf = `[libdefaults]
    default_realm = CERN.CH
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false
    ticket_lifetime = 24h
    forwardable = true
    udp_preference_limit = 0
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    CERN.CH = {
        kdc = cerndc.cern.ch
        default_domain = cern.ch
    }

[domain_realm]
    .cern.ch = CERN.CH
    cern.ch = CERN.CH
`

// Krb5ConfigSource constants for config source options.
const (
	Krb5ConfigEmbedded = "embedded"
	Krb5ConfigSystem   = "system"
)

// LoadKrb5Config loads Kerberos configuration from the specified source.
// source can be:
//   - "" or "embedded": use the built-in CERN.CH configuration
//   - "system": use system krb5.conf (KRB5_CONFIG env var or /etc/krb5.conf)
//   - "/path/to/file": use a custom configuration file
func LoadKrb5Config(source string) (*config.Config, error) {
	switch source {
	case "", Krb5ConfigEmbedded:
		return config.NewFromString(defaultKrb5Conf)

	case Krb5ConfigSystem:
		// Check KRB5_CONFIG environment variable first
		configPath := os.Getenv("KRB5_CONFIG")
		if configPath == "" {
			// Fall back to default system path
			if runtime.GOOS == "darwin" {
				// macOS: check common locations
				paths := []string{"/etc/krb5.conf", "/Library/Preferences/edu.mit.Kerberos"}
				for _, p := range paths {
					if _, err := os.Stat(p); err == nil {
						configPath = p
						break
					}
				}
			} else {
				configPath = "/etc/krb5.conf"
			}
		}
		if configPath == "" {
			return nil, fmt.Errorf("no system krb5.conf found")
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load system krb5.conf from %s: %w", configPath, err)
		}
		return cfg, nil

	default:
		// Treat as a file path
		if _, err := os.Stat(source); err != nil {
			return nil, fmt.Errorf("krb5.conf not found at %s: %w", source, err)
		}
		cfg, err := config.Load(source)
		if err != nil {
			return nil, fmt.Errorf("failed to load krb5.conf from %s: %w", source, err)
		}
		return cfg, nil
	}
}

// KerberosClient handles Kerberos authentication.
type KerberosClient struct {
	krbClient        *client.Client
	httpClient       *http.Client
	jar              http.CookieJar
	collectedCookies []*http.Cookie // Stores full cookie attributes from Set-Cookie headers
	version          string         // Version string for User-Agent header
	username         string         // Username for display in prompts
}

// NewKerberosClient creates a new Kerberos client.
// It first attempts to use an existing credential cache (ccache), which works
// on Linux and macOS with file-based caches. If no valid ccache is found,
// it falls back to username/password authentication using KRB_USERNAME and
// KRB_PASSWORD environment variables.
// krb5ConfigSource can be "embedded" (default), "system", or a file path.
func NewKerberosClient(version string, krb5ConfigSource string, verifyCert bool) (*KerberosClient, error) {
	return NewKerberosClientWithUser(version, krb5ConfigSource, "", verifyCert)
}

// NewKerberosClientWithUser creates a new Kerberos client, optionally for a specific user.
// If krbUsername is provided, it will search for a matching CERN.CH credential cache
// and use that instead of the default cache. The username can be with or without
// the @CERN.CH suffix (e.g., "clange" or "clange@CERN.CH").
// If no matching cache is found but KRB_PASSWORD is set, password-based auth is used.
// krb5ConfigSource can be "embedded" (default), "system", or a file path.
func NewKerberosClientWithUser(version string, krb5ConfigSource string, krbUsername string, verifyCert bool) (*KerberosClient, error) {
	cfg, err := LoadKrb5Config(krb5ConfigSource)
	if err != nil {
		return nil, fmt.Errorf("failed to load krb5 config: %w", err)
	}

	var cl *client.Client

	// If a specific username is requested, try to find and use that cache
	if krbUsername != "" && IsMacOSAPICCache() {
		cacheInfo, err := FindCacheByUsername(krbUsername)
		if err == nil {
			// Found a matching cache, convert it to file-based cache
			filePath, convErr := ConvertSpecificCacheToFile(cacheInfo)
			if convErr == nil {
				os.Setenv("KRB5CCNAME", filePath)
				cl, err = NewClientFromCCache(cfg)
				if err == nil {
					return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, cacheInfo.Principal)
				}
			}
		}

		// No cache found or conversion failed - try password-based auth if available
		password := os.Getenv("KRB_PASSWORD")
		if password != "" {
			// Normalize username to not include @CERN.CH for the client
			username := krbUsername
			if strings.HasSuffix(strings.ToLower(username), "@cern.ch") {
				username = strings.Split(username, "@")[0]
			}
			cl = client.NewWithPassword(username, "CERN.CH", password, cfg, client.DisablePAFXFAST(true))
			if loginErr := cl.Login(); loginErr == nil {
				return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, krbUsername)
			} else {
				return nil, fmt.Errorf("kerberos login failed for %s: %w", krbUsername, loginErr)
			}
		}

		// No password available, return the cache lookup error
		if err != nil {
			return nil, err // Error includes list of available caches
		}
		return nil, fmt.Errorf("failed to use cache for %s and KRB_PASSWORD not set", krbUsername)
	}

	// If username is specified but not on macOS API cache, try password auth directly
	if krbUsername != "" {
		password := os.Getenv("KRB_PASSWORD")
		if password != "" {
			username := krbUsername
			if strings.HasSuffix(strings.ToLower(username), "@cern.ch") {
				username = strings.Split(username, "@")[0]
			}
			cl = client.NewWithPassword(username, "CERN.CH", password, cfg, client.DisablePAFXFAST(true))
			if loginErr := cl.Login(); loginErr == nil {
				return newKerberosClientFromKrbClient(cl, version, verifyCert)
			} else {
				return nil, fmt.Errorf("kerberos login failed for %s: %w", krbUsername, loginErr)
			}
		}
	}

	// Try credential cache first (default behavior)
	cl, err = NewClientFromCCache(cfg)
	if err == nil {
		// Successfully loaded from ccache
		username := extractUsernameFromClient(cl)
		return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, username)
	}

	// On macOS, try to convert API cache to file cache
	if IsMacOSAPICCache() {
		if filePath, convErr := ConvertAPICacheToFile(); convErr == nil {
			os.Setenv("KRB5CCNAME", filePath)
			cl, err = NewClientFromCCache(cfg)
			if err == nil {
				username := extractUsernameFromClient(cl)
				return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, username)
			}
		}
	}

	// Fall back to password-based login from environment
	username := os.Getenv("KRB_USERNAME")
	password := os.Getenv("KRB_PASSWORD")

	if username == "" || password == "" {
		// Provide helpful error message based on platform
		if IsMacOSAPICCache() {
			return nil, fmt.Errorf("no credential cache available. On macOS, either:\n" +
				"  1. Set up keychain: kinit --keychain your-username@CERN.CH (one-time setup)\n" +
				"  2. Create file cache: kinit -c /tmp/krb5cc_custom && export KRB5CCNAME=/tmp/krb5cc_custom\n" +
				"  3. Set KRB_USERNAME and KRB_PASSWORD environment variables")
		}
		return nil, fmt.Errorf("no credential cache found and KRB_USERNAME/KRB_PASSWORD not set")
	}

	cl = client.NewWithPassword(username, "CERN.CH", password, cfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login failed: %w", err)
	}

	// Normalize username for storage
	if !strings.Contains(username, "@") {
		username = username + "@CERN.CH"
	}
	if strings.HasSuffix(strings.ToLower(username), "@cern.ch") {
		parts := strings.Split(username, "@")
		username = parts[0] + "@CERN.CH"
	}
	return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, username)
}

// extractUsernameFromClient extracts the principal name from the Kerberos client.
// Returns empty string if the principal cannot be determined.
func extractUsernameFromClient(cl *client.Client) string {
	if cl == nil || cl.Credentials == nil {
		return ""
	}
	cname := cl.Credentials.CName()
	realm := cl.Credentials.Realm()
	if cname.PrincipalNameString() != "" && realm != "" {
		return cname.PrincipalNameString() + "@" + realm
	}
	return ""
}

// newKerberosClientFromKrbClient creates a KerberosClient from an existing gokrb5 client.
func newKerberosClientFromKrbClient(cl *client.Client, version string, verifyCert bool) (*KerberosClient, error) {
	return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, "")
}

// newKerberosClientFromKrbClientWithUser creates a KerberosClient from an existing gokrb5 client with a username.
func newKerberosClientFromKrbClientWithUser(cl *client.Client, version string, verifyCert bool, username string) (*KerberosClient, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	kc := &KerberosClient{
		krbClient:        cl,
		jar:              jar,
		collectedCookies: make([]*http.Cookie, 0),
		version:          version,
		username:         username,
	}

	// Create a custom transport that intercepts cookies from responses
	customTransport := &cookieInterceptTransport{
		base: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyCert},
		},
		client: kc,
	}

	httpClient := &http.Client{
		Jar:       jar,
		Transport: customTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	}

	kc.httpClient = httpClient
	return kc, nil
}

// cookieInterceptTransport wraps an http.RoundTripper to intercept Set-Cookie headers.
type cookieInterceptTransport struct {
	base   http.RoundTripper
	client *KerberosClient
}

func (t *cookieInterceptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set headers for all requests
	req.Header.Set("User-Agent", fmt.Sprintf("CERN-SSO-CLI/%s (%s; %s)", t.client.version, runtime.GOOS, runtime.GOARCH))
	req.Header.Set("Accept", "*/*")

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	// Capture full cookies from Set-Cookie headers
	cookies := resp.Cookies()
	for _, c := range cookies {
		// Set domain from response URL if not set in cookie
		if c.Domain == "" {
			c.Domain = req.URL.Hostname()
		}
		t.client.collectedCookies = append(t.client.collectedCookies, c)
	}
	return resp, nil
}

// Close cleans up the Kerberos client.
func (k *KerberosClient) Close() {
	k.krbClient.Destroy()
}

// GetHTTPClient returns the HTTP client for non-SPNEGO requests.
func (k *KerberosClient) GetHTTPClient() *http.Client {
	return k.httpClient
}

// GetCookies returns all cookies from the jar for a given URL.
// It ensures the Domain field is populated if empty (Go's cookiejar doesn't populate it).
func (k *KerberosClient) GetCookies(u *url.URL) []*http.Cookie {
	cookies := k.jar.Cookies(u)
	for _, c := range cookies {
		if c.Domain == "" {
			c.Domain = u.Hostname()
		}
	}
	return cookies
}

// GetCollectedCookies returns all cookies collected during the session with full attributes.
func (k *KerberosClient) GetCollectedCookies() []*http.Cookie {
	// Deduplicate by domain+path+name, keeping the latest
	seen := make(map[string]*http.Cookie)
	for _, c := range k.collectedCookies {
		key := c.Domain + c.Path + c.Name
		seen[key] = c
	}
	result := make([]*http.Cookie, 0, len(seen))
	for _, c := range seen {
		result = append(result, c)
	}
	return result
}

// DoSPNEGO performs an HTTP GET request with SPNEGO authentication.
func (k *KerberosClient) DoSPNEGO(targetURL string) (*http.Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	// Explicitly set SPN to HTTP/hostname
	spn := "HTTP/" + u.Host
	spnegoClient := spnego.NewClient(k.krbClient, k.httpClient, spn)
	return spnegoClient.Get(targetURL)
}

// DoSPNEGORequest performs an HTTP request with SPNEGO authentication.
func (k *KerberosClient) DoSPNEGORequest(req *http.Request) (*http.Response, error) {
	spnegoClient := spnego.NewClient(k.krbClient, k.httpClient, "")
	return spnegoClient.Do(req)
}

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
// Returns success if cookies are valid (no redirect to auth hostname).
// Returns error if cookies are invalid/missing (caller should fallback to Kerberos).
//
// Example flow:
// 1. User authenticates to account.web.cern.ch with Kerberos
// 2. auth.cern.ch cookies are saved to cookies.txt
// 3. Later, user wants to authenticate to gitlab.cern.ch
// 4. TryLoginWithCookies reuses auth.cern.ch cookies
// 5. Only falls back to Kerberos if cookies are expired/invalid
// Returns success if cookies are valid (no redirect to auth hostname).
// Returns error if cookies are invalid/missing (caller should fallback to Kerberos).
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
	defer resp.Body.Close()

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

			resp, err = k.httpClient.Get(location)
			if err != nil {
				return nil, fmt.Errorf("redirect failed: %w", err)
			}
			defer resp.Body.Close()
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

				resp, err = k.httpClient.PostForm(action, data)
				if err != nil {
					return nil, fmt.Errorf("form auto-submit failed: %w", err)
				}
				defer resp.Body.Close()
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
			resp, err = k.httpClient.PostForm(action, data)
			if err != nil {
				return nil, fmt.Errorf("SAML POST failed: %w", err)
			}
			defer resp.Body.Close()
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
func (k *KerberosClient) LoginWithKerberos(loginPage string, authHostname string, verifyCert bool) (*LoginResult, error) {
	// Step 1: Fetch login page (no SPNEGO needed yet)
	resp, err := k.httpClient.Get(loginPage)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch login page: %w", err)
	}
	defer resp.Body.Close()

	// Follow redirects to get to the actual login page
	for resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		resp, err = k.httpClient.Get(location)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
		defer resp.Body.Close()
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
			defer oidcResp.Body.Close()

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
				oidcResp, err = k.httpClient.Get(location)
				if err != nil {
					return nil, fmt.Errorf("failed to follow OIDC redirect: %w", err)
				}
				defer oidcResp.Body.Close()
			}

			// Now we should be at the Keycloak login page
			bodyBytes, err = io.ReadAll(oidcResp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read OIDC response: %w", err)
			}
			resp = oidcResp
		}
	}

	// Step 2: Parse Kerberos link
	kerbURL, err := ParseKerberosLink(bytes.NewReader(bodyBytes), authHostname)
	if err != nil {
		return nil, err
	}

	// Step 3: Follow redirects to get the actual SPNEGO URL
	// We need to follow redirects but NOT consume the final page - only get the redirect chain
	kerbAuthURL := kerbURL
	for {
		req, err := http.NewRequest("GET", kerbAuthURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create redirect request: %w", err)
		}

		// Use the no-redirect client
		resp, err := k.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusSeeOther {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}
			// Handle relative URLs
			if !strings.HasPrefix(location, "http") {
				u, _ := url.Parse(kerbAuthURL)
				u.Path = location
				location = u.String()
			}
			kerbAuthURL = location
		} else {
			// Not a redirect - this is the URL we want to authenticate against
			break
		}
	}
	// Step 5: Perform SPNEGO authentication
	authResp, err := k.DoSPNEGO(kerbAuthURL)
	if err != nil {
		return nil, fmt.Errorf("SPNEGO authentication failed: %w", err)
	}
	defer authResp.Body.Close()

	defer authResp.Body.Close()

	// Step 6: Follow redirects within auth hostname or to login completion
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

			authResp, err = k.httpClient.Get(location)
			if err != nil {
				return nil, fmt.Errorf("redirect failed: %w", err)
			}
			defer authResp.Body.Close()
			continue
		}

		// Not a redirect - check body for auto-submit forms or errors
		authBody, _ := io.ReadAll(authResp.Body)
		authBodyStr := string(authBody)

		if Check2FARequired(authBodyStr) {
			otpForm, err := ParseOTPForm(bytes.NewReader(authBody))
			if err != nil {
				return nil, &LoginError{Message: fmt.Sprintf("failed to parse OTP form: %v", err)}
			}

			otpCode, err := promptForOTP(k.username)
			if err != nil {
				return nil, &LoginError{Message: fmt.Sprintf("failed to read OTP: %v", err)}
			}

			formData := url.Values{}
			for k, v := range otpForm.HiddenFields {
				formData.Set(k, v)
			}
			formData.Set(otpForm.OTPField, otpCode)
			if otpForm.SubmitName != "" {
				formData.Set(otpForm.SubmitName, otpForm.SubmitValue)
			}

			otpResp, err := k.httpClient.PostForm(otpForm.Action, formData)
			if err != nil {
				return nil, &LoginError{Message: fmt.Sprintf("failed to submit OTP: %v", err)}
			}
			defer otpResp.Body.Close()

			otpBody, _ := io.ReadAll(otpResp.Body)
			otpBodyStr := string(otpBody)

			if Check2FARequired(otpBodyStr) {
				return nil, &LoginError{Message: "Invalid OTP code. Please try again."}
			}

			if errMsg, _ := GetErrorMessageFromHTML(bytes.NewReader(otpBody)); errMsg != "" {
				return nil, &LoginError{Message: errMsg}
			}

			authResp = otpResp
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
				defer authResp.Body.Close()
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
			defer authResp.Body.Close()
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

// promptForOTP prompts the user for a 6-digit OTP code.
func promptForOTP(username string) (string, error) {
	if username != "" {
		fmt.Printf("Enter your 6-digit OTP code for %s: ", username)
	} else {
		fmt.Print("Enter your 6-digit OTP code: ")
	}
	var code string
	_, err := fmt.Scanln(&code)
	if err != nil {
		return "", fmt.Errorf("failed to read input: %v", err)
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return "", fmt.Errorf("OTP must be 6 digits")
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("OTP must contain only digits")
		}
	}
	return code, nil
}

// CollectCookies collects all cookies from the session with full attributes.
// This uses cookies intercepted from Set-Cookie headers during the authentication flow,
// which preserves the original Path and Domain attributes.
func (k *KerberosClient) CollectCookies(targetURL string, authHostname string, result *LoginResult) ([]*http.Cookie, error) {
	// Make a final request to the target to collect any remaining cookies
	if result.RedirectURI != "" {
		resp, err := k.httpClient.Get(result.RedirectURI)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
		defer resp.Body.Close()
	}

	// Return all cookies collected during the session
	return k.GetCollectedCookies(), nil
}
