package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
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

// KerberosClient handles Kerberos authentication.
type KerberosClient struct {
	krbClient        *client.Client
	httpClient       *http.Client
	jar              http.CookieJar
	collectedCookies []*http.Cookie // Stores full cookie attributes from Set-Cookie headers
}

// NewKerberosClient creates a new Kerberos client.
// It first attempts to use an existing credential cache (ccache), which works
// on Linux and macOS with file-based caches. If no valid ccache is found,
// it falls back to username/password authentication using KRB_USERNAME and
// KRB_PASSWORD environment variables.
func NewKerberosClient() (*KerberosClient, error) {
	cfg, err := config.NewFromString(defaultKrb5Conf)
	if err != nil {
		return nil, fmt.Errorf("failed to load krb5 config: %w", err)
	}

	var cl *client.Client

	// Try credential cache first
	cl, err = NewClientFromCCache(cfg)
	if err == nil {
		// Successfully loaded from ccache
		return newKerberosClientFromKrbClient(cl)
	}

	// Fall back to password-based login from environment
	username := os.Getenv("KRB_USERNAME")
	password := os.Getenv("KRB_PASSWORD")

	if username == "" || password == "" {
		// Provide helpful error message based on platform
		if IsMacOSAPICCache() {
			return nil, fmt.Errorf("no credential cache available. On macOS, either:\n" +
				"  1. Set KRB5CCNAME to a file-based cache: kinit -c /tmp/krb5cc_custom && export KRB5CCNAME=/tmp/krb5cc_custom\n" +
				"  2. Set KRB_USERNAME and KRB_PASSWORD environment variables")
		}
		return nil, fmt.Errorf("no credential cache found and KRB_USERNAME/KRB_PASSWORD not set")
	}

	cl = client.NewWithPassword(username, "CERN.CH", password, cfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login failed: %w", err)
	}

	return newKerberosClientFromKrbClient(cl)
}

// newKerberosClientFromKrbClient creates a KerberosClient from an existing gokrb5 client.
func newKerberosClientFromKrbClient(cl *client.Client) (*KerberosClient, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	kc := &KerberosClient{
		krbClient:        cl,
		jar:              jar,
		collectedCookies: make([]*http.Cookie, 0),
	}

	// Create a custom transport that intercepts cookies from responses
	transport := &cookieInterceptTransport{
		base:   http.DefaultTransport,
		client: kc,
	}

	httpClient := &http.Client{
		Jar:       jar,
		Transport: transport,
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
			return nil, &LoginError{Message: "2FA authentication required (not supported)"}
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
	}, nil
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
