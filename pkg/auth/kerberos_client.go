package auth

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"runtime"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/clelange/cern-sso-cli/internal/httpclient"
	"github.com/clelange/cern-sso-cli/pkg/auth/certs"
)

// KerberosClient handles Kerberos authentication.
type KerberosClient struct {
	krbClient        *client.Client
	httpClient       *http.Client
	jar              http.CookieJar
	collectedCookies []*http.Cookie    // Stores full cookie attributes from Set-Cookie headers
	version          string            // Version string for User-Agent header
	username         string            // Username for display in prompts
	otpProvider      *OTPProvider      // Optional OTP provider for 2FA
	webauthnProvider *WebAuthnProvider // Optional WebAuthn provider for FIDO2 2FA
	preferredMethod  string            // Preferred 2FA method: "otp", "webauthn", or "" (use default)
	authConfig       AuthConfig        // Authentication configuration
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

// newTestKerberosClient creates a KerberosClient for unit tests.
// It uses a hardcoded "test" version string since it's only meant for testing.
func newTestKerberosClient(cl *client.Client, verifyCert bool) (*KerberosClient, error) {
	return newKerberosClientFromKrbClientWithUser(cl, "test", verifyCert, "")
}

// newKerberosClientFromKrbClientWithUser creates a KerberosClient from an existing gokrb5 client with a username.
func newKerberosClientFromKrbClientWithUser(cl *client.Client, version string, verifyCert bool, username string) (*KerberosClient, error) {
	jar, err := httpclient.NewJar()
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

	var certPool *x509.CertPool
	// When verifying certs, use system certs plus embedded CERN CA certificates
	if verifyCert {
		certPool, err = certs.GetSystemWithCERNCertPool()
		if err != nil {
			// Fall back to just system certs if CERN certs fail to load
			// This shouldn't happen with embedded certs, but be defensive
			certPool = nil
		}
	}

	// Create a custom transport that intercepts cookies from responses
	customTransport := &cookieInterceptTransport{
		base: httpclient.NewTransport(httpclient.TransportConfig{
			VerifyCert:     verifyCert,
			RootCAs:        certPool,
			ForceTLSConfig: true,
		}),
		client: kc,
	}

	httpClient := httpclient.New(httpclient.Config{
		Jar:       jar,
		Transport: customTransport,
		Timeout:   oidcHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects automatically
		},
	})

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

// SetOTPProvider sets the OTP provider for 2FA authentication.
func (k *KerberosClient) SetOTPProvider(provider *OTPProvider) {
	k.otpProvider = provider
}

// SetWebAuthnProvider sets the WebAuthn provider for FIDO2 2FA authentication.
func (k *KerberosClient) SetWebAuthnProvider(provider *WebAuthnProvider) {
	k.webauthnProvider = provider
}

// SetPreferredMethod sets the preferred 2FA method.
// Valid values are "otp", "webauthn", or "" (use server default).
func (k *KerberosClient) SetPreferredMethod(method string) {
	k.preferredMethod = method
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
		defer func() {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
		}()
	}

	// Return all cookies collected during the session
	return k.GetCollectedCookies(), nil
}

// ExportCCache writes the internal Kerberos credentials to a ccache file.
func (k *KerberosClient) ExportCCache(path string) error {
	// Stub implementation - robust gokrb5 ccache export requires deeper integration
	// For now, we return error so it falls back to system kinit if available.
	return fmt.Errorf("ccache export not fully implemented - please run kinit in your shell")
}
