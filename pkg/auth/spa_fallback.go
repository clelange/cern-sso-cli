// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// SPAType constants for known SPA applications
const (
	SPATypeUnknown   = ""
	SPATypeHarbor    = "harbor"
	SPATypeOpenShift = "openshift"
)

// SPAInfo contains detected SPA configuration
type SPAInfo struct {
	Type     string // SPATypeHarbor, SPATypeOpenShift, etc.
	LoginURL string // Direct login URL that triggers OIDC flow
	ClientID string // OIDC client ID (if extractable)
	BaseURL  string // Base URL of the target site
}

// HarborSystemInfo represents the Harbor systeminfo API response
type HarborSystemInfo struct {
	AuthMode         string `json:"auth_mode"`
	OIDCProviderName string `json:"oidc_provider_name"`
	HarborVersion    string `json:"harbor_version"`
}

// DetectSPA probes the target URL for known SPA patterns.
// Called when ParseKerberosLink fails on the landing page.
// bodyBytes contains the HTML response from the initial request.
func DetectSPA(client *http.Client, targetURL string, bodyBytes []byte) (*SPAInfo, error) {
	// Try Harbor detection first
	if info, err := DetectHarbor(client, targetURL); err == nil && info != nil {
		return info, nil
	}

	// Try OpenShift detection
	if info, err := DetectOpenShift(bodyBytes, targetURL); err == nil && info != nil {
		return info, nil
	}

	return nil, fmt.Errorf("no known SPA pattern detected")
}

// DetectHarbor checks for Harbor registry indicators by probing the systeminfo API.
func DetectHarbor(client *http.Client, targetURL string) (*SPAInfo, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Probe Harbor's systeminfo API
	systeminfoURL := fmt.Sprintf("%s://%s/api/v2.0/systeminfo", u.Scheme, u.Host)
	resp, err := client.Get(systeminfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("systeminfo API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info HarborSystemInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	// Check if Harbor uses OIDC authentication
	if info.AuthMode != "oidc_auth" {
		return nil, fmt.Errorf("Harbor auth_mode is %q, not oidc_auth", info.AuthMode)
	}

	// Harbor with OIDC - we need to construct the OIDC authorization URL
	// The client_id is typically the service name derived from the host
	return &SPAInfo{
		Type:     SPATypeHarbor,
		BaseURL:  fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		ClientID: "", // Will be determined from OIDC discovery if needed
	}, nil
}

// DetectOpenShift checks for OpenShift/OKD indicators in the HTML response.
func DetectOpenShift(bodyBytes []byte, targetURL string) (*SPAInfo, error) {
	bodyStr := string(bodyBytes)

	// Check for OpenShift SERVER_FLAGS pattern
	if !strings.Contains(bodyStr, "window.SERVER_FLAGS") {
		return nil, fmt.Errorf("not an OpenShift page")
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Extract loginURL from SERVER_FLAGS JSON
	// Pattern: "loginURL":"https://paas.cern.ch/auth/login"
	loginURLPattern := regexp.MustCompile(`"loginURL"\s*:\s*"([^"]+)"`)
	matches := loginURLPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return nil, fmt.Errorf("loginURL not found in SERVER_FLAGS")
	}

	loginURL := matches[1]
	// Unescape any escaped characters
	loginURL = strings.ReplaceAll(loginURL, "\\u0026", "&")

	return &SPAInfo{
		Type:     SPATypeOpenShift,
		LoginURL: loginURL,
		BaseURL:  fmt.Sprintf("%s://%s", u.Scheme, u.Host),
	}, nil
}

// GetSPALoginPage navigates through the SPA login flow to reach the SSO page.
// Returns the login page URL and its body content.
func GetSPALoginPage(client *http.Client, spaInfo *SPAInfo, authHostname string) (string, []byte, error) {
	switch spaInfo.Type {
	case SPATypeHarbor:
		return getHarborLoginPage(client, spaInfo, authHostname)
	case SPATypeOpenShift:
		return getOpenShiftLoginPage(client, spaInfo, authHostname)
	default:
		return "", nil, fmt.Errorf("unknown SPA type: %s", spaInfo.Type)
	}
}

// getHarborLoginPage constructs the OIDC authorization URL for Harbor.
func getHarborLoginPage(client *http.Client, spaInfo *SPAInfo, authHostname string) (string, []byte, error) {
	// Harbor's OIDC flow uses a known pattern:
	// auth.cern.ch/auth/realms/cern/protocol/openid-connect/auth?
	//   client_id=registry&
	//   redirect_uri=https://registry.cern.ch/c/oidc/callback&
	//   response_type=code&
	//   scope=openid

	u, err := url.Parse(spaInfo.BaseURL)
	if err != nil {
		return "", nil, err
	}

	// Extract client_id from the hostname (e.g., "registry" from "registry.cern.ch")
	hostParts := strings.Split(u.Host, ".")
	clientID := hostParts[0]

	// Construct the OIDC authorization URL
	authURL := fmt.Sprintf("https://%s/auth/realms/cern/protocol/openid-connect/auth", authHostname)
	redirectURI := fmt.Sprintf("%s://%s/c/oidc/callback", u.Scheme, u.Host)

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid")

	fullURL := authURL + "?" + params.Encode()

	// Fetch the login page
	resp, err := client.Get(fullURL)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch Harbor login page: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read Harbor login page: %w", err)
	}

	return resp.Request.URL.String(), body, nil
}

// getOpenShiftLoginPage follows the OpenShift login URL to reach the SSO page.
// Manually follows redirects since the HTTP client has CheckRedirect disabled.
func getOpenShiftLoginPage(client *http.Client, spaInfo *SPAInfo, authHostname string) (string, []byte, error) {
	if spaInfo.LoginURL == "" {
		return "", nil, fmt.Errorf("OpenShift loginURL not set")
	}

	// Follow the loginURL redirect chain to reach auth.cern.ch
	currentURL := spaInfo.LoginURL
	maxRedirects := 10

	for i := 0; i < maxRedirects; i++ {
		resp, err := client.Get(currentURL)
		if err != nil {
			return "", nil, fmt.Errorf("failed to fetch OpenShift login page: %w", err)
		}

		// Check for redirect status codes (301, 302, 303, 307, 308)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			resp.Body.Close()
			if location == "" {
				return "", nil, fmt.Errorf("redirect response missing Location header")
			}
			// Handle relative URLs
			if !strings.HasPrefix(location, "http") {
				baseURL, _ := url.Parse(currentURL)
				resolvedURL, _ := baseURL.Parse(location)
				location = resolvedURL.String()
			}
			currentURL = location
			continue
		}

		// Not a redirect - read the body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", nil, fmt.Errorf("failed to read OpenShift login page: %w", err)
		}

		return resp.Request.URL.String(), body, nil
	}

	return "", nil, fmt.Errorf("too many redirects following OpenShift login URL")
}
