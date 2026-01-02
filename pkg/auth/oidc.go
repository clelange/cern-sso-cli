package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCConfig holds configuration for OIDC flows.
type OIDCConfig struct {
	AuthHostname string
	AuthRealm    string
	ClientID     string
	RedirectURI  string
	VerifyCert   bool
	Quiet        bool
}

// TokenResponse represents an OIDC token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// AuthorizationCodeFlow performs the OAuth2 Authorization Code flow with Kerberos.
func AuthorizationCodeFlow(kerbClient *KerberosClient, cfg OIDCConfig) (string, error) {
	// Generate state
	state := generateRandomState()

	// Build authorization URL
	authzURL := fmt.Sprintf(
		"https://%s/auth/realms/%s/protocol/openid-connect/auth?client_id=%s&response_type=code&state=%s&redirect_uri=%s",
		cfg.AuthHostname, cfg.AuthRealm, cfg.ClientID, state, url.QueryEscape(cfg.RedirectURI),
	)

	// Login with Kerberos
	result, err := kerbClient.LoginWithKerberos(authzURL, cfg.AuthHostname, cfg.VerifyCert)
	if err != nil {
		return "", err
	}

	// Parse the redirect to get the authorization code
	redirectURL, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect URI: %w", err)
	}

	query := redirectURL.Query()
	if query.Get("state") != state {
		return "", &LoginError{Message: "authorization response doesn't contain expected state"}
	}

	code := query.Get("code")
	if code == "" {
		return "", &LoginError{Message: "no authorization code in response"}
	}

	// Exchange code for token
	tokenURL := fmt.Sprintf(
		"https://%s/auth/realms/%s/protocol/openid-connect/token",
		cfg.AuthHostname, cfg.AuthRealm,
	)

	resp, err := http.PostForm(tokenURL, url.Values{
		"client_id":    {cfg.ClientID},
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {cfg.RedirectURI},
	})
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccessStatus(resp.StatusCode) {
		return "", fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := parseJSONResponse(resp, &tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// DeviceAuthorizationFlow performs the OAuth2 Device Authorization Grant flow.
func DeviceAuthorizationFlow(cfg OIDCConfig) (*TokenResponse, error) {
	// Generate PKCE values
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Request device authorization
	deviceURL := fmt.Sprintf(
		"https://%s/auth/realms/%s/protocol/openid-connect/auth/device",
		cfg.AuthHostname, cfg.AuthRealm,
	)

	resp, err := http.PostForm(deviceURL, url.Values{
		"client_id":             {cfg.ClientID},
		"code_challenge_method": {"S256"},
		"code_challenge":        {codeChallenge},
	})
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccessStatus(resp.StatusCode) {
		return nil, fmt.Errorf("device authorization failed with status: %d", resp.StatusCode)
	}

	var deviceResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}

	if err := parseJSONResponse(resp, &deviceResp); err != nil {
		return nil, err
	}

	// Print instructions (even in quiet mode - user needs them to complete auth)
	fmt.Println("CERN Single Sign-On")
	fmt.Println()
	fmt.Printf("On your tablet, phone or computer, go to:\n    %s\n", deviceResp.VerificationURI)
	fmt.Printf("and enter the following code:\n    %s\n\n", deviceResp.UserCode)
	fmt.Printf("You may also open the following link directly:\n    %s\n\n", deviceResp.VerificationURIComplete)
	if !cfg.Quiet {
		fmt.Println("Waiting for login...")
	}

	// Set up polling with timeout
	tokenURL := fmt.Sprintf(
		"https://%s/auth/realms/%s/protocol/openid-connect/token",
		cfg.AuthHostname, cfg.AuthRealm,
	)

	pollInterval := 5 * time.Second
	if deviceResp.Interval > 0 {
		pollInterval = time.Duration(deviceResp.Interval) * time.Second
	}

	// Calculate expiry time
	expiresAt := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)

	for {
		// Check if expired
		if time.Now().After(expiresAt) {
			return nil, &LoginError{Message: "device authorization expired - user did not complete login in time"}
		}

		time.Sleep(pollInterval)

		tokenResp, err := http.PostForm(tokenURL, url.Values{
			"client_id":     {cfg.ClientID},
			"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code":   {deviceResp.DeviceCode},
			"code_verifier": {codeVerifier},
		})
		if err != nil {
			// Network error - retry
			continue
		}

		if tokenResp.StatusCode == http.StatusOK {
			var token TokenResponse
			if err := parseJSONResponse(tokenResp, &token); err != nil {
				tokenResp.Body.Close()
				return nil, err
			}
			tokenResp.Body.Close()
			return &token, nil
		}

		// Parse error response
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := parseJSONResponse(tokenResp, &errorResp); err != nil {
			tokenResp.Body.Close()
			continue
		}
		tokenResp.Body.Close()

		switch errorResp.Error {
		case "authorization_pending":
			// User hasn't completed login yet - keep polling
			continue
		case "slow_down":
			// Server asks us to slow down - increase interval by 5 seconds (RFC 8628)
			pollInterval += 5 * time.Second
			continue
		case "expired_token":
			return nil, &LoginError{Message: "device authorization expired"}
		case "access_denied":
			return nil, &LoginError{Message: "user denied the authorization request"}
		default:
			// Other error
			if errorResp.ErrorDescription != "" {
				return nil, &LoginError{Message: fmt.Sprintf("%s: %s", errorResp.Error, errorResp.ErrorDescription)}
			}
			return nil, &LoginError{Message: errorResp.Error}
		}
	}
}

// TokenExchange performs a token exchange.
func TokenExchange(cfg OIDCConfig, subjectToken, audience string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf(
		"https://%s/auth/realms/%s/protocol/openid-connect/token",
		cfg.AuthHostname, cfg.AuthRealm,
	)

	resp, err := http.PostForm(tokenURL, url.Values{
		"client_id":            {cfg.ClientID},
		"audience":             {audience},
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
		"subject_token":        {subjectToken},
	})
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccessStatus(resp.StatusCode) {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := parseJSONResponse(resp, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func generateRandomState() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCodeVerifier() string {
	b := make([]byte, 48)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	// Remove padding as Keycloak rejects it
	return strings.TrimRight(base64.URLEncoding.EncodeToString(h[:]), "=")
}

func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

func parseJSONResponse(resp *http.Response, v interface{}) error {
	return json.NewDecoder(resp.Body).Decode(v)
}
