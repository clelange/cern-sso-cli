package openshift

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clelange/cern-sso-cli/internal/httpclient"
	"github.com/clelange/cern-sso-cli/pkg/auth"
)

const (
	openShiftTokenRedirectURI = "http://localhost" // #nosec G101 -- fixed public redirect placeholder required by the token-exchange API
	cacheDirName              = "cern-sso-cli/openshift"
	accessTokenExpirySkew     = 30 * time.Second
)

var (
	deviceExchangeTimeNow    = time.Now
	deviceExchangeUserCache  = os.UserCacheDir
	startDeviceAuthorization = auth.StartDeviceAuthorization
	waitForDeviceToken       = func(session *auth.DeviceAuthorizationSession) (*auth.TokenResponse, error) {
		return session.WaitForToken()
	}
	tokenExchange = auth.TokenExchange
	tokenRefresh  = auth.TokenRefresh
)

type cachedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type openShiftTokenResponse struct {
	Token string `json:"token"`
}

// FetchLoginCommandWithDeviceExchange authenticates to OpenShift using the CERN OIDC device flow.
//
//nolint:cyclop // Device-exchange flow has cache, refresh, exchange, and minting branches.
func FetchLoginCommandWithDeviceExchange(
	clusterURL string,
	verifyCerts bool,
	logf LogFunc,
	promptf func(auth.DeviceAuthorizationPrompt),
) (*LoginCommandResult, error) {
	clusterName, err := ClusterNameFromURL(clusterURL)
	if err != nil {
		return nil, err
	}

	if logf != nil {
		logf("Looking up OpenShift cluster config for %s...\n", clusterName)
	}

	clusterConfig, err := LookupClusterConfig(clusterName)
	if err != nil {
		return nil, err
	}

	loginOIDC, err := oidcConfigFromAuthURL(clusterConfig.AuthURL, clusterConfig.LoginApplicationID, verifyCerts)
	if err != nil {
		return nil, err
	}

	audienceRecord, audienceErr := loadTokenCache(audienceCachePath(clusterConfig.AudienceID))
	if audienceErr != nil && logf != nil {
		logf("Ignoring cached audience token: %v\n", audienceErr)
	}
	if audienceRecord != nil && audienceRecord.isValid(deviceExchangeTimeNow()) {
		if logf != nil {
			logf("Reusing cached audience token for %s...\n", clusterConfig.AudienceID)
		}
		return mintOpenShiftLoginResult(clusterConfig, audienceRecord.AccessToken, verifyCerts)
	}

	loginRecord, loginErr := loadTokenCache(loginApplicationCachePath(clusterConfig.LoginApplicationID))
	if loginErr != nil && logf != nil {
		logf("Ignoring cached login-app token: %v\n", loginErr)
	}

	var loginToken *auth.TokenResponse
	switch {
	case loginRecord != nil && loginRecord.isValid(deviceExchangeTimeNow()):
		if logf != nil {
			logf("Reusing cached login token for %s...\n", clusterConfig.LoginApplicationID)
		}
		loginToken = loginRecord.toTokenResponse()
	case loginRecord != nil && loginRecord.RefreshToken != "":
		if logf != nil {
			logf("Refreshing cached login token for %s...\n", clusterConfig.LoginApplicationID)
		}
		loginToken, err = tokenRefresh(loginOIDC, loginRecord.RefreshToken)
		if err == nil {
			if err = saveTokenCache(loginApplicationCachePath(clusterConfig.LoginApplicationID), loginToken); err != nil {
				return nil, err
			}
			break
		}
		if logf != nil {
			logf("Cached login token refresh failed: %v\n", err)
		}
		loginToken = nil
	}

	if loginToken == nil {
		if logf != nil {
			logf("Starting device authorization for %s...\n", clusterConfig.LoginApplicationID)
		}

		session, err := startDeviceAuthorization(loginOIDC)
		if err != nil {
			return nil, fmt.Errorf("device authorization failed: %w", err)
		}
		if promptf != nil {
			promptf(session.Prompt)
		}

		loginToken, err = waitForDeviceToken(session)
		if err != nil {
			return nil, fmt.Errorf("device authorization failed: %w", err)
		}
		if err := saveTokenCache(loginApplicationCachePath(clusterConfig.LoginApplicationID), loginToken); err != nil {
			return nil, err
		}
	}

	if logf != nil {
		logf("Exchanging token for audience %s...\n", clusterConfig.AudienceID)
	}

	audienceToken, err := tokenExchange(loginOIDC, loginToken.AccessToken, clusterConfig.AudienceID)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token for OpenShift audience: %w", err)
	}
	if audienceToken.AccessToken == "" {
		return nil, fmt.Errorf("token exchange response missing access token")
	}
	if err := saveTokenCache(audienceCachePath(clusterConfig.AudienceID), audienceToken); err != nil {
		return nil, err
	}

	return mintOpenShiftLoginResult(clusterConfig, audienceToken.AccessToken, verifyCerts)
}

func mintOpenShiftLoginResult(clusterConfig *ClusterConfig, accessToken string, verifyCerts bool) (*LoginCommandResult, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("audience access token is empty")
	}

	token, err := exchangeOpenShiftAPIToken(clusterConfig.TokenExchangeURL, accessToken, verifyCerts)
	if err != nil {
		return nil, err
	}

	return &LoginCommandResult{
		Command: fmt.Sprintf("oc login --token=%s --server=%s", token, clusterConfig.APIURL),
		Token:   token,
		Server:  clusterConfig.APIURL,
	}, nil
}

func exchangeOpenShiftAPIToken(tokenExchangeURL string, accessToken string, verifyCerts bool) (string, error) {
	client := httpclient.New(httpclient.Config{
		Timeout:    httpTimeout,
		VerifyCert: verifyCerts,
	})

	endpoint, err := url.Parse(tokenExchangeURL + "/openshift-api-token")
	if err != nil {
		return "", fmt.Errorf("invalid token exchange URL: %w", err)
	}

	query := endpoint.Query()
	query.Set("redirect-uri", openShiftTokenRedirectURI)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create OpenShift token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req) // #nosec G704
	if err != nil {
		return "", fmt.Errorf("failed to exchange OpenShift API token: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OpenShift token exchange failed with status: %d", resp.StatusCode)
	}

	var response openShiftTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to parse OpenShift token exchange response: %w", err)
	}
	if response.Token == "" {
		return "", fmt.Errorf("OpenShift token exchange response missing token")
	}

	return response.Token, nil
}

func loginApplicationCachePath(clientID string) string {
	return filepath.Join(cacheDirectory(), "login-"+sanitizeCacheKey(clientID)+".json")
}

func audienceCachePath(audienceID string) string {
	return filepath.Join(cacheDirectory(), "audience-"+sanitizeCacheKey(audienceID)+".json")
}

func cacheDirectory() string {
	cacheRoot, err := deviceExchangeUserCache()
	if err != nil || cacheRoot == "" {
		homeDir, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return filepath.Join(os.TempDir(), "cern-sso-cli", "openshift")
		}
		cacheRoot = filepath.Join(homeDir, ".cache")
	}

	return filepath.Join(cacheRoot, cacheDirName)
}

func loadTokenCache(path string) (*cachedToken, error) {
	// #nosec G304 -- path is constructed by internal cache helpers under the user cache directory
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read cache %q: %w", path, err)
	}

	var record cachedToken
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("failed to decode cache %q: %w", path, err)
	}

	return &record, nil
}

func saveTokenCache(path string, token *auth.TokenResponse) error {
	if token == nil {
		return fmt.Errorf("token is required")
	}

	record := cachedToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}
	if token.ExpiresIn > 0 {
		record.ExpiresAt = deviceExchangeTimeNow().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to encode cache: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write cache %q: %w", path, err)
	}

	return nil
}

func (c *cachedToken) isValid(now time.Time) bool {
	if c == nil || c.AccessToken == "" || c.ExpiresAt.IsZero() {
		return false
	}

	return now.Add(accessTokenExpirySkew).Before(c.ExpiresAt)
}

func (c *cachedToken) toTokenResponse() *auth.TokenResponse {
	if c == nil {
		return nil
	}

	return &auth.TokenResponse{
		AccessToken:  c.AccessToken,
		RefreshToken: c.RefreshToken,
	}
}

func sanitizeCacheKey(value string) string {
	sanitized := strings.Map(func(r rune) rune {
		if isCacheKeyRuneAllowed(r) {
			return r
		}
		return '_'
	}, value)

	if sanitized == "" {
		return "token"
	}

	return sanitized
}

func isCacheKeyRuneAllowed(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	default:
		return r == '.' || r == '-' || r == '_'
	}
}
