package harbor

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const httpTimeout = 30 * time.Second

// SecretResult contains the Harbor CLI secret and user metadata.
type SecretResult struct {
	UserID   int64
	Username string
	Secret   string
}

type currentUserResponse struct {
	UserID       int64        `json:"user_id"`
	Username     string       `json:"username"`
	OIDCUserMeta oidcUserMeta `json:"oidc_user_meta"`
}

type oidcUserMeta struct {
	Secret string `json:"secret"`
}

type cliSecretResponse struct {
	Secret string `json:"secret"`
}

// FetchCLISecret fetches the Harbor CLI secret using an authenticated SSO cookie set.
func FetchCLISecret(baseURL string, cookies []*http.Cookie, verifyCerts bool) (*SecretResult, error) {
	client := &http.Client{Timeout: httpTimeout}
	if !verifyCerts {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
		}
	}

	currentUser, err := fetchCurrentUser(client, baseURL, cookies)
	if err != nil {
		return nil, err
	}

	if currentUser.OIDCUserMeta.Secret != "" {
		return &SecretResult{
			UserID:   currentUser.UserID,
			Username: currentUser.Username,
			Secret:   currentUser.OIDCUserMeta.Secret,
		}, nil
	}

	secret, err := fetchSecretFromAPI(client, baseURL, currentUser.UserID, cookies)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, fmt.Errorf("CLI secret not found in user profile or API")
	}

	return &SecretResult{
		UserID:   currentUser.UserID,
		Username: currentUser.Username,
		Secret:   secret,
	}, nil
}

func fetchCurrentUser(client *http.Client, baseURL string, cookies []*http.Cookie) (*currentUserResponse, error) {
	req, err := newCookieRequest(http.MethodGet, baseURL+"/api/v2.0/users/current", cookies)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req) // #nosec G704
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user profile: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch user profile (status %d): %s", resp.StatusCode, string(body))
	}

	var response currentUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	return &response, nil
}

func fetchSecretFromAPI(client *http.Client, baseURL string, userID int64, cookies []*http.Cookie) (string, error) {
	req, err := newCookieRequest(http.MethodGet, fmt.Sprintf("%s/api/v2.0/users/%d/cli_secret", baseURL, userID), cookies)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req) // #nosec G704
	if err != nil {
		return "", fmt.Errorf("failed to fetch CLI secret: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var response cliSecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", nil
	}

	return response.Secret, nil
}

func newCookieRequest(method, targetURL string, cookies []*http.Cookie) (*http.Request, error) {
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	return req, nil
}
