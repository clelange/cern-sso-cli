package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/clelange/cern-sso-cli/pkg/auth"
	"github.com/spf13/cobra"
)

const (
	defaultHarborURL = "https://registry.cern.ch"
)

var (
	harborURL      string
	harborAuthHost string
	harborInsecure bool
	harborJSON     bool
)

// HarborSecretOutput represents the JSON output for the harbor command.
type HarborSecretOutput struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

var harborCmd = &cobra.Command{
	Use:   "harbor",
	Short: "Get Harbor CLI secret",
	Long: `Authenticate to CERN Harbor registry and retrieve your CLI secret.

The CLI secret can be used to log in to Harbor via Docker CLI:
  docker login registry.cern.ch -u <username> -p <secret>

Example:
  cern-sso-cli harbor
  cern-sso-cli harbor --url https://registry-dev.cern.ch`,
	RunE: runHarbor,
}

func init() {
	rootCmd.AddCommand(harborCmd)

	harborCmd.Flags().StringVar(&harborURL, "url", defaultHarborURL, "Harbor registry URL")
	harborCmd.Flags().StringVar(&harborAuthHost, "auth-host", defaultAuthHostname, "Authentication hostname")
	harborCmd.Flags().BoolVarP(&harborInsecure, "insecure", "k", false, "Skip certificate validation")
	harborCmd.Flags().BoolVar(&harborJSON, "json", false, "Output result as JSON")
}

func runHarbor(cmd *cobra.Command, args []string) error {
	// Validate mutually exclusive flags
	if err := ValidateMethodFlags(); err != nil {
		return err
	}
	if err := ValidateAuthMethodFlags(); err != nil {
		return err
	}

	// The Harbor OIDC login initiation URL
	loginURL := harborURL + "/c/oidc/login"

	logInfo("Authenticating to Harbor at %s...\n", harborURL)

	authConfig := GetAuthConfig()
	kerbClient, err := auth.NewKerberosClientWithConfig(version, krb5Config, krbUser, !harborInsecure, authConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize Kerberos: %w", err)
	}
	defer kerbClient.Close()

	// Configure authentication providers
	kerbClient.SetOTPProvider(GetOTPProvider())
	kerbClient.SetWebAuthnProvider(GetWebAuthnProvider())
	kerbClient.SetPreferredMethod(GetPreferredMethod())

	logPrintln("Logging in with Kerberos...")
	result, err := kerbClient.LoginWithKerberos(loginURL, harborAuthHost, !harborInsecure)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Collect cookies
	cookies, err := kerbClient.CollectCookies(loginURL, harborAuthHost, result)
	if err != nil {
		return fmt.Errorf("failed to collect cookies: %w", err)
	}

	// Now use the cookies to fetch the user profile from Harbor API
	secret, username, err := fetchHarborCLISecret(harborURL, cookies, !harborInsecure)
	if err != nil {
		return err
	}

	// Output
	if harborJSON {
		output := HarborSecretOutput{
			Username: username,
			Secret:   secret,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
	} else {
		logInfo("Username: %s\n", username)
		fmt.Println(secret)
	}

	return nil
}

// fetchHarborCLISecret fetches the CLI secret from Harbor API using the provided cookies.
func fetchHarborCLISecret(baseURL string, cookies []*http.Cookie, verifyCerts bool) (string, string, error) {
	// Create HTTP client
	client := &http.Client{}
	if !verifyCerts {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // User explicitly requested insecure mode
		}
	}

	// Fetch current user
	currentUserURL := baseURL + "/api/v2.0/users/current"
	req, err := http.NewRequest("GET", currentUserURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add cookies
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch user profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("failed to fetch user profile (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response: %w", err)
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(body, &userData); err != nil {
		return "", "", fmt.Errorf("failed to parse user data: %w", err)
	}

	userID, _ := userData["user_id"].(float64)
	username, _ := userData["username"].(string)
	logInfo("Authenticated as: %s (ID: %.0f)\n", username, userID)

	// Strategy 1: Check if secret is in oidc_user_meta
	if oidcMeta, ok := userData["oidc_user_meta"].(map[string]interface{}); ok {
		if secret, ok := oidcMeta["secret"].(string); ok && secret != "" {
			return secret, username, nil
		}
	}

	// Strategy 2: Fetch from CLI secret endpoint
	secretURL := fmt.Sprintf("%s/api/v2.0/users/%.0f/cli_secret", baseURL, userID)
	req, err = http.NewRequest("GET", secretURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request: %w", err)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err = client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch CLI secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var secretData map[string]interface{}
		if err := json.Unmarshal(body, &secretData); err == nil {
			if secret, ok := secretData["secret"].(string); ok && secret != "" {
				return secret, username, nil
			}
		}
	}

	return "", "", fmt.Errorf("CLI secret not found in user profile or API")
}
