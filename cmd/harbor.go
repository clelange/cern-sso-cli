package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	harborsvc "github.com/clelange/cern-sso-cli/pkg/services/harbor"
)

const defaultHarborURL = "https://registry.cern.ch"

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
	if err := validateAuthCLIOptions(); err != nil {
		return err
	}

	// The Harbor OIDC login initiation URL
	loginURL := harborURL + "/c/oidc/login"

	logInfo("Authenticating to Harbor at %s...\n", harborURL)

	kerbClient, result, err := loginWithKerberosSession(loginURL, harborAuthHost, harborInsecure)
	if err != nil {
		return err
	}
	defer kerbClient.Close()

	// Collect cookies
	cookies, err := kerbClient.CollectCookies(loginURL, harborAuthHost, result)
	if err != nil {
		return fmt.Errorf("failed to collect cookies: %w", err)
	}

	// Now use the cookies to fetch the user profile from Harbor API
	secretResult, err := harborsvc.FetchCLISecret(harborURL, cookies, !harborInsecure)
	if err != nil {
		return err
	}
	logInfo("Authenticated as: %s (ID: %d)\n", secretResult.Username, secretResult.UserID)

	logInfo("Username: %s\n", secretResult.Username)
	return renderHarborOutput(secretResult.Username, secretResult.Secret)
}

func renderHarborOutput(username, secret string) error {
	return writeCommandOutput(harborJSON, HarborSecretOutput{
		Username: username,
		Secret:   secret,
	}, secret)
}
