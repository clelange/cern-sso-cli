package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

var (
	deviceClientID string
	deviceAuthHost string
	deviceRealm    string
	deviceInsecure bool
	deviceJSON     bool
)

// DeviceOutput represents the JSON output for the device command.
type DeviceOutput struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Device Authorization Grant flow for headless environments",
	Long: `For environments without Kerberos, use Device Authorization Grant.

This displays a URL and code for you to authenticate in a browser.

Example:
  cern-sso-cli device --client-id your-client-id`,
	RunE: runDevice,
}

func init() {
	rootCmd.AddCommand(deviceCmd)

	deviceCmd.Flags().StringVar(&deviceClientID, "client-id", "", "OAuth client ID (required)")
	deviceCmd.Flags().StringVar(&deviceAuthHost, "auth-host", defaultAuthHostname, "Authentication hostname")
	deviceCmd.Flags().StringVar(&deviceRealm, "realm", defaultAuthRealm, "Authentication realm")
	deviceCmd.Flags().BoolVarP(&deviceInsecure, "insecure", "k", false, "Skip certificate validation")
	deviceCmd.Flags().BoolVar(&deviceJSON, "json", false, "Output result as JSON")

	_ = deviceCmd.MarkFlagRequired("client-id")
}

func runDevice(cmd *cobra.Command, args []string) error {
	cfg := auth.OIDCConfig{
		AuthHostname: deviceAuthHost,
		AuthRealm:    deviceRealm,
		ClientID:     deviceClientID,
		VerifyCert:   !deviceInsecure,
	}

	session, err := auth.StartDeviceAuthorization(cfg)
	if err != nil {
		return fmt.Errorf("device login failed: %w", err)
	}

	renderDeviceInstructions(session.Prompt)

	token, err := session.WaitForToken()
	if err != nil {
		return fmt.Errorf("device login failed: %w", err)
	}

	return renderDeviceOutput(token)
}

func renderDeviceOutput(token *auth.TokenResponse) error {
	lines := []string{"Access Token:", token.AccessToken}
	if token.RefreshToken != "" {
		lines = append(lines, "", "Refresh Token:", token.RefreshToken)
	}

	return writeCommandOutput(deviceJSON, DeviceOutput{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		RefreshToken: token.RefreshToken,
		Scope:        token.Scope,
	}, lines...)
}

func renderDeviceInstructions(prompt auth.DeviceAuthorizationPrompt) {
	_, _ = fmt.Fprintln(os.Stderr, "CERN Single Sign-On")
	_, _ = fmt.Fprintln(os.Stderr)
	_, _ = fmt.Fprintf(os.Stderr, "On your tablet, phone or computer, go to:\n    %s\n", prompt.VerificationURI)
	_, _ = fmt.Fprintf(os.Stderr, "and enter the following code:\n    %s\n\n", prompt.UserCode)
	_, _ = fmt.Fprintf(os.Stderr, "You may also open the following link directly:\n    %s\n\n", prompt.VerificationURIComplete)
	if !quiet {
		_, _ = fmt.Fprintln(os.Stderr, "Waiting for login...")
	}
}
