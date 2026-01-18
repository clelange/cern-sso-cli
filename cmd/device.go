package cmd

import (
	"encoding/json"
	"fmt"

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
		Quiet:        quiet,
	}

	token, err := auth.DeviceAuthorizationFlow(cfg)
	if err != nil {
		return fmt.Errorf("device login failed: %w", err)
	}

	if deviceJSON {
		output := DeviceOutput{
			AccessToken:  token.AccessToken,
			TokenType:    token.TokenType,
			ExpiresIn:    token.ExpiresIn,
			RefreshToken: token.RefreshToken,
			Scope:        token.Scope,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
	} else {
		fmt.Println("Access Token:")
		fmt.Println(token.AccessToken)
		if token.RefreshToken != "" {
			fmt.Println("\nRefresh Token:")
			fmt.Println(token.RefreshToken)
		}
	}
	return nil
}
