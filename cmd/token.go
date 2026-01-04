package cmd

import (
	"fmt"

	"github.com/clelange/cern-sso-cli/pkg/auth"
	"github.com/spf13/cobra"
)

var (
	tokenURL      string
	tokenClientID string
	tokenAuthHost string
	tokenRealm    string
	tokenInsecure bool
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Get OIDC access token via Authorization Code flow",
	Long: `Get an OIDC access token using Kerberos authentication.

This performs the OAuth2 Authorization Code flow with Kerberos.

Example:
  cern-sso-cli token --url https://redirect-uri --client-id your-client-id`,
	RunE: runToken,
}

func init() {
	rootCmd.AddCommand(tokenCmd)

	tokenCmd.Flags().StringVar(&tokenURL, "url", "", "OAuth redirect URI (required)")
	tokenCmd.Flags().StringVar(&tokenClientID, "client-id", "", "OAuth client ID (required)")
	tokenCmd.Flags().StringVar(&tokenAuthHost, "auth-host", defaultAuthHostname, "Authentication hostname")
	tokenCmd.Flags().StringVar(&tokenRealm, "realm", defaultAuthRealm, "Authentication realm")
	tokenCmd.Flags().BoolVarP(&tokenInsecure, "insecure", "k", false, "Skip certificate validation")

	tokenCmd.MarkFlagRequired("url")
	tokenCmd.MarkFlagRequired("client-id")
}

func runToken(cmd *cobra.Command, args []string) error {
	// Validate mutually exclusive flags
	if err := ValidateMethodFlags(); err != nil {
		return err
	}

	logPrintln("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser, !tokenInsecure)
	if err != nil {
		return fmt.Errorf("failed to initialize Kerberos: %w", err)
	}
	defer kerbClient.Close()

	// Configure OTP provider for 2FA support
	kerbClient.SetOTPProvider(GetOTPProvider())

	// Configure WebAuthn provider for FIDO2 2FA support
	kerbClient.SetWebAuthnProvider(GetWebAuthnProvider())
	kerbClient.SetPreferredMethod(GetPreferredMethod())

	cfg := auth.OIDCConfig{
		AuthHostname: tokenAuthHost,
		AuthRealm:    tokenRealm,
		ClientID:     tokenClientID,
		RedirectURI:  tokenURL,
		VerifyCert:   !tokenInsecure,
		Quiet:        quiet,
	}

	logPrintln("Getting access token...")
	token, err := auth.AuthorizationCodeFlow(kerbClient, cfg)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	fmt.Println(token)
	return nil
}
