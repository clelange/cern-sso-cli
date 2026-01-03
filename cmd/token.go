package cmd

import (
	"fmt"
	"log"

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
	logPrintln("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser, !tokenInsecure)
	if err != nil {
		log.Fatalf("Failed to initialize Kerberos: %v", err)
	}
	defer kerbClient.Close()

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
		log.Fatalf("Failed to get token: %v", err)
	}

	fmt.Println(token)
	return nil
}
