package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"

	openshiftsvc "github.com/clelange/cern-sso-cli/pkg/services/openshift"
)

const defaultOpenShiftURL = "https://paas.cern.ch"

var (
	openshiftURL      string
	openshiftAuthHost string
	openshiftInsecure bool
	openshiftJSON     bool
	openshiftLoginCmd bool
)

// OpenShiftLoginOutput represents the JSON output for the openshift command.
type OpenShiftLoginOutput struct {
	Command string `json:"command"`
	Token   string `json:"token,omitempty"`
	Server  string `json:"server,omitempty"`
}

var openshiftCmd = &cobra.Command{
	Use:     "openshift",
	Aliases: []string{"oc", "okd"},
	Short:   "Get OpenShift/OKD API token",
	Long: `Authenticate to CERN OpenShift (OKD/PaaS) and retrieve your API token.

By default, outputs only the token. Use --login-command to get the full oc login command.

Example:
  cern-sso-cli openshift
  cern-sso-cli oc --login-command
  cern-sso-cli openshift --url https://paas-dev.cern.ch`,
	RunE: runOpenShift,
}

func init() {
	rootCmd.AddCommand(openshiftCmd)

	openshiftCmd.Flags().StringVar(&openshiftURL, "url", defaultOpenShiftURL, "OpenShift cluster URL")
	openshiftCmd.Flags().StringVar(&openshiftAuthHost, "auth-host", defaultAuthHostname, "Authentication hostname")
	openshiftCmd.Flags().BoolVarP(&openshiftInsecure, "insecure", "k", false, "Skip certificate validation")
	openshiftCmd.Flags().BoolVar(&openshiftJSON, "json", false, "Output result as JSON")
	openshiftCmd.Flags().BoolVar(&openshiftLoginCmd, "login-command", false, "Output full oc login command instead of just the token")
}

//nolint:cyclop // OpenShift OAuth authentication requires multiple steps
func runOpenShift(cmd *cobra.Command, args []string) error {
	// Validate mutually exclusive flags
	if err := validateAuthCLIOptions(); err != nil {
		return err
	}

	// Derive the OAuth server URL from the base URL
	// e.g., https://paas.cern.ch -> https://oauth-openshift.paas.cern.ch
	parsedURL, err := url.Parse(openshiftURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	oauthHost := "oauth-openshift." + parsedURL.Host
	oauthBaseURL := parsedURL.Scheme + "://" + oauthHost

	// OpenShift OAuth token request URL
	tokenRequestURL := oauthBaseURL + "/oauth/token/request"

	logInfo("Authenticating to OpenShift at %s...\n", openshiftURL)
	logInfo("OAuth endpoint: %s\n", tokenRequestURL)

	kerbClient, result, err := loginWithKerberosSession(tokenRequestURL, openshiftAuthHost, openshiftInsecure)
	if err != nil {
		return err
	}
	defer kerbClient.Close()

	// Collect cookies
	cookies, err := kerbClient.CollectCookies(tokenRequestURL, openshiftAuthHost, result)
	if err != nil {
		return fmt.Errorf("failed to collect cookies: %w", err)
	}

	// Fetch the token request page and parse the login command
	loginResult, err := openshiftsvc.FetchLoginCommand(
		oauthBaseURL,
		openshiftURL,
		openshiftAuthHost,
		cookies,
		!openshiftInsecure,
		logInfo,
	)
	if err != nil {
		return err
	}

	return renderOpenShiftOutput(loginResult.Command, loginResult.Token, loginResult.Server)
}

func renderOpenShiftOutput(command, token, server string) error {
	text := token
	if openshiftLoginCmd {
		text = command
	}

	return writeCommandOutput(openshiftJSON, OpenShiftLoginOutput{
		Command: command,
		Token:   token,
		Server:  server,
	}, text)
}
