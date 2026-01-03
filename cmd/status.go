package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/cookie"
	"github.com/spf13/cobra"
)

var (
	statusFile     string
	statusJSON     bool
	statusURL      string
	statusInsecure bool
	statusAuthHost string
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check cookie expiration status",
	Long: `Display the expiration information of stored cookies.

By default, this command only checks cookie expiration times stored in the file
without making network requests.

To verify cookies actually work by making an HTTP request to a target URL,
use the --url flag:

  cern-sso-cli status --url https://gitlab.cern.ch --file cookies.txt

In quiet mode (--quiet), exits with code 0 if cookies are valid (and verified
if --url is provided), 1 otherwise.

Examples:
  cern-sso-cli status --file cookies.txt
  cern-sso-cli status --url https://gitlab.cern.ch --file cookies.txt
  cern-sso-cli status --json`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)

	statusCmd.Flags().StringVar(&statusFile, "file", "cookies.txt", "Cookie file to check")
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON instead of table format")
	statusCmd.Flags().StringVar(&statusURL, "url", "", "URL to verify cookies against (makes HTTP request)")
	statusCmd.Flags().BoolVarP(&statusInsecure, "insecure", "k", false, "Skip certificate validation when verifying")
	statusCmd.Flags().StringVar(&statusAuthHost, "auth-host", defaultAuthHostname, "Authentication hostname for verification")
}

func runStatus(cmd *cobra.Command, args []string) error {
	cookies, err := cookie.Load(statusFile)
	if err != nil {
		return fmt.Errorf("failed to load cookies from %s: %w", statusFile, err)
	}

	// Verify cookies if URL is provided
	var verified bool
	var verifiedValid bool
	if statusURL != "" {
		verified = true
		verifiedValid, _ = cookie.VerifyCookies(statusURL, statusAuthHost, cookies, !statusInsecure)
	}

	if quiet {
		// In quiet mode, exit with code based on cookie validity
		if verified {
			// If verification was requested, use actual verification result
			if verifiedValid {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		} else {
			// Without verification, check expiry times only
			now := time.Now()
			hasValidCookies := false
			for _, c := range cookies {
				if c.Expires.IsZero() || c.Expires.After(now) {
					hasValidCookies = true
					break
				}
			}
			if hasValidCookies {
				os.Exit(0)
			} else {
				os.Exit(1)
			}
		}
	}

	cookie.PrintStatus(cookies, statusJSON, verified, verifiedValid, os.Stdout)
	return nil
}
