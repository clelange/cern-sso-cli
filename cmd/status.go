package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/cookie"
	"github.com/spf13/cobra"
)

var (
	statusFile string
	statusJSON bool
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check cookie validity and expiration status",
	Long: `Display the validity and expiration information of stored cookies.

In quiet mode (--quiet), exits with code 0 if any valid cookies exist, 1 otherwise.

Example:
  cern-sso-cli status --file cookies.txt
  cern-sso-cli status --json`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)

	statusCmd.Flags().StringVar(&statusFile, "file", "cookies.txt", "Cookie file to check")
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON instead of table format")
}

func runStatus(cmd *cobra.Command, args []string) error {
	cookies, err := cookie.Load(statusFile)
	if err != nil {
		return fmt.Errorf("failed to load cookies from %s: %w", statusFile, err)
	}

	if quiet {
		// In quiet mode, exit with code based on cookie validity
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
	cookie.PrintStatus(cookies, statusJSON, os.Stdout)
	return nil
}
