// Package cmd provides CLI commands for the CERN SSO tool.
package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultAuthHostname = "auth.cern.ch"
	defaultAuthRealm    = "cern"
)

// Global flags
var (
	quiet      bool
	krbUser    string
	krb5Config string
)

// version is set from main.go
var version = "dev"

// SetVersion sets the version string (called from main).
func SetVersion(v string) {
	version = v
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cern-sso-cli",
	Short: "CERN SSO Authentication Tool",
	Long: `A Go implementation of CERN SSO authentication tools.

This is the Go equivalent of auth-get-sso-cookie. It allows you to:
  - Save SSO session cookies for use with curl, wget, etc.
  - Get OIDC access tokens via Authorization Code flow
  - Use Device Authorization Grant flow for headless environments`,
	Version: version,
	// Silence usage on errors - we handle errors ourselves
	SilenceUsage: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// Update version in case it was set after init
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Persistent flags (global flags available to all commands)
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress all output (except critical errors)")
	rootCmd.PersistentFlags().StringVarP(&krbUser, "user", "u", "", "Use specific CERN.CH Kerberos principal (e.g., clange or clange@CERN.CH)")
	rootCmd.PersistentFlags().StringVar(&krb5Config, "krb5-config", "", "Kerberos config source: 'embedded' (default), 'system', or file path")
}

// logInfo prints a formatted message if not in quiet mode.
func logInfo(format string, args ...interface{}) {
	if !quiet {
		fmt.Printf(format, args...)
	}
}

// logPrintln prints a message if not in quiet mode.
func logPrintln(args ...interface{}) {
	if !quiet {
		fmt.Println(args...)
	}
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// normalizeUsername ensures the username has @CERN.CH suffix with correct case.
func normalizeUsername(username string) string {
	if username == "" {
		return ""
	}
	if !strings.Contains(username, "@") {
		username = username + "@CERN.CH"
	}
	if strings.HasSuffix(strings.ToLower(username), "@cern.ch") {
		parts := strings.Split(username, "@")
		username = parts[0] + "@CERN.CH"
	}
	return username
}
