// Package cmd provides CLI commands for the CERN SSO tool.
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/auth"
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
	otpCode    string
	otpCommand string
	otpRetries int
	// WebAuthn flags
	webauthnPIN         string
	webauthnDevice      string
	webauthnDeviceIndex int
	webauthnTimeout     int
	webauthnBrowser     bool
	// 2FA method preference flags
	useOTP      bool
	useWebAuthn bool
	// Authentication method flags
	keytabPath  string
	usePassword bool
	useKeytab   bool
	useCCache   bool
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
	rootCmd.PersistentFlags().StringVar(&otpCode, "otp", "", "6-digit OTP code for 2FA (alternative to prompt)")
	rootCmd.PersistentFlags().StringVar(&otpCommand, "otp-command", "", "Command to execute to get OTP (e.g., 'op item get CERN --otp')")
	rootCmd.PersistentFlags().IntVar(&otpRetries, "otp-retries", 3, "Max OTP retry attempts (0 to disable retry)")
	// WebAuthn flags
	rootCmd.PersistentFlags().StringVar(&webauthnPIN, "webauthn-pin", "", "PIN for FIDO2 security key (alternative to prompt)")
	rootCmd.PersistentFlags().StringVar(&webauthnDevice, "webauthn-device", "", "Path to specific FIDO2 device (auto-detect if empty)")
	rootCmd.PersistentFlags().IntVar(&webauthnDeviceIndex, "webauthn-device-index", -1, "Index of FIDO2 device to use (see 'webauthn list'), -1 for auto-detect")
	rootCmd.PersistentFlags().IntVar(&webauthnTimeout, "webauthn-timeout", 30, "Timeout in seconds for FIDO2 device interaction")
	rootCmd.PersistentFlags().BoolVar(&webauthnBrowser, "webauthn-browser", false, "Use browser for WebAuthn instead of direct FIDO2")
	// 2FA method preference flags
	rootCmd.PersistentFlags().BoolVar(&useOTP, "use-otp", false, "Use OTP (authenticator app) for 2FA, even if WebAuthn is the default")
	rootCmd.PersistentFlags().BoolVar(&useWebAuthn, "use-webauthn", false, "Use WebAuthn (security key) for 2FA, even if OTP is the default")
	// Authentication method flags
	rootCmd.PersistentFlags().StringVar(&keytabPath, "keytab", "", "Path to keytab file (implies --use-keytab)")
	rootCmd.PersistentFlags().BoolVar(&usePassword, "use-password", false, "Force password authentication (requires KRB5_USERNAME and KRB5_PASSWORD)")
	rootCmd.PersistentFlags().BoolVar(&useKeytab, "use-keytab", false, "Force keytab authentication (uses --keytab, KRB5_KTNAME, or default locations)")
	rootCmd.PersistentFlags().BoolVar(&useCCache, "use-ccache", false, "Force credential cache authentication")
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
// This is a convenience wrapper around auth.NormalizePrincipal.
func normalizeUsername(username string) string {
	return auth.NormalizePrincipal(username)
}

// GetOTPProvider returns an OTP provider configured with CLI flags.
func GetOTPProvider() *auth.OTPProvider {
	return &auth.OTPProvider{
		OTP:        otpCode,
		OTPCommand: otpCommand,
		MaxRetries: otpRetries,
	}
}

// GetWebAuthnProvider returns a WebAuthn provider configured with CLI flags.
func GetWebAuthnProvider() *auth.WebAuthnProvider {
	return &auth.WebAuthnProvider{
		PIN:         webauthnPIN,
		DevicePath:  webauthnDevice,
		DeviceIndex: webauthnDeviceIndex,
		Timeout:     time.Duration(webauthnTimeout) * time.Second,
		UseBrowser:  webauthnBrowser,
	}
}

// GetPreferredMethod returns the user's preferred 2FA method.
// Returns "otp", "webauthn", or "" (use server default).
func GetPreferredMethod() string {
	if useOTP {
		return "otp"
	}
	if useWebAuthn {
		return "webauthn"
	}
	return ""
}

// ValidateMethodFlags checks that --use-otp and --use-webauthn are not both set.
func ValidateMethodFlags() error {
	if useOTP && useWebAuthn {
		return fmt.Errorf("--use-otp and --use-webauthn are mutually exclusive")
	}
	return nil
}

// ValidateAuthMethodFlags checks that authentication method flags are mutually exclusive.
// It also handles the implication that --keytab implies --use-keytab.
func ValidateAuthMethodFlags() error {
	// --keytab implies --use-keytab
	if keytabPath != "" {
		useKeytab = true
	}

	// Count how many --use-* auth flags are set
	count := 0
	if usePassword {
		count++
	}
	if useKeytab {
		count++
	}
	if useCCache {
		count++
	}

	if count > 1 {
		return fmt.Errorf("--use-password, --use-keytab, and --use-ccache are mutually exclusive")
	}
	return nil
}

// GetAuthConfig returns the authentication configuration from CLI flags.
func GetAuthConfig() auth.AuthConfig {
	return auth.AuthConfig{
		KeytabPath:    keytabPath,
		ForcePassword: usePassword,
		ForceKeytab:   useKeytab,
		ForceCCache:   useCCache,
		Quiet:         quiet,
	}
}
