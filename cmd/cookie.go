package cmd

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/clelange/cern-sso-cli/pkg/auth"
	"github.com/clelange/cern-sso-cli/pkg/cookie"
	"github.com/spf13/cobra"
)

var (
	cookieURL      string
	cookieFile     string
	cookieAuthHost string
	cookieForce    bool
	cookieInsecure bool
)

var cookieCmd = &cobra.Command{
	Use:   "cookie",
	Short: "Save SSO session cookies",
	Long: `Authenticate to a CERN SSO-protected URL and save cookies in Netscape format.

The cookies can be used with curl, wget, and other HTTP clients.

Example:
  cern-sso-cli cookie --url https://gitlab.cern.ch --file cookies.txt
  curl -b cookies.txt https://gitlab.cern.ch/api/v4/projects`,
	RunE: runCookie,
}

func init() {
	rootCmd.AddCommand(cookieCmd)

	cookieCmd.Flags().StringVar(&cookieURL, "url", "", "URL to authenticate against (required)")
	cookieCmd.Flags().StringVar(&cookieFile, "file", "cookies.txt", "Output cookie file")
	cookieCmd.Flags().StringVar(&cookieAuthHost, "auth-host", defaultAuthHostname, "Authentication hostname")
	cookieCmd.Flags().BoolVar(&cookieForce, "force", false, "Force refresh of cookies, bypassing validation")
	cookieCmd.Flags().BoolVarP(&cookieInsecure, "insecure", "k", false, "Skip certificate validation")

	cookieCmd.MarkFlagRequired("url")
}

func runCookie(cmd *cobra.Command, args []string) error {
	// Extract domain from target URL for cookie matching
	u, err := url.Parse(cookieURL)
	if err != nil {
		return err
	}
	targetDomain := u.Hostname()

	// Check for user mismatch in existing cookie file (unless --force is used)
	if krbUser != "" && !cookieForce {
		existingUser := cookie.LoadUser(cookieFile)
		if existingUser != "" {
			requestedUser := normalizeUsername(krbUser)
			if existingUser != requestedUser {
				return fmt.Errorf("cookie file %s was created by user %s, but you requested user %s\n"+
					"Use --force to overwrite with the new user's cookies", cookieFile, existingUser, requestedUser)
			}
		}
	}

	// If force refresh is requested, skip validation and authenticate
	if cookieForce {
		logPrintln("Force refresh requested. Authenticating regardless of existing cookies...")
		// Clean up expired cookies before authentication
		jar, err := cookie.NewJar()
		if err != nil {
			logInfo("Warning: Failed to create cookie jar: %v\n", err)
		} else {
			if err := jar.Update(cookieFile, nil, targetDomain); err != nil {
				logInfo("Warning: Failed to cleanup cookies: %v\n", err)
			}
		}
		return authenticateWithKerberos(cookieURL, cookieFile, cookieAuthHost, cookieInsecure)
	}

	// Try to reuse existing cookies
	if existing, err := cookie.Load(cookieFile); err == nil && len(existing) > 0 {
		// First, try auth.cern.ch cookies
		authCookies := cookie.FilterAuthCookies(existing, cookieAuthHost)
		if len(authCookies) > 0 {
			logInfo("Found %d auth.cern.ch cookies, attempting to use them...\n", len(authCookies))
			if ok, result, client := tryAuthCookies(cookieURL, cookieAuthHost, authCookies, cookieInsecure); ok {
				logPrintln("Existing auth cookies worked. Skipping Kerberos authentication.")
				saveCookiesFromAuth(client, cookieFile, cookieURL, cookieAuthHost, result, cookieInsecure)
				return nil
			}
			logPrintln("Auth cookies invalid or expired, falling back to Kerberos...")
		}

		// Then try cookies that match the target domain
		var domainCookies []*http.Cookie
		for _, c := range existing {
			if cookie.MatchDomain(c.Domain, targetDomain) {
				domainCookies = append(domainCookies, c)
			}
		}

		if len(domainCookies) > 0 {
			logInfo("Checking validity of %d existing cookies for %s...\n", len(domainCookies), targetDomain)
			if valid, duration := cookie.VerifyCookies(cookieURL, cookieAuthHost, domainCookies, !cookieInsecure); valid {
				logInfo("Existing cookies are valid for another %v. Reusing them.\n", formatDuration(duration))
				jar, err := cookie.NewJar()
				if err != nil {
					logInfo("Warning: Failed to create cookie jar: %v\n", err)
					return nil
				}
				// Clean up expired ones
				if err := jar.Update(cookieFile, nil, targetDomain); err != nil {
					logInfo("Warning: Failed to cleanup cookies: %v\n", err)
				}
				return nil
			}
			logPrintln("Cookies expired or invalid. Authenticating...")
		} else {
			logInfo("No existing cookies for %s. Authenticating...\n", targetDomain)
		}
	}

	return authenticateWithKerberos(cookieURL, cookieFile, cookieAuthHost, cookieInsecure)
}

// tryAuthCookies attempts to authenticate using existing auth cookies.
func tryAuthCookies(targetURL, authHost string, cookies []*http.Cookie, insecure bool) (bool, *auth.LoginResult, *auth.KerberosClient) {
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser, !insecure)
	if err != nil {
		logInfo("Warning: Failed to create Kerberos client for cookie attempt: %v\n", err)
		return false, nil, nil
	}

	// Configure OTP provider for 2FA support
	kerbClient.SetOTPProvider(GetOTPProvider())

	result, err := kerbClient.TryLoginWithCookies(targetURL, authHost, cookies)
	if err != nil {
		kerbClient.Close()
		return false, nil, nil
	}

	return true, result, kerbClient
}

// saveCookiesFromAuth collects and saves cookies from a successful authentication.
func saveCookiesFromAuth(client *auth.KerberosClient, filename, targetURL, authHost string, result *auth.LoginResult, insecure bool) {
	logPrintln("Collecting cookies...")
	cookies, err := client.CollectCookies(targetURL, authHost, result)
	client.Close()
	if err != nil {
		logInfo("Warning: Failed to collect cookies: %v\n", err)
		return
	}

	u, _ := url.Parse(targetURL)
	logInfo("Saving %d cookies to %s\n", len(cookies), filename)
	jar, err := cookie.NewJar()
	if err != nil {
		logInfo("Warning: Failed to create cookie jar: %v\n", err)
		return
	}

	// Use username from the login result, or fall back to krbUser
	username := result.Username
	if username == "" {
		username = krbUser
	}
	username = normalizeUsername(username)

	if err := jar.UpdateWithUser(filename, cookies, u.Hostname(), username); err != nil {
		logInfo("Warning: Failed to save cookies: %v\n", err)
		return
	}

	logPrintln("Done!")
}

// authenticateWithKerberos performs full Kerberos authentication flow.
func authenticateWithKerberos(targetURL, filename, authHost string, insecure bool) error {
	logPrintln("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser, !insecure)
	if err != nil {
		return fmt.Errorf("failed to initialize Kerberos: %w", err)
	}
	defer kerbClient.Close()

	// Configure OTP provider for 2FA support
	kerbClient.SetOTPProvider(GetOTPProvider())

	logPrintln("Logging in with Kerberos...")
	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, !insecure)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	saveCookiesFromAuth(kerbClient, filename, targetURL, authHost, result, insecure)
	return nil
}
