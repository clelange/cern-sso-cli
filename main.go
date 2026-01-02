// Package main provides the CLI for CERN SSO authentication.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/auth"
	"github.com/clelange/cern-sso-cli/pkg/cookie"
)

const (
	defaultAuthHostname = "auth.cern.ch"
	defaultAuthRealm    = "cern"
)

// version is set at build time via ldflags
var version = "dev"

var quiet bool
var krb5Config string
var krbUser string

func logInfo(format string, args ...interface{}) {
	if !quiet {
		log.Printf(format, args...)
	}
}

func logPrintln(args ...interface{}) {
	if !quiet {
		log.Println(args...)
	}
}

func main() {
	// Check for global flags first (can appear anywhere in args)
	var newArgs []string
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--quiet" || arg == "-q" {
			quiet = true
		} else if arg == "--krb5-config" && i+1 < len(os.Args) {
			krb5Config = os.Args[i+1]
			i++ // Skip the next arg (the value)
		} else if len(arg) > 14 && arg[:14] == "--krb5-config=" {
			krb5Config = arg[14:]
		} else if (arg == "--user" || arg == "-u") && i+1 < len(os.Args) {
			krbUser = os.Args[i+1]
			i++ // Skip the next arg (the value)
		} else if len(arg) > 7 && arg[:7] == "--user=" {
			krbUser = arg[7:]
		} else {
			newArgs = append(newArgs, arg)
		}
	}
	os.Args = newArgs

	// Subcommands
	cookieCmd := flag.NewFlagSet("cookie", flag.ExitOnError)
	tokenCmd := flag.NewFlagSet("token", flag.ExitOnError)
	deviceCmd := flag.NewFlagSet("device", flag.ExitOnError)
	statusCmd := flag.NewFlagSet("status", flag.ExitOnError)

	// Cookie command flags
	cookieURL := cookieCmd.String("url", "", "URL to authenticate against")
	cookieFile := cookieCmd.String("file", "cookies.txt", "Output cookie file")
	cookieAuthHost := cookieCmd.String("auth-host", defaultAuthHostname, "Authentication hostname")
	cookieForce := cookieCmd.Bool("force", false, "Force refresh of cookies, bypassing validation")

	// Token command flags
	tokenURL := tokenCmd.String("url", "", "Redirect URI for OAuth")
	tokenClientID := tokenCmd.String("client-id", "", "OAuth client ID")
	tokenAuthHost := tokenCmd.String("auth-host", defaultAuthHostname, "Authentication hostname")
	tokenAuthRealm := tokenCmd.String("realm", defaultAuthRealm, "Authentication realm")

	// Device command flags
	deviceClientID := deviceCmd.String("client-id", "", "OAuth client ID")
	deviceAuthHost := deviceCmd.String("auth-host", defaultAuthHostname, "Authentication hostname")
	deviceAuthRealm := deviceCmd.String("realm", defaultAuthRealm, "Authentication realm")

	// Status command flags
	statusFile := statusCmd.String("file", "cookies.txt", "Cookie file to check")
	statusJSON := statusCmd.Bool("json", false, "Output as JSON")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Handle version flag
	if os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version" {
		if !quiet {
			fmt.Printf("cern-sso-cli version %s\n", version)
		}
		os.Exit(0)
	}

	switch os.Args[1] {
	case "cookie":
		cookieCmd.Parse(os.Args[2:])
		if *cookieURL == "" {
			log.Fatal("--url is required")
		}
		saveCookie(*cookieURL, *cookieFile, *cookieAuthHost, *cookieForce)

	case "token":
		tokenCmd.Parse(os.Args[2:])
		if *tokenURL == "" || *tokenClientID == "" {
			log.Fatal("--url and --client-id are required")
		}
		getToken(*tokenURL, *tokenClientID, *tokenAuthHost, *tokenAuthRealm)

	case "device":
		deviceCmd.Parse(os.Args[2:])
		if *deviceClientID == "" {
			log.Fatal("--client-id is required")
		}
		deviceLogin(*deviceClientID, *deviceAuthHost, *deviceAuthRealm)

	case "status":
		statusCmd.Parse(os.Args[2:])
		cookies, err := cookie.Load(*statusFile)
		if err != nil {
			log.Fatalf("Failed to load cookies from %s: %v", *statusFile, err)
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
		cookie.PrintStatus(cookies, *statusJSON, os.Stdout)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	if quiet {
		return
	}
	fmt.Println("CERN SSO Authentication Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cern-sso-cli cookie --url <URL> [--file cookies.txt] [--auth-host auth.cern.ch] [--force]")
	fmt.Println("  cern-sso-cli token --url <URL> --client-id <ID> [--realm cern]")
	fmt.Println("  cern-sso-cli device --client-id <ID> [--realm cern]")
	fmt.Println("  cern-sso-cli status [--file cookies.txt] [--json]")
	fmt.Println()
	fmt.Println("Global flags:")
	fmt.Println("  --quiet, -q           Suppress non-essential output")
	fmt.Println("  --user, -u <name>     Use specific Kerberos principal (e.g., clange or clange@CERN.CH)")
	fmt.Println("  --krb5-config <src>   Kerberos config source: 'embedded' (default), 'system', or file path")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  KRB_USERNAME   Kerberos username")
	fmt.Println("  KRB_PASSWORD   Kerberos password")
	fmt.Println("  KRB5_CONFIG    System krb5.conf path (used with --krb5-config system)")
}

func saveCookie(targetURL, filename, authHost string, forceRefresh bool) {
	// Extract domain from target URL for cookie matching
	u, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}
	targetDomain := u.Hostname()

	// If force refresh is requested, skip validation and authenticate
	if forceRefresh {
		logPrintln("Force refresh requested. Authenticating regardless of existing cookies...")
		// Clean up expired cookies before authentication
		jar, err := cookie.NewJar()
		if err != nil {
			logInfo("Warning: Failed to create cookie jar: %v", err)
		} else {
			if err := jar.Update(filename, nil, targetDomain); err != nil {
				logInfo("Warning: Failed to cleanup cookies: %v", err)
			}
		}
		authenticateWithKerberos(targetURL, filename, authHost)
		return
	}

	// Try to reuse existing cookies
	if existing, err := cookie.Load(filename); err == nil && len(existing) > 0 {
		// First, try auth.cern.ch cookies
		authCookies := cookie.FilterAuthCookies(existing, authHost)
		if len(authCookies) > 0 {
			logInfo("Found %d auth.cern.ch cookies, attempting to use them...", len(authCookies))
			if ok, result, client := tryAuthCookies(targetURL, authHost, authCookies); ok {
				logPrintln("Existing auth cookies worked. Skipping Kerberos authentication.")
				saveCookies(client, filename, targetURL, authHost, result)
				return
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
			logInfo("Checking validity of %d existing cookies for %s...", len(domainCookies), targetDomain)
			if valid, duration := cookie.VerifyCookies(targetURL, authHost, domainCookies); valid {
				logInfo("Existing cookies are valid for another %v. Reusing them.", formatDuration(duration))
				jar, err := cookie.NewJar()
				if err != nil {
					logInfo("Warning: Failed to create cookie jar: %v", err)
					return
				}
				// Clean up expired ones
				if err := jar.Update(filename, nil, targetDomain); err != nil {
					logInfo("Warning: Failed to cleanup cookies: %v", err)
				}
				return
			}
			logPrintln("Cookies expired or invalid. Authenticating...")
		} else {
			logInfo("No existing cookies for %s. Authenticating...", targetDomain)
		}
	}

	authenticateWithKerberos(targetURL, filename, authHost)
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

func getToken(redirectURL, clientID, authHost, realm string) {
	logPrintln("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser)
	if err != nil {
		log.Fatalf("Failed to initialize Kerberos: %v", err)
	}
	defer kerbClient.Close()

	cfg := auth.OIDCConfig{
		AuthHostname: authHost,
		AuthRealm:    realm,
		ClientID:     clientID,
		RedirectURI:  redirectURL,
		VerifyCert:   true,
		Quiet:        quiet,
	}

	logPrintln("Getting access token...")
	token, err := auth.AuthorizationCodeFlow(kerbClient, cfg)
	if err != nil {
		log.Fatalf("Failed to get token: %v", err)
	}

	fmt.Println(token)
}

func deviceLogin(clientID, authHost, realm string) {
	cfg := auth.OIDCConfig{
		AuthHostname: authHost,
		AuthRealm:    realm,
		ClientID:     clientID,
		VerifyCert:   true,
		Quiet:        quiet,
	}

	token, err := auth.DeviceAuthorizationFlow(cfg)
	if err != nil {
		log.Fatalf("Device login failed: %v", err)
	}

	fmt.Println("Access Token:")
	fmt.Println(token.AccessToken)
	if token.RefreshToken != "" {
		fmt.Println("\nRefresh Token:")
		fmt.Println(token.RefreshToken)
	}
}

// tryAuthCookies attempts to authenticate using existing auth cookies.
// Returns (success, result, client) tuple.
func tryAuthCookies(targetURL, authHost string, cookies []*http.Cookie) (bool, *auth.LoginResult, *auth.KerberosClient) {
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser)
	if err != nil {
		logInfo("Warning: Failed to create Kerberos client for cookie attempt: %v", err)
		return false, nil, nil
	}

	result, err := kerbClient.TryLoginWithCookies(targetURL, authHost, cookies)
	if err != nil {
		// Cookies didn't work
		kerbClient.Close()
		return false, nil, nil
	}

	return true, result, kerbClient
}

// saveCookies collects and saves cookies from a successful authentication.
func saveCookies(client *auth.KerberosClient, filename, targetURL, authHost string, result *auth.LoginResult) {
	logPrintln("Collecting cookies...")
	cookies, err := client.CollectCookies(targetURL, authHost, result)
	client.Close()
	if err != nil {
		logInfo("Warning: Failed to collect cookies: %v", err)
		return
	}

	u, _ := url.Parse(targetURL)
	logInfo("Saving %d cookies to %s\n", len(cookies), filename)
	jar, err := cookie.NewJar()
	if err != nil {
		logInfo("Warning: Failed to create cookie jar: %v", err)
		return
	}

	if err := jar.Update(filename, cookies, u.Hostname()); err != nil {
		logInfo("Warning: Failed to save cookies: %v", err)
		return
	}

	logPrintln("Done!")
}

// authenticateWithKerberos performs full Kerberos authentication flow.
func authenticateWithKerberos(targetURL, filename, authHost string) {
	logPrintln("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClientWithUser(version, krb5Config, krbUser)
	if err != nil {
		log.Fatalf("Failed to initialize Kerberos: %v", err)
	}
	defer kerbClient.Close()

	logPrintln("Logging in with Kerberos...")
	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	saveCookies(kerbClient, filename, targetURL, authHost, result)
}
