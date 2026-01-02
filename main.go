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

func main() {
	// Subcommands
	cookieCmd := flag.NewFlagSet("cookie", flag.ExitOnError)
	tokenCmd := flag.NewFlagSet("token", flag.ExitOnError)
	deviceCmd := flag.NewFlagSet("device", flag.ExitOnError)

	// Cookie command flags
	cookieURL := cookieCmd.String("url", "", "URL to authenticate against")
	cookieFile := cookieCmd.String("file", "cookies.txt", "Output cookie file")
	cookieAuthHost := cookieCmd.String("auth-host", defaultAuthHostname, "Authentication hostname")

	// Token command flags
	tokenURL := tokenCmd.String("url", "", "Redirect URI for OAuth")
	tokenClientID := tokenCmd.String("client-id", "", "OAuth client ID")
	tokenAuthHost := tokenCmd.String("auth-host", defaultAuthHostname, "Authentication hostname")
	tokenAuthRealm := tokenCmd.String("realm", defaultAuthRealm, "Authentication realm")

	// Device command flags
	deviceClientID := deviceCmd.String("client-id", "", "OAuth client ID")
	deviceAuthHost := deviceCmd.String("auth-host", defaultAuthHostname, "Authentication hostname")
	deviceAuthRealm := deviceCmd.String("realm", defaultAuthRealm, "Authentication realm")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Handle version flag
	if os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version" {
		fmt.Printf("cern-sso-cli version %s\n", version)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "cookie":
		cookieCmd.Parse(os.Args[2:])
		if *cookieURL == "" {
			log.Fatal("--url is required")
		}
		saveCookie(*cookieURL, *cookieFile, *cookieAuthHost)

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

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("CERN SSO Authentication Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cern-sso-cli cookie --url <URL> [--file cookies.txt] [--auth-host auth.cern.ch]")
	fmt.Println("  cern-sso-cli token --url <URL> --client-id <ID> [--realm cern]")
	fmt.Println("  cern-sso-cli device --client-id <ID> [--realm cern]")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  KRB_USERNAME  Kerberos username")
	fmt.Println("  KRB_PASSWORD  Kerberos password")
}

func saveCookie(targetURL, filename, authHost string) {
	// Try to reuse existing cookies
	if existing, err := cookie.Load(filename); err == nil && len(existing) > 0 {
		log.Println("Checking validity of existing cookies...")
		if valid, duration := verifyCookies(targetURL, authHost, existing); valid {
			log.Printf("Existing cookies are valid for another %v. Reusing them.", duration.Round(time.Second))
			jar, err := cookie.NewJar()
			if err != nil {
				log.Printf("Warning: Failed to create cookie jar: %v", err)
				return
			}
			// Clean up expired ones
			if err := jar.Update(filename, nil); err != nil {
				log.Printf("Warning: Failed to cleanup cookies: %v", err)
			}
			return
		}
		log.Println("Cookies expired or invalid. Authenticating...")
	}

	log.Println("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClient()
	if err != nil {
		log.Fatalf("Failed to initialize Kerberos: %v", err)
	}
	defer kerbClient.Close()

	log.Println("Logging in with Kerberos...")
	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, true)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}

	log.Println("Collecting cookies...")
	cookies, err := kerbClient.CollectCookies(targetURL, result)
	if err != nil {
		log.Fatalf("Failed to collect cookies: %v", err)
	}

	log.Printf("Saving %d cookies to %s\n", len(cookies), filename)
	jar, err := cookie.NewJar()
	if err != nil {
		log.Fatalf("Failed to create cookie jar: %v", err)
	}

	if err := jar.Update(filename, cookies); err != nil {
		log.Fatalf("Failed to save cookies: %v", err)
	}

	log.Println("Done!")
}

// ... existing getToken ...

func verifyCookies(targetURL, authHost string, cookies []*http.Cookie) (bool, time.Duration) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, 0
	}

	jar, err := cookie.NewJar()
	if err != nil {
		return false, 0
	}
	jar.SetCookies(u, cookies)

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host == authHost {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK && resp.Request.URL.Host != authHost {
		// Calculate minimum remaining validity
		var minDuration time.Duration = 100000 * time.Hour // Start large
		found := false
		now := time.Now()

		for _, c := range cookies {
			if c.Expires.IsZero() {
				continue
			}
			// Only consider cookies that haven't expired yet (though verify check implies they worked)
			if c.Expires.After(now) {
				d := c.Expires.Sub(now)
				if d < minDuration {
					minDuration = d
					found = true
				}
			}
		}
		if !found {
			minDuration = 0
		}
		return true, minDuration
	}
	return false, 0
}

func getToken(redirectURL, clientID, authHost, realm string) {
	log.Println("Initializing Kerberos client...")
	kerbClient, err := auth.NewKerberosClient()
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
	}

	log.Println("Getting access token...")
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
