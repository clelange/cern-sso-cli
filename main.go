// Package main provides the CLI for CERN SSO authentication.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/clange/cern-krb-cookie/pkg/auth"
	"github.com/clange/cern-krb-cookie/pkg/cookie"
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
		fmt.Printf("cern-krb-cookie version %s\n", version)
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
	fmt.Println("  cern-krb-cookie cookie --url <URL> [--file cookies.txt] [--auth-host auth.cern.ch]")
	fmt.Println("  cern-krb-cookie token --url <URL> --client-id <ID> [--realm cern]")
	fmt.Println("  cern-krb-cookie device --client-id <ID> [--realm cern]")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  KRB_USERNAME  Kerberos username")
	fmt.Println("  KRB_PASSWORD  Kerberos password")
}

func saveCookie(targetURL, filename, authHost string) {
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

	// Extract domain from target URL
	u, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}
	domain := u.Hostname()

	log.Printf("Saving %d cookies to %s\n", len(cookies), filename)
	jar, err := cookie.NewJar()
	if err != nil {
		log.Fatalf("Failed to create cookie jar: %v", err)
	}

	if err := jar.Save(filename, cookies, domain); err != nil {
		log.Fatalf("Failed to save cookies: %v", err)
	}

	log.Println("Done!")
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
