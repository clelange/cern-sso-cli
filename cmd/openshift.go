package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/clelange/cern-sso-cli/pkg/auth"
	"github.com/spf13/cobra"
)

const (
	defaultOpenShiftURL = "https://paas.cern.ch"
)

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

func runOpenShift(cmd *cobra.Command, args []string) error {
	// Validate mutually exclusive flags
	if err := ValidateMethodFlags(); err != nil {
		return err
	}
	if err := ValidateAuthMethodFlags(); err != nil {
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

	authConfig := GetAuthConfig()
	kerbClient, err := auth.NewKerberosClientWithConfig(version, krb5Config, krbUser, !openshiftInsecure, authConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize Kerberos: %w", err)
	}
	defer kerbClient.Close()

	// Configure authentication providers
	kerbClient.SetOTPProvider(GetOTPProvider())
	kerbClient.SetWebAuthnProvider(GetWebAuthnProvider())
	kerbClient.SetPreferredMethod(GetPreferredMethod())

	logPrintln("Logging in with Kerberos...")
	result, err := kerbClient.LoginWithKerberos(tokenRequestURL, openshiftAuthHost, !openshiftInsecure)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Collect cookies
	cookies, err := kerbClient.CollectCookies(tokenRequestURL, openshiftAuthHost, result)
	if err != nil {
		return fmt.Errorf("failed to collect cookies: %w", err)
	}

	// Fetch the token request page and parse the login command
	loginCmd, token, server, err := fetchOpenShiftLoginCommand(oauthBaseURL, openshiftURL, cookies, !openshiftInsecure)
	if err != nil {
		return err
	}

	// Output
	if openshiftJSON {
		output := OpenShiftLoginOutput{
			Command: loginCmd,
			Token:   token,
			Server:  server,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
	} else if openshiftLoginCmd {
		fmt.Println(loginCmd)
	} else {
		fmt.Println(token)
	}

	return nil
}

// fetchOpenShiftLoginCommand fetches the oc login command from OpenShift token request page.
func fetchOpenShiftLoginCommand(oauthBaseURL, clusterURL string, cookies []*http.Cookie, verifyCerts bool) (string, string, string, error) {
	// Create HTTP client with cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create cookie jar: %w", err)
	}

	transport := &http.Transport{}
	if !verifyCerts {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // User explicitly requested insecure mode
	}

	client := &http.Client{
		Jar:       jar,
		Transport: transport,
	}

	// Set cookies on the OAuth URL
	oauthURL, _ := url.Parse(oauthBaseURL)
	jar.SetCookies(oauthURL, cookies)

	// Also set cookies on auth.cern.ch for the SSO session
	authURL, _ := url.Parse("https://auth.cern.ch")
	jar.SetCookies(authURL, cookies)

	// Step 1: Fetch the token request page (may redirect to /display?code=...)
	tokenRequestURL := oauthBaseURL + "/oauth/token/request"

	resp, err := client.Get(tokenRequestURL)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch token request page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("failed to fetch token request page (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse HTML to find the "Display Token" form or the token itself
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Check if we're already on the token display page
	loginCmd, token, server := parseTokenFromPage(doc, clusterURL)
	if loginCmd != "" {
		return loginCmd, token, server, nil
	}

	// Look for the "Display Token" form and submit it
	form := doc.Find("form")
	if form.Length() == 0 {
		return "", "", "", fmt.Errorf("could not find Display Token form on page")
	}

	// Get form action
	action, exists := form.Attr("action")
	if !exists {
		action = resp.Request.URL.Path
	}

	// Resolve relative action URL
	formURL := oauthBaseURL + action
	if strings.HasPrefix(action, "http") {
		formURL = action
	}

	// Get form method (default POST)
	method := strings.ToUpper(form.AttrOr("method", "POST"))

	// Collect form data
	formData := url.Values{}
	form.Find("input").Each(func(_ int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value := s.AttrOr("value", "")
		if name != "" {
			formData.Set(name, value)
		}
	})

	logInfo("Submitting Display Token form...\n")

	// Submit the form
	var formResp *http.Response
	if method == "GET" {
		formResp, err = client.Get(formURL + "?" + formData.Encode())
	} else {
		formResp, err = client.PostForm(formURL, formData)
	}
	if err != nil {
		return "", "", "", fmt.Errorf("failed to submit form: %w", err)
	}
	defer formResp.Body.Close()

	if formResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(formResp.Body)
		return "", "", "", fmt.Errorf("form submission failed (status %d): %s", formResp.StatusCode, string(body))
	}

	// Parse the token display page
	bodyBytes, err := io.ReadAll(formResp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read response: %w", err)
	}

	doc, err = goquery.NewDocumentFromReader(strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse token page: %w", err)
	}

	loginCmd, token, server = parseTokenFromPage(doc, clusterURL)
	if loginCmd == "" {
		return "", "", "", fmt.Errorf("could not find oc login command in response")
	}

	return loginCmd, token, server, nil
}

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// parseTokenFromPage extracts the oc login command from an HTML document.
func parseTokenFromPage(doc *goquery.Document, clusterURL string) (loginCmd, token, server string) {
	// Strategy 1: Look for pre element containing "oc login" (the actual displayed command)
	doc.Find("pre").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if strings.Contains(text, "oc login") && strings.Contains(text, "--token=") {
			loginCmd = text
		}
	})

	// Strategy 2: Look for code element with just the token (e.g., <code>sha256~...</code>)
	doc.Find("code").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		// Check if this is just a token (not a full command)
		if strings.HasPrefix(text, "sha256~") && !strings.Contains(text, " ") {
			token = strings.Trim(text, "\"'") // Clean up any quotes
		}
	})

	// If we found the login command, extract token and server from it
	if loginCmd != "" {
		// Parse the command to extract token and server
		// Format: oc login --token=xxx --server=xxx
		for _, part := range strings.Fields(loginCmd) {
			if strings.HasPrefix(part, "--token=") {
				token = strings.TrimPrefix(part, "--token=")
				token = strings.Trim(token, "\"'") // Clean up any quotes
			}
			if strings.HasPrefix(part, "--server=") {
				server = strings.TrimPrefix(part, "--server=")
				server = strings.Trim(server, "\"'")
			}
		}
	} else if token != "" {
		// If we only found the token, try to find the server and construct the command
		// Look for server URL in pre elements
		doc.Find("pre").Each(func(_ int, s *goquery.Selection) {
			text := strings.TrimSpace(s.Text())
			if strings.Contains(text, "--server=") {
				for _, part := range strings.Fields(text) {
					if strings.HasPrefix(part, "--server=") {
						server = strings.TrimPrefix(part, "--server=")
						server = strings.Trim(server, "\"'")
						break
					}
				}
			}
		})

		// Fallback: construct API server from cluster URL
		if server == "" {
			parsedURL, _ := url.Parse(clusterURL)
			server = parsedURL.Scheme + "://api." + parsedURL.Host + ":6443"
		}
		loginCmd = fmt.Sprintf("oc login --token=%s --server=%s", token, server)
	}

	return loginCmd, token, server
}
