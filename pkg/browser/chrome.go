// Package browser provides browser-based authentication functionality.
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// AuthResult contains the result of browser-based authentication.
type AuthResult struct {
	Cookies  []*http.Cookie
	FinalURL string
	Username string
}

// AuthenticateWithChrome opens Chrome, navigates to the target URL, waits for
// authentication to complete, and extracts cookies from the authenticated session.
//
// The user must complete authentication (including Touch ID) in the browser window.
// The function waits until the browser navigates away from the auth hostname,
// indicating successful authentication.
// env is a map of environment variables to set for the browser process (e.g. KRB5CCNAME).
func AuthenticateWithChrome(targetURL string, authHostname string, timeout time.Duration, env map[string]string) (*AuthResult, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create Chrome options for a visible browser window
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),          // Show browser window
		chromedp.Flag("disable-gpu", false),       // Enable GPU for better UI
		chromedp.Flag("start-maximized", false),   // Normal window size
		chromedp.WindowSize(1024, 768),            // Set reasonable size
		chromedp.Flag("disable-extensions", true), // No extensions
		chromedp.Flag("no-first-run", true),       // Skip first run dialogs
		chromedp.Flag("no-default-browser-check", true),
		// Keycloak/Kerberos configuration
		chromedp.Flag("auth-server-allowlist", "auth.cern.ch,login.cern.ch,*.cern.ch"), // Allow Kerberos delegation
		chromedp.Flag("auth-negotiate-delegate-allowlist", "auth.cern.ch,login.cern.ch,*.cern.ch"),
	)

	// Handle environment variables
	// IMPORTANT: chromedp.Env REPLACES the process environment if set.
	// We must merge with os.Environ() to ensure Chrome inherits the system environment (PATH, HOME, etc.)
	if len(env) > 0 {
		// Parse current environment into a map
		fullEnv := make(map[string]string)
		for _, e := range os.Environ() {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				fullEnv[parts[0]] = parts[1]
			}
		}

		// Apply overrides
		for k, v := range env {
			fullEnv[k] = v
		}

		// Convert back to slice
		envSlice := make([]string, 0, len(fullEnv))
		for k, v := range fullEnv {
			envSlice = append(envSlice, k+"="+v)
		}

		opts = append(opts, chromedp.Env(envSlice...))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	// Create browser context
	browserCtx, browserCancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(func(format string, args ...interface{}) {
			// Suppress chromedp logs unless debugging
			if os.Getenv("DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "[chromedp] "+format+"\n", args...)
			}
		}),
	)
	defer browserCancel()

	fmt.Fprintln(os.Stderr, "Opening Chrome for authentication...")
	fmt.Fprintln(os.Stderr, "Please complete authentication (including Touch ID) in the browser window.")

	// Navigate to target URL
	var currentURL string
	err := chromedp.Run(browserCtx,
		chromedp.Navigate(targetURL),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to navigate to target URL: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Waiting for authentication to complete...")

	// Automate Kerberos button click if present
	// This helps for users who have a valid Kerberos ticket in their system ccache
	go func() {
		// Try to find and click the Kerberos button
		// Give it a few seconds to appear
		ctx, cancel := context.WithTimeout(browserCtx, 5*time.Second)
		defer cancel()

		// Common selectors for Keycloak Kerberos button
		selectors := []string{
			`#social-kerberos`,              // CERN Keycloak specific
			`#zocial-kerberos`,              // Standard Keycloak
			`a.zocial.kerberos`,             // Link version
			`input[name="login_kerberos"]`,  // Input version
			`button[name="login_kerberos"]`, // Button version
			`div.kc-social-provider-list > a[id="zocial-kerberos"]`,
		}

		for _, selector := range selectors {
			if err := chromedp.Run(ctx,
				chromedp.WaitVisible(selector, chromedp.ByQuery),
				chromedp.Click(selector, chromedp.ByQuery),
			); err == nil {
				break
			}
		}
	}()

	// Wait for authentication to complete
	// We consider auth complete when:
	// 1. URL is on the target domain (not auth hostname)
	// 2. URL has stopped changing (stabilized)
	err = chromedp.Run(browserCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			// Parse target URL to get the host
			targetParsed, err := url.Parse(targetURL)
			if err != nil {
				return fmt.Errorf("failed to parse target URL: %w", err)
			}
			targetHost := targetParsed.Host

			var lastURL string
			var stableCount int
			const requiredStableChecks = 6 // 3 seconds of stability at 500ms intervals

			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					// Get current URL
					if err := chromedp.Location(&currentURL).Do(ctx); err != nil {
						continue // Ignore transient errors
					}

					// Check we're not on a blank page
					if strings.HasPrefix(currentURL, "about:") || strings.HasPrefix(currentURL, "chrome:") {
						stableCount = 0
						lastURL = currentURL
						continue
					}

					// Check if we've left the auth hostname
					if strings.Contains(currentURL, authHostname) {
						stableCount = 0
						lastURL = currentURL
						continue
					}

					// Check if we're on the target domain
					currentParsed, err := url.Parse(currentURL)
					if err != nil {
						continue
					}

					if currentParsed.Host != targetHost {
						stableCount = 0
						lastURL = currentURL
						continue
					}

					// We're on the target domain - check for stability
					if currentURL == lastURL {
						stableCount++
						if stableCount >= requiredStableChecks {
							// URL has been stable for 3 seconds - auth complete!
							return nil
						}
					} else {
						// URL changed - reset stability counter
						stableCount = 1
						lastURL = currentURL
					}
				}
			}
		}),
	)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("authentication timed out after %v", timeout)
		}
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Wait for the cookies to be set
	// Need a significant wait for OIDC flows - cookies are set during HTTP redirects
	fmt.Fprintln(os.Stderr, "Waiting for cookies to be set...")

	err = chromedp.Run(browserCtx,
		// Wait for DOM to be ready
		chromedp.WaitReady("body", chromedp.ByQuery),
		// Then wait a short time for all cookies to be set
		chromedp.Sleep(1*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for page load: %w", err)
	}

	fmt.Fprintln(os.Stderr, "✓ Authentication successful!")

	// Extract all cookies using network.GetCookies with explicit URLs
	// This ensures we get cookies for all relevant domains
	var cdpCookies []*network.Cookie

	// Build list of URLs to get cookies for
	// Use the authHostname parameter instead of hardcoded values
	authURL := fmt.Sprintf("https://%s/", authHostname)
	cookieURLs := []string{
		targetURL,
		authURL,
		authURL + "auth/realms/cern/",
		authURL + "auth/realms/kerberos/",
	}

	// Parse target URL to also add root domain
	if parsedURL, err := url.Parse(targetURL); err == nil {
		rootURL := fmt.Sprintf("https://%s/", parsedURL.Host)
		if rootURL != targetURL {
			cookieURLs = append(cookieURLs, rootURL)
		}
	}

	err = chromedp.Run(browserCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := network.GetCookies().WithURLs(cookieURLs).Do(ctx)
			if err != nil {
				return err
			}
			cdpCookies = cookies
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to extract cookies: %w", err)
	}

	// Convert CDP cookies to http.Cookie
	httpCookies := make([]*http.Cookie, 0, len(cdpCookies))
	var username string

	for _, c := range cdpCookies {
		// Extract username from Keycloak cookies if present
		// Look for KEYCLOAK_REMEMBER_ME which often contains "username:<uid>"
		if c.Name == "KEYCLOAK_REMEMBER_ME" && strings.HasPrefix(c.Value, "username:") {
			username = strings.TrimPrefix(c.Value, "username:")
		}

		httpCookie := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		}

		// Convert expiration time
		if c.Expires > 0 {
			httpCookie.Expires = time.Unix(int64(c.Expires), 0)
		}

		// Handle SameSite
		switch c.SameSite {
		case network.CookieSameSiteStrict:
			httpCookie.SameSite = http.SameSiteStrictMode
		case network.CookieSameSiteLax:
			httpCookie.SameSite = http.SameSiteLaxMode
		case network.CookieSameSiteNone:
			httpCookie.SameSite = http.SameSiteNoneMode
		}

		httpCookies = append(httpCookies, httpCookie)
	}

	return &AuthResult{
		Cookies:  httpCookies,
		FinalURL: currentURL,
		Username: username,
	}, nil
}

// IsChromeAvailable checks if Chrome or Chromium is available on the system.
// Returns true if Chrome/Chromium is found at common installation paths.
func IsChromeAvailable() bool {
	paths := []string{
		// macOS
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		// Linux
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		// Snap/Flatpak on Linux
		"/snap/bin/chromium",
		"/var/lib/flatpak/exports/bin/com.google.Chrome",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}
