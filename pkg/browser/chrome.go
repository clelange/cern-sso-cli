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
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
)

// AuthResult contains the result of browser-based authentication.
type AuthResult struct {
	Cookies     []*http.Cookie
	FinalURL    string
	RedirectURI string
}

// AuthenticateWithChrome opens Chrome, navigates to the target URL, waits for
// authentication to complete, and extracts cookies from the authenticated session.
//
// The user must complete authentication (including Touch ID) in the browser window.
// The function waits until the browser navigates away from the auth hostname,
// indicating successful authentication.
func AuthenticateWithChrome(targetURL string, authHostname string, timeout time.Duration) (*AuthResult, error) {
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
	)

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

	// Wait for the page to fully load and cookies to be set
	// Need a significant wait for OIDC flows - cookies are set during HTTP redirects
	// not by JavaScript, so we can't detect them by DOM changes
	fmt.Fprintln(os.Stderr, "Waiting for cookies to be set...")

	err = chromedp.Run(browserCtx,
		// Wait for DOM to be ready
		chromedp.WaitReady("body", chromedp.ByQuery),
		// Then wait a fixed time for all cookies to be set
		// OIDC flows can have multiple server-side redirects that set cookies
		chromedp.Sleep(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for page load: %w", err)
	}

	fmt.Fprintln(os.Stderr, "✓ Authentication successful!")

	// Extract all cookies using storage.GetCookies
	var cdpCookies []*network.Cookie
	err = chromedp.Run(browserCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := storage.GetCookies().Do(ctx)
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
	for _, c := range cdpCookies {
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
	}, nil
}

// IsChromeAvailable checks if Chrome or Chromium is available on the system.
func IsChromeAvailable() bool {
	// chromedp will find Chrome automatically, but we can do a quick check
	// This is mainly for providing better error messages
	paths := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Let chromedp try to find it
	return true // chromedp has its own detection
}
