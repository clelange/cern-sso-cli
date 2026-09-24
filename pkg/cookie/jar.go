package cookie

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/clelange/cern-sso-cli/internal/httpclient"
)

const verifyHTTPTimeout = 30 * time.Second

// MatchDomain checks if a cookie domain matches the target domain.
// Cookie domain ".example.com" matches "sub.example.com" and "example.com".
// Cookie domain "example.com" matches only "example.com".
func MatchDomain(cookieDomain, targetDomain string) bool {
	if cookieDomain == "" {
		return false
	}
	// Exact match
	if cookieDomain == targetDomain {
		return true
	}
	// Leading dot means subdomains match
	if strings.HasPrefix(cookieDomain, ".") {
		// ".example.com" matches "sub.example.com" and "example.com"
		base := strings.TrimPrefix(cookieDomain, ".")
		if targetDomain == base || strings.HasSuffix(targetDomain, cookieDomain) {
			return true
		}
	}
	return false
}

// FilterAuthCookies returns cookies that belong to the auth hostname.
func FilterAuthCookies(cookies []*http.Cookie, authHost string) []*http.Cookie {
	var authCookies []*http.Cookie
	for _, c := range cookies {
		if c.Domain == authHost || c.Domain == "."+authHost || strings.HasSuffix(c.Domain, "."+authHost) {
			authCookies = append(authCookies, c)
		}
	}
	return authCookies
}

// VerifyCookies checks if cookies are valid for the target URL.
// Returns (valid, remainingDuration) tuple.
//
//nolint:cyclop // HTTP verification with redirect handling and duration calculation
func VerifyCookies(targetURL, authHost string, cookies []*http.Cookie, verifyCert bool) (bool, time.Duration) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, 0
	}

	jar, err := NewJar()
	if err != nil {
		return false, 0
	}

	// Set cookies via URLs matching their domains
	// This ensures the cookie jar properly associates cookies with their domains
	authURL := &url.URL{Scheme: "https", Host: authHost, Path: "/"}
	for _, c := range cookies {
		if c.Domain == authHost || c.Domain == "."+authHost || strings.HasSuffix(c.Domain, "."+authHost) {
			jar.SetCookies(authURL, []*http.Cookie{c})
		} else {
			jar.SetCookies(u, []*http.Cookie{c})
		}
	}

	client := httpclient.New(httpclient.Config{
		Jar:        jar,
		Timeout:    verifyHTTPTimeout,
		VerifyCert: verifyCert,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host == authHost {
				return http.ErrUseLastResponse
			}
			return nil
		},
	})

	resp, err := client.Get(targetURL)
	if err != nil {
		return false, 0
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK && resp.Request.URL.Host != authHost {
		// Calculate minimum remaining validity
		minDuration := 100000 * time.Hour // Start large
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

// Jar wraps http.CookieJar with persistence to Netscape format.
type Jar struct {
	*cookiejar.Jar
}

// NewJar creates a new cookie jar.
func NewJar() (*Jar, error) {
	jar, err := httpclient.NewJar()
	if err != nil {
		return nil, err
	}
	return &Jar{Jar: jar}, nil
}

// Save writes cookies to a file in Netscape format.
func (j *Jar) Save(filename string, cookies []*http.Cookie, domain string) error {
	return j.SaveWithUser(filename, cookies, domain, "")
}

// SaveWithUser writes cookies to a file in Netscape format with username tracking.
// Replace the destination only after a complete write, and always use owner-only permissions.
func (j *Jar) SaveWithUser(filename string, cookies []*http.Cookie, domain string, username string) error {
	dir := filepath.Dir(filename)
	// #nosec G301
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, ".cern-sso-cookies-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if err := writeNetscapeCookies(f, cookies, domain, username); err != nil {
		return fmt.Errorf("write cookie file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync cookie file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close cookie file: %w", err)
	}
	if err := os.Rename(f.Name(), filename); err != nil {
		return fmt.Errorf("replace cookie file: %w", err)
	}
	return nil
}

func writeNetscapeCookies(w io.Writer, cookies []*http.Cookie, domain, username string) error {
	// A buffered writer remembers the first write error, including when Flush fails.
	f := bufio.NewWriter(w)
	_, _ = fmt.Fprintln(f, "# Netscape HTTP Cookie File")
	_, _ = fmt.Fprintln(f, "# https://curl.se/docs/http-cookies.html")
	_, _ = fmt.Fprintln(f, "# This file was generated by cern-sso-cli. Edit at your own risk.")
	if username != "" {
		_, _ = fmt.Fprintf(f, "# CERN-SSO-CLI-USER: %s\n", username)
	}
	_, _ = fmt.Fprintln(f, "")

	now := time.Now()
	for _, original := range cookies {
		c := normaliseCookie(original, domain, now)
		if expiredCookie(c, now) {
			continue
		}
		secure := "FALSE"
		if c.Secure {
			secure = "TRUE"
		}
		// Netscape uses zero for session cookies, which have no fixed expiry.
		var expires int64
		if !c.Expires.IsZero() {
			expires = c.Expires.Unix()
		}
		includeSubdomains := "FALSE"
		if strings.HasPrefix(c.Domain, ".") {
			includeSubdomains = "TRUE"
		}
		domainOutput := c.Domain
		if c.HttpOnly {
			domainOutput = "#HttpOnly_" + domainOutput
		}
		_, _ = fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			domainOutput, includeSubdomains, c.Path, secure, expires, c.Name, c.Value)
	}
	return f.Flush()
}

// normaliseCookie prepares a copy for persistence without modifying the caller's cookies.
func normaliseCookie(c *http.Cookie, domain string, now time.Time) *http.Cookie {
	copy := *c // #nosec G124 -- Preserve the original server cookie security attributes.
	if copy.Domain == "" {
		copy.Domain = domain
	}
	if copy.Path == "" {
		copy.Path = "/"
	}
	if copy.MaxAge > 0 {
		copy.Expires = now.Add(time.Duration(copy.MaxAge) * time.Second)
		copy.MaxAge = 0
	}
	return &copy
}

func expiredCookie(c *http.Cookie, now time.Time) bool {
	return c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(now))
}

// Load reads cookies from a Netscape format file.
func Load(filename string) ([]*http.Cookie, error) {
	f, err := os.Open(filename) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var cookies []*http.Cookie
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "#HttpOnly_") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			continue
		}

		domain := parts[0]
		httpOnly := false
		if strings.HasPrefix(domain, "#HttpOnly_") {
			httpOnly = true
			domain = strings.TrimPrefix(domain, "#HttpOnly_")
		}
		// Preserve the Netscape host-only/subdomain distinction in Domain.
		domain = strings.TrimPrefix(domain, ".")
		if parts[1] == "TRUE" {
			domain = "." + domain
		}
		path := parts[2]
		secure := parts[3] == "TRUE"
		expires, _ := strconv.ParseInt(parts[4], 10, 64)
		name := parts[5]
		value := parts[6]
		var expiry time.Time
		if expires != 0 {
			expiry = time.Unix(expires, 0)
		}

		cookies = append(cookies, &http.Cookie{ // #nosec G124
			Name:     name,
			Value:    value,
			Path:     path,
			Domain:   domain,
			Expires:  expiry,
			Secure:   secure,
			HttpOnly: httpOnly,
		})
	}

	return cookies, scanner.Err()
}

// LoadUser reads the username from a cookie file if present.
// Returns empty string if no username is found or file doesn't exist.
func LoadUser(filename string) string {
	f, err := os.Open(filename) // #nosec G304
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# CERN-SSO-CLI-USER: ") {
			return strings.TrimPrefix(line, "# CERN-SSO-CLI-USER: ")
		}
		// Stop scanning after header section (first non-comment line)
		if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
			break
		}
	}
	return ""
}

// SetCookiesFromSlice sets cookies on the jar for a given URL.
func (j *Jar) SetCookiesFromSlice(u *url.URL, cookies []*http.Cookie) {
	j.SetCookies(u, cookies)
}

// Update reads the existing cookies from the file, removes expired ones,
// updates with the new cookies (replacing conflicts), and saves the result.
// The domain parameter is used as a fallback for cookies without a domain set.
func (j *Jar) Update(filename string, newCookies []*http.Cookie, domain string) error {
	return j.UpdateWithUser(filename, newCookies, domain, "")
}

// UpdateWithUser is like Update but also stores the username in the file.
// If username is empty, it preserves any existing username from the file.
func (j *Jar) UpdateWithUser(filename string, newCookies []*http.Cookie, domain string, username string) error {
	// Try to load existing cookies
	existing, err := Load(filename)
	if err != nil && !os.IsNotExist(err) {
		// If file exists but error (e.g. permission), returns error
		return err
	}

	// Preserve existing username if none provided
	if username == "" {
		username = LoadUser(filename)
	}

	// Filter expired and prepare map for merging
	cookieMap := make(map[string]*http.Cookie)
	now := time.Now()

	// Helper to generate key
	getKey := func(c *http.Cookie) string {
		return strings.ToLower(strings.TrimPrefix(c.Domain, ".")) + "\t" + c.Path + "\t" + c.Name
	}

	// Add existing non-expired cookies
	for _, c := range existing {
		if !expiredCookie(c, now) {
			cookieMap[getKey(c)] = c
		}
	}

	// Add/Overwrite with new cookies
	for _, original := range newCookies {
		c := normaliseCookie(original, domain, now)
		if expiredCookie(c, now) {
			delete(cookieMap, getKey(c))
		} else {
			cookieMap[getKey(c)] = c
		}
	}

	// Flatten back to slice
	var finalCookies []*http.Cookie
	for _, c := range cookieMap {
		finalCookies = append(finalCookies, c)
	}

	return j.SaveWithUser(filename, finalCookies, domain, username)
}
