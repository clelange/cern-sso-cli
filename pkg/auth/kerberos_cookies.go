package auth

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clelange/cern-sso-cli/internal/httpclient"
)

// recordResponseCookies stores metadata before the request jar discards it.
func (k *KerberosClient) recordResponseCookies(u *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		domain, ok := responseCookieDomain(u, c)
		if !ok {
			continue
		}
		copy := *c // #nosec G124 -- Preserve the original server cookie security attributes.
		copy.Domain = domain
		k.recordCookie(u, &copy)
	}
}

// responseCookieDomain asks a temporary Go jar to validate the response's scope.
// Probing with a session cookie also validates deletion markers and expired cookies.
// The returned Domain encodes host-only cookies without a dot, as Netscape files do.
func responseCookieDomain(u *url.URL, c *http.Cookie) (string, bool) {
	jar, err := httpclient.NewJar()
	if err != nil {
		return "", false
	}
	probe := *c // #nosec G124 -- This scope probe stays in an isolated in-memory jar; it is never sent or saved.
	probe.Path, probe.Secure, probe.MaxAge, probe.Expires = "/", false, 0, time.Time{}
	jar.SetCookies(u, []*http.Cookie{&probe})
	if len(jar.Cookies(u)) == 0 {
		return "", false
	}

	domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
	if domain != "" {
		subdomainURL := &url.URL{Scheme: u.Scheme, Host: "subdomain." + domain, Path: "/"}
		if len(jar.Cookies(subdomainURL)) > 0 {
			return "." + domain, true
		}
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), true
}

// seedCookie retains attributes that would otherwise be lost when reusing a session.
func (k *KerberosClient) seedCookie(u *url.URL, c *http.Cookie) {
	copy := *c // #nosec G124 -- Preserve the original server cookie security attributes.
	if copy.Path == "" {
		copy.Path = "/"
	}
	// Saved domains without a leading dot denote host-only cookies.
	if !strings.HasPrefix(copy.Domain, ".") {
		if copy.Domain != "" && !strings.EqualFold(copy.Domain, u.Hostname()) {
			return
		}
		copy.Domain = ""
	}
	k.jar.SetCookies(u, []*http.Cookie{&copy})
	k.recordResponseCookies(u, []*http.Cookie{&copy})
}

// #nosec G124 -- Only path and lifetime are normalised; original security attributes are retained.
func (k *KerberosClient) recordCookie(u *url.URL, c *http.Cookie) {
	if !strings.HasPrefix(c.Path, "/") {
		c.Path = "/"
		if i := strings.LastIndex(u.Path, "/"); i > 0 {
			c.Path = u.Path[:i]
		}
	}
	// Resolve Max-Age when received, so saving or reusing it cannot extend its life.
	if c.MaxAge > 0 {
		c.Expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second)
		c.MaxAge = 0
	}
	k.cookiesMu.Lock()
	defer k.cookiesMu.Unlock()
	k.collectedCookies = append(k.collectedCookies, c)
}
