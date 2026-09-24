package auth

import (
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cookiepkg "github.com/clelange/cern-sso-cli/pkg/cookie"
)

type cookieRoundTripper func(*http.Request) (*http.Response, error)

func (f cookieRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCookieLoginPreservesMetadataAcrossRedirects(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	seeds := []*http.Cookie{
		{Name: "sso", Value: "seed", Domain: "auth.example.com", Path: "/auth", Secure: true, HttpOnly: true, Expires: expires},
		{Name: "deleted", Value: "old", Domain: "auth.example.com", Path: "/auth", Expires: expires},
	}
	kc.httpClient.Transport.(*cookieInterceptTransport).base = cookieRoundTripper(func(req *http.Request) (*http.Response, error) {
		header := make(http.Header)
		status := http.StatusFound
		switch req.URL.String() {
		case "https://portal.example.com/start":
			header.Set("Location", "https://auth.example.com/auth/realms/login")
		case "https://auth.example.com/auth/realms/login":
			if c, err := req.Cookie("sso"); err != nil || c.Value != "seed" {
				t.Errorf("seeded cookie was not sent: %v", err)
			}
			header.Set("Location", "https://portal.example.com/private/welcome")
			header.Add("Set-Cookie", "realm=token; Secure; HttpOnly; Max-Age=120")
			header.Add("Set-Cookie", "deleted=; Path=/auth; Max-Age=0")
		case "https://portal.example.com/private/welcome":
			if _, err := req.Cookie("sso"); err == nil {
				t.Error("auth cookie leaked to portal")
			}
			status = http.StatusOK
			header.Add("Set-Cookie", "app=session; Path=/private; Secure; HttpOnly; Expires="+expires.Format(http.TimeFormat))
			header.Add("Set-Cookie", "invalid=foreign; Domain=unrelated.example")
			header.Add("Set-Cookie", "invalid=publicsuffix; Domain=com")
		default:
			t.Fatalf("unexpected request %s", req.URL)
		}
		return &http.Response{StatusCode: status, Header: header, Request: req, Body: io.NopCloser(strings.NewReader("OK"))}, nil
	})

	before := time.Now()
	result, err := kc.TryLoginWithCookies("https://portal.example.com/start", "auth.example.com", seeds)
	if err != nil {
		t.Fatal(err)
	}
	cookies := cookiesByName(result.Cookies)
	if len(cookies) != 4 || cookies["invalid"] != nil {
		t.Fatalf("lost cookies or retained rejected cookie: %v", cookies)
	}
	if c := cookies["sso"]; c.Domain != "auth.example.com" || c.Path != "/auth" || !c.Secure || !c.HttpOnly || !c.Expires.Equal(expires) {
		t.Fatalf("seed metadata lost: %#v", c)
	}
	if c := cookies["app"]; c.Domain != "portal.example.com" || c.Path != "/private" || !c.Secure || !c.HttpOnly || !c.Expires.Equal(expires) {
		t.Fatalf("response metadata lost: %#v", c)
	}
	if c := cookies["realm"]; c.Domain != "auth.example.com" || c.Path != "/auth/realms" || !c.Secure || !c.HttpOnly || c.Expires.Before(before.Add(120*time.Second)) || c.Expires.After(time.Now().Add(120*time.Second)) || c.MaxAge != 0 {
		t.Fatalf("default path or Max-Age expiry lost: %#v", c)
	}
	if cookies["deleted"].MaxAge >= 0 {
		t.Fatal("deletion marker was lost")
	}
	if seeds[1].Value != "old" || seeds[1].MaxAge != 0 {
		t.Fatal("seed cookie was modified")
	}

	// Full Kerberos login must return the same complete metadata, not request cookies.
	flow := kerberosLoginFlow{client: kc}
	finalURL, _ := url.Parse("https://portal.example.com/private/welcome")
	fullResult := flow.successResult(&http.Response{Request: &http.Request{URL: finalURL}})
	if got := cookiesByName(fullResult.Cookies); len(got) != 4 || got["sso"] == nil || !got["app"].HttpOnly {
		t.Fatalf("full login dropped metadata: %v", got)
	}

	// Applying the result to an older cookie file must remove revoked cookies.
	jar, _ := cookiepkg.NewJar()
	filename := filepath.Join(t.TempDir(), "cookies.txt")
	if err := jar.Save(filename, seeds, "portal.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := jar.Update(filename, result.Cookies, "portal.example.com"); err != nil {
		t.Fatal(err)
	}
	saved, err := cookiepkg.Load(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got := cookiesByName(saved); len(got) != 3 || got["deleted"] != nil || !got["app"].Secure || !got["app"].Expires.Equal(expires) {
		t.Fatalf("saved session lost attributes or retained deletion: %v", got)
	}
}

func TestResponseCookieScopeAndDefaultPaths(t *testing.T) {
	tests := []struct {
		name, source, domain, path, wantDomain, wantPath string
		accepted                                         bool
	}{
		{"host only", "https://auth.example.com/a/b", "", "", "auth.example.com", "/a", true},
		{"domain without dot", "https://auth.example.com/a/b", "example.com", "relative", ".example.com", "/a", true},
		{"domain with dot", "https://auth.example.com/", ".example.com", "/realm", ".example.com", "/realm", true},
		{"root path", "https://auth.example.com/login", "", "", "auth.example.com", "/", true},
		{"IP address", "http://127.0.0.1/", "127.0.0.1", "", "127.0.0.1", "/", true},
		{"foreign domain", "https://auth.example.com/", "unrelated.example", "", "", "", false},
		{"public suffix", "https://auth.example.com/", ".com", "", "", "", false},
		{"malformed domain", "https://auth.example.com/", "..example.com", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kc := &KerberosClient{}
			u, _ := url.Parse(tt.source)
			c := &http.Cookie{Name: "session", Domain: tt.domain, Path: tt.path}
			kc.recordResponseCookies(u, []*http.Cookie{c})
			got := kc.GetCollectedCookies()
			if !tt.accepted {
				if len(got) != 0 {
					t.Fatalf("rejected cookie was captured: %v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Domain != tt.wantDomain || got[0].Path != tt.wantPath {
				t.Fatalf("wrong captured scope: %v", got)
			}
			if c.Domain != tt.domain || c.Path != tt.path {
				t.Fatal("input cookie was modified")
			}
		})
	}
}

func TestSeedCookieRetainsHostOnlyScope(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()
	u, _ := url.Parse("https://auth.example.com/")
	for _, c := range []*http.Cookie{
		{Name: "host", Domain: "auth.example.com"},
		{Name: "domain", Domain: ".example.com"},
		{Name: "foreign", Domain: "unrelated.example"},
		{Name: "subauth", Domain: "sub.auth.example.com"},
	} {
		kc.seedCookie(u, c)
	}
	got := cookiesByName(kc.GetCollectedCookies())
	if len(got) != 2 || got["host"] == nil || got["domain"] == nil {
		t.Fatalf("seeded cookie scope changed: %v", got)
	}
	subdomain, _ := url.Parse("https://sub.auth.example.com/")
	requestCookies := cookiesByName(kc.jar.Cookies(subdomain))
	if len(requestCookies) != 1 || requestCookies["domain"] == nil {
		t.Fatalf("host-only cookie escaped its domain: %v", requestCookies)
	}
}

func TestCollectCookiesRetainsBrowserCookiesWithoutReplayingRedirect(t *testing.T) {
	kc := &KerberosClient{}
	browserCookies := []*http.Cookie{{Name: "browser", Domain: "portal.example.com", Secure: true, HttpOnly: true}}
	got, err := kc.CollectCookies("https://portal.example.com", "auth.example.com", &LoginResult{
		Cookies: browserCookies, RedirectURI: "https://portal.example.com/callback?code=already-used",
	})
	if err != nil || len(got) != 1 || got[0] != browserCookies[0] {
		t.Fatalf("browser cookies were not retained: %v, %v", got, err)
	}
}

func cookiesByName(cookies []*http.Cookie) map[string]*http.Cookie {
	result := make(map[string]*http.Cookie)
	for _, c := range cookies {
		result[c.Name] = c
	}
	return result
}

func TestCollectedCookiesUseEffectiveDomainPathAndNameIdentity(t *testing.T) {
	kc := &KerberosClient{}
	u, _ := url.Parse("https://auth.example.com/a/login")
	kc.recordResponseCookies(u, []*http.Cookie{
		{Name: "session", Value: "old"},
		{Name: "bc", Value: "first", Path: "/a"},
		{Name: "c", Value: "second", Path: "/ab"},
	})
	kc.recordResponseCookies(u, []*http.Cookie{
		{Name: "session", Domain: "auth.example.com", Path: "/a", MaxAge: -1},
	})
	got := cookiesByName(kc.GetCollectedCookies())
	if len(got) != 3 || got["bc"] == nil || got["c"] == nil {
		t.Fatalf("distinct path/name pairs collided: %v", got)
	}
	if got["session"].MaxAge >= 0 {
		t.Fatal("deletion with an explicit domain and path did not replace the default-scoped cookie")
	}
	got["session"].Value = "mutated"
	if cookiesByName(kc.GetCollectedCookies())["session"].Value != "" {
		t.Fatal("returned cookie aliases collected state")
	}
}
