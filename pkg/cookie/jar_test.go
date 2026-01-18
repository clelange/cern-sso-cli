package cookie

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name         string
		cookieDomain string
		targetDomain string
		expected     bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"leading dot matches subdomain", ".example.com", "sub.example.com", true},
		{"leading dot matches base", ".example.com", "example.com", true},
		{"no leading dot doesn't match subdomain", "example.com", "sub.example.com", false},
		{"empty cookie domain", "", "example.com", false},
		{"subdomain matches leading dot", ".example.com", "deep.sub.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchDomain(tt.cookieDomain, tt.targetDomain)
			if result != tt.expected {
				t.Errorf("MatchDomain(%q, %q) = %v, want %v", tt.cookieDomain, tt.targetDomain, result, tt.expected)
			}
		})
	}
}

func TestFilterAuthCookies(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "auth1", Domain: "auth.cern.ch"},
		{Name: "auth2", Domain: ".auth.cern.ch"},
		{Name: "other", Domain: "other.cern.ch"},
		{Name: "subdomain", Domain: "sub.auth.cern.ch"},
		{Name: "empty", Domain: ""},
	}

	filtered := FilterAuthCookies(cookies, "auth.cern.ch")

	if len(filtered) != 3 {
		t.Errorf("Expected 3 auth cookies, got %d", len(filtered))
	}

	domains := make(map[string]bool)
	for _, c := range filtered {
		domains[c.Name] = true
	}

	if !domains["auth1"] {
		t.Error("Expected auth1 to be in filtered results")
	}
	if !domains["auth2"] {
		t.Error("Expected auth2 to be in filtered results")
	}
	if !domains["subdomain"] {
		t.Error("Expected subdomain to be in filtered results")
	}
	if domains["other"] {
		t.Error("Did not expect other to be in filtered results")
	}
}

func TestFilterAuthCookies_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		cookies  []*http.Cookie
		authHost string
		expected []string // cookie names that should be included
		excluded []string // cookie names that should NOT be included
	}{
		{
			name: "unrelated subdomain should not match",
			cookies: []*http.Cookie{
				{Name: "bad", Domain: "notauth.cern.ch"},
				{Name: "good", Domain: "auth.cern.ch"},
			},
			authHost: "auth.cern.ch",
			expected: []string{"good"},
			excluded: []string{"bad"},
		},
		{
			name: "similar suffix should not match",
			cookies: []*http.Cookie{
				{Name: "bad1", Domain: "fakeauth.cern.ch"},
				{Name: "bad2", Domain: "myauth.cern.ch"},
				{Name: "good", Domain: ".auth.cern.ch"},
			},
			authHost: "auth.cern.ch",
			expected: []string{"good"},
			excluded: []string{"bad1", "bad2"},
		},
		{
			name: "deeper subdomain should match",
			cookies: []*http.Cookie{
				{Name: "deep", Domain: "very.deep.sub.auth.cern.ch"},
				{Name: "exact", Domain: "auth.cern.ch"},
			},
			authHost: "auth.cern.ch",
			expected: []string{"deep", "exact"},
			excluded: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterAuthCookies(tt.cookies, tt.authHost)

			found := make(map[string]bool)
			for _, c := range filtered {
				found[c.Name] = true
			}

			for _, name := range tt.expected {
				if !found[name] {
					t.Errorf("Expected cookie %q to be in filtered results", name)
				}
			}
			for _, name := range tt.excluded {
				if found[name] {
					t.Errorf("Did NOT expect cookie %q to be in filtered results", name)
				}
			}
		})
	}
}

func TestJar_SaveAndLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cookie-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cookieFile := filepath.Join(tmpDir, "cookies.txt")
	domain := "example.com"

	now := time.Now().Truncate(time.Second)
	expiry := now.Add(24 * time.Hour)

	testCookies := []*http.Cookie{
		{
			Name:     "session_id",
			Value:    "12345",
			Path:     "/",
			Domain:   "example.com",
			Expires:  expiry,
			Secure:   true,
			HttpOnly: true,
		},
		{
			Name:     "pref",
			Value:    "dark",
			Path:     "/settings",
			Domain:   "example.com",
			Expires:  expiry,
			Secure:   false,
			HttpOnly: false,
		},
	}

	jar, err := NewJar()
	if err != nil {
		t.Fatal(err)
	}

	// Test Save
	if err := jar.Save(cookieFile, testCookies, domain); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Test Load
	loadedCookies, err := Load(cookieFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(loadedCookies) != len(testCookies) {
		t.Fatalf("Expected %d cookies, got %d", len(testCookies), len(loadedCookies))
	}

	for i, expected := range testCookies {
		got := loadedCookies[i]
		if got.Name != expected.Name {
			t.Errorf("Cookie %d: expected name %q, got %q", i, expected.Name, got.Name)
		}
		if got.Value != expected.Value {
			t.Errorf("Cookie %d: expected value %q, got %q", i, expected.Value, got.Value)
		}
		if got.Path != expected.Path {
			t.Errorf("Cookie %d: expected path %q, got %q", i, expected.Path, got.Path)
		}
		if got.Domain != expected.Domain {
			t.Errorf("Cookie %d: expected domain %q, got %q", i, expected.Domain, got.Domain)
		}
		if got.Secure != expected.Secure {
			t.Errorf("Cookie %d: expected secure %v, got %v", i, expected.Secure, got.Secure)
		}
		if got.HttpOnly != expected.HttpOnly {
			t.Errorf("Cookie %d: expected httponly %v, got %v", i, expected.HttpOnly, got.HttpOnly)
		}
		if !got.Expires.Equal(expected.Expires) {
			t.Errorf("Cookie %d: expected expires %v, got %v", i, expected.Expires, got.Expires)
		}
	}
}

func TestJar_EmptyDomain(t *testing.T) {
	jar, _ := NewJar()
	cookies := []*http.Cookie{{Name: "a", Value: "b"}}

	// Should use fallback domain
	tmpFile := filepath.Join(t.TempDir(), "cookies.txt")
	if err := jar.Save(tmpFile, cookies, "fallback.com"); err != nil {
		t.Fatal(err)
	}

	loaded, _ := Load(tmpFile)
	if len(loaded) != 1 || loaded[0].Domain != "fallback.com" {
		t.Errorf("Expected domain fallback.com, got %q", loaded[0].Domain)
	}
}

func TestJar_Update(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "cookies.txt")
	jar, _ := NewJar()

	now := time.Now().Truncate(time.Second)
	validExpiry := now.Add(1 * time.Hour)
	expired := now.Add(-1 * time.Hour)

	initialCookies := []*http.Cookie{
		{Name: "keep", Value: "val", Domain: "example.com", Path: "/", Expires: validExpiry},
		{Name: "replace", Value: "old", Domain: "example.com", Path: "/", Expires: validExpiry},
		{Name: "expire", Value: "bye", Domain: "example.com", Path: "/", Expires: expired},
	}

	// Create initial file
	if err := jar.Save(tmpFile, initialCookies, "example.com"); err != nil {
		t.Fatal(err)
	}

	newCookies := []*http.Cookie{
		{Name: "replace", Value: "new", Domain: "example.com", Path: "/", Expires: validExpiry},
		{Name: "add", Value: "newItem", Domain: "example.com", Path: "/", Expires: validExpiry},
	}

	if err := jar.Update(tmpFile, newCookies, "example.com"); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	// Expected: keep, replace (new), add. expire should be gone.
	if len(loaded) != 3 {
		t.Errorf("Expected 3 cookies, got %d", len(loaded))
	}

	found := make(map[string]string)
	for _, c := range loaded {
		found[c.Name] = c.Value
	}

	if val, ok := found["keep"]; !ok || val != "val" {
		t.Errorf("keep cookie missing or wrong val")
	}
	if val, ok := found["replace"]; !ok || val != "new" {
		t.Errorf("replace cookie missing or wrong val: %s", val)
	}
	if val, ok := found["add"]; !ok || val != "newItem" {
		t.Errorf("add cookie missing or wrong val")
	}
	if _, ok := found["expire"]; ok {
		t.Errorf("expire cookie should be removed")
	}
}

func TestJar_UpdateMultipleDomains(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "cookies.txt")
	jar, _ := NewJar()

	now := time.Now().Truncate(time.Second)
	validExpiry := now.Add(1 * time.Hour)

	// Initial cookies for domain1
	domain1Cookies := []*http.Cookie{
		{Name: "session", Value: "domain1", Domain: "domain1.com", Path: "/", Expires: validExpiry},
	}
	if err := jar.Save(tmpFile, domain1Cookies, "domain1.com"); err != nil {
		t.Fatal(err)
	}

	// Add cookies for domain2
	domain2Cookies := []*http.Cookie{
		{Name: "session", Value: "domain2", Domain: "domain2.com", Path: "/", Expires: validExpiry},
	}
	if err := jar.Update(tmpFile, domain2Cookies, "domain2.com"); err != nil {
		t.Fatal(err)
	}

	// Verify both domains have cookies
	loaded, err := Load(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded) != 2 {
		t.Errorf("Expected 2 cookies, got %d", len(loaded))
	}

	found := make(map[string]string)
	for _, c := range loaded {
		found[c.Domain] = c.Value
	}

	if val, ok := found["domain1.com"]; !ok || val != "domain1" {
		t.Errorf("domain1.com cookie missing or wrong val")
	}
	if val, ok := found["domain2.com"]; !ok || val != "domain2" {
		t.Errorf("domain2.com cookie missing or wrong val")
	}
}
