package cookie

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJar_SaveAndLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cookie-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

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
