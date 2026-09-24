package cookie

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSaveUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions")
	}
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[existing], func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "cookies.txt")
			if existing {
				if err := os.WriteFile(filename, []byte("old"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filename, 0644); err != nil {
					t.Fatal(err)
				}
			}
			jar, _ := NewJar()
			if err := jar.Save(filename, []*http.Cookie{{Name: "session", Value: "new"}}, "example.com"); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filename)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("cookie file permissions = %04o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func TestSaveFailurePreservesDestinationAndRemovesTemporaryFile(t *testing.T) {
	// A directory cannot be replaced by the temporary cookie file. Its existing
	// content must survive the failure, and no partially written file may remain.
	dir := t.TempDir()
	filename := filepath.Join(dir, "cookies.txt")
	if err := os.Mkdir(filename, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(filename, "existing")
	if err := os.WriteFile(marker, []byte("preserve me"), 0600); err != nil {
		t.Fatal(err)
	}
	jar, _ := NewJar()
	err := jar.Save(filename, []*http.Cookie{{Name: "session", Value: "new"}}, "example.com")
	if err == nil || !strings.Contains(err.Error(), "replace cookie file") {
		t.Fatalf("expected replacement error, got %v", err)
	}
	contents, err := os.ReadFile(marker)
	if err != nil || string(contents) != "preserve me" {
		t.Fatalf("destination was changed: %q, %v", contents, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary file was left behind: %v, %v", entries, err)
	}
}

type failingCookieWriter struct{ err error }

func (w failingCookieWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCookieSerializationReturnsWriteErrors(t *testing.T) {
	want := errors.New("disk full")
	for _, value := range []string{"small", strings.Repeat("large", 2000)} {
		err := writeNetscapeCookies(failingCookieWriter{want}, []*http.Cookie{{Name: "session", Value: value}}, "example.com", "alice")
		if !errors.Is(err, want) {
			t.Fatalf("expected writer error, got %v", err)
		}
	}
}

func TestUpdatePreservesCookieLifetimesAndAppliesDeletions(t *testing.T) {
	jar, _ := NewJar()
	filename := filepath.Join(t.TempDir(), "cookies.txt")
	future := time.Now().Add(time.Hour).Truncate(time.Second)
	initial := []*http.Cookie{
		{Name: "deleted", Domain: "example.com", Path: "/", Expires: future},
		{Name: "expired", Domain: ".example.com", Path: "/", Expires: future},
		{Name: "replaced", Value: "old", Domain: "example.com", Path: "/", Expires: future},
		{Name: "other", Domain: "other.example.com", Path: "/", Expires: future},
		{Name: "session", Domain: "example.com", Path: "/"},
	}
	if err := jar.SaveWithUser(filename, initial, "example.com", "alice"); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	updates := []*http.Cookie{
		{Name: "deleted", Domain: ".example.com", MaxAge: -1},
		{Name: "expired", Domain: "example.com", Expires: before.Add(-time.Hour)},
		{Name: "replaced", Value: "new", Secure: true, HttpOnly: true},
		{Name: "maxage", MaxAge: 60, Expires: before.Add(-time.Hour)},
	}
	if err := jar.Update(filename, updates, "example.com"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(filename)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]*http.Cookie)
	for _, c := range loaded {
		byName[c.Name] = c
	}
	if len(loaded) != 4 || byName["deleted"] != nil || byName["expired"] != nil || byName["other"] == nil {
		t.Fatalf("unexpected cookies after merge: %v", byName)
	}
	if c := byName["replaced"]; c == nil || c.Value != "new" || c.Domain != "example.com" || c.Path != "/" || !c.Secure || !c.HttpOnly {
		t.Fatalf("replacement lost attributes or created a duplicate: %#v", c)
	}
	if c := byName["maxage"]; c == nil || c.Expires.Before(before.Add(59*time.Second)) || c.Expires.After(time.Now().Add(time.Minute)) {
		t.Fatalf("Max-Age expiry was not preserved: %#v", c)
	}
	if !byName["session"].Expires.IsZero() {
		t.Fatal("session cookie gained an invented expiry")
	}
	if LoadUser(filename) != "alice" {
		t.Fatal("username was not preserved")
	}
	if updates[2].Domain != "" || updates[2].Path != "" || updates[3].MaxAge != 60 {
		t.Fatal("input cookies were modified")
	}
	if err := jar.Update(filename, nil, "example.com"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(filename)
	if err != nil || len(reloaded) != 4 {
		t.Fatalf("session cookie did not survive reuse: %v, %v", reloaded, err)
	}
}

func TestSaveFailureLeavesExistingCookieFileIntact(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires POSIX directory permissions for a non-root user")
	}
	dir := t.TempDir()
	filename := filepath.Join(dir, "cookies.txt")
	original := []byte("existing cookie file")
	if err := os.WriteFile(filename, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	jar, _ := NewJar()
	if err := jar.Save(filename, []*http.Cookie{{Name: "session", Value: "new"}}, "example.com"); err == nil {
		t.Fatal("expected failure in an unwritable directory")
	}
	got, err := os.ReadFile(filename)
	if err != nil || string(got) != string(original) {
		t.Fatalf("failed save damaged existing cookie file: %q, %v", got, err)
	}
}
