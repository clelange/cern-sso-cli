package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExitCodeForErrorUsesCustomExitCode(t *testing.T) {
	if code := exitCodeForError(&exitCodeError{code: 7}); code != 7 {
		t.Fatalf("expected exit code %d, got %d", 7, code)
	}
}

func TestStatusIsValidUsesVerificationResult(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "auth", Expires: time.Now().Add(1 * time.Hour)},
	}

	if statusIsValid(cookies, true, false, time.Now()) {
		t.Fatal("expected failed verification to mark cookies invalid")
	}
	if !statusIsValid(cookies, true, true, time.Now()) {
		t.Fatal("expected successful verification to mark cookies valid")
	}
}

func TestStatusIsValidUsesExpiryWithoutVerification(t *testing.T) {
	now := time.Now()

	if !statusIsValid([]*http.Cookie{{Name: "session"}}, false, false, now) {
		t.Fatal("expected session cookie to be treated as valid")
	}
	if !statusIsValid([]*http.Cookie{{Name: "future", Expires: now.Add(1 * time.Hour)}}, false, false, now) {
		t.Fatal("expected future cookie to be treated as valid")
	}
	if statusIsValid([]*http.Cookie{{Name: "expired", Expires: now.Add(-1 * time.Hour)}}, false, false, now) {
		t.Fatal("expected expired cookies to be treated as invalid")
	}
}

func TestRunStatusQuietReturnsExitCodeErrorForExpiredCookies(t *testing.T) {
	oldQuiet := quiet
	oldStatusFile := statusFile
	oldStatusURL := statusURL
	oldStatusJSON := statusJSON
	defer func() {
		quiet = oldQuiet
		statusFile = oldStatusFile
		statusURL = oldStatusURL
		statusJSON = oldStatusJSON
	}()

	quiet = true
	statusURL = ""
	statusJSON = false
	statusFile = writeStatusCookieFile(t, time.Now().Add(-1*time.Hour))

	stdout, stderr := captureStdoutStderr(t, func() {
		err := runStatus(statusCmd, nil)
		if exitCodeForError(err) != 1 {
			t.Fatalf("expected exit code %d, got %d (err=%v)", 1, exitCodeForError(err), err)
		}
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got %q", stderr)
	}
}

func TestRunStatusQuietSucceedsForValidCookies(t *testing.T) {
	oldQuiet := quiet
	oldStatusFile := statusFile
	oldStatusURL := statusURL
	oldStatusJSON := statusJSON
	defer func() {
		quiet = oldQuiet
		statusFile = oldStatusFile
		statusURL = oldStatusURL
		statusJSON = oldStatusJSON
	}()

	quiet = true
	statusURL = ""
	statusJSON = false
	statusFile = writeStatusCookieFile(t, time.Now().Add(1*time.Hour))

	stdout, stderr := captureStdoutStderr(t, func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got %q", stderr)
	}
}

func writeStatusCookieFile(t *testing.T, expires time.Time) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "cookies.txt")
	content := strings.Join([]string{
		"# Netscape HTTP Cookie File",
		".example.com\tTRUE\t/\tTRUE\t" + formatUnix(expires) + "\tAUTH_SESSION\tvalue",
		"",
	}, "\n")

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write cookie file: %v", err)
	}

	return path
}

func formatUnix(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
